#include "apiset_map.h"

#include <algorithm>
#include <cstring>
#include <format>
#include <map>

namespace sheller::loader {
namespace {

// The binary layout (all fields little-endian):
//   Header (40 bytes)
//     0   magic   "APSMMAP1"
//     8   u32     version (1)
//     12  u8      architecture (kApiSetMapArchX64)
//     13  3 bytes zero padding
//     16  u64     anchor: whole-file xxhash64 of the directory's raw ntdll
//     24  u32     entry count
//     28  u32     pool size in bytes
//     32  u32     entry bytes (24 * count, pinned so the layout has one shape)
//     36  u32     pool offset (40 + entry bytes, pinned likewise)
//   Entries (24 bytes each, from offset 40): six u32s - contract, importer
//   and host as (pool offset, length) pairs. An importer length of zero is
//   the unconditional entry.
//   Pool: the strings, contract/importer folded, hosts folded with extension.
constexpr std::size_t kHeaderBytes = 40;
constexpr std::size_t kEntryBytes = 24;
constexpr std::uint32_t kVersion1 = 1;
constexpr std::uint32_t kMaxEntries = 65536;
constexpr std::uint32_t kMaxStringBytes = 255;

constexpr char kMagic[8] = {'A', 'P', 'S', 'M', 'M', 'A', 'P', '1'};

std::uint32_t read32(const std::span<const std::uint8_t> bytes, const std::size_t offset)
{
    std::uint32_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof value);
    return value;
}

std::uint64_t read64(const std::span<const std::uint8_t> bytes, const std::size_t offset)
{
    std::uint64_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof value);
    return value;
}

ApiSetMapFailure fail(const ApiSetMapError code, std::string detail)
{
    return ApiSetMapFailure{code, std::move(detail)};
}

} // namespace

std::string_view apiset_map_error_message(const ApiSetMapError error)
{
    switch (error) {
    case ApiSetMapError::kNone:
        return "ok";
    case ApiSetMapError::kTooSmall:
        return "apiset map shorter than the fixed header";
    case ApiSetMapError::kBadMagic:
        return "apiset map magic mismatch";
    case ApiSetMapError::kUnknownVersion:
        return "apiset map version is unknown to this reader";
    case ApiSetMapError::kArchMismatch:
        return "apiset map architecture differs from the world";
    case ApiSetMapError::kAnchorMismatch:
        return "apiset map anchor differs from the directory's raw ntdll";
    case ApiSetMapError::kOutOfBounds:
        return "apiset map entry or string range exceeds the file";
    case ApiSetMapError::kConflict:
        return "apiset map maps one (contract, importer) pair to two hosts";
    }
    return "unknown apiset map error";
}

std::expected<ApiSetMapView, ApiSetMapFailure>
ApiSetMapView::load(const std::span<const std::uint8_t> bytes, const std::uint8_t arch,
                    const std::uint64_t ntdll_xxhash64)
{
    if (bytes.size() < kHeaderBytes) {
        return std::unexpected(
            fail(ApiSetMapError::kTooSmall, std::format("{} bytes", bytes.size())));
    }
    if (std::memcmp(bytes.data(), kMagic, sizeof kMagic) != 0) {
        return std::unexpected(fail(ApiSetMapError::kBadMagic, "header magic mismatch"));
    }
    if (read32(bytes, 8) != kVersion1) {
        return std::unexpected(
            fail(ApiSetMapError::kUnknownVersion, std::format("version {}", read32(bytes, 8))));
    }
    if (bytes[12] != arch) {
        return std::unexpected(fail(ApiSetMapError::kArchMismatch,
                                    std::format("map arch byte {} vs world {}", bytes[12], arch)));
    }
    const auto anchor = read64(bytes, 16);
    if (anchor != ntdll_xxhash64) {
        return std::unexpected(fail(
            ApiSetMapError::kAnchorMismatch,
            std::format("map anchor 0x{:x} vs directory ntdll 0x{:x}", anchor, ntdll_xxhash64)));
    }
    const auto entry_count = read32(bytes, 24);
    const auto pool_size = read32(bytes, 28);
    const auto entry_bytes = read32(bytes, 32);
    const auto pool_offset = read32(bytes, 36);
    if (entry_count > kMaxEntries || entry_bytes != entry_count * kEntryBytes ||
        pool_offset != kHeaderBytes + entry_bytes ||
        static_cast<std::uint64_t>(pool_offset) + pool_size > bytes.size()) {
        return std::unexpected(
            fail(ApiSetMapError::kOutOfBounds,
                 std::format("entries {} / entry bytes {} / pool offset {} / pool size {}",
                             entry_count, entry_bytes, pool_offset, pool_size)));
    }
    const auto pool = bytes.subspan(pool_offset, pool_size);

    ApiSetMapView view;
    view.entries_.reserve(entry_count);
    std::map<std::pair<std::string_view, std::string_view>, std::string_view> seen;
    for (std::uint32_t i = 0; i < entry_count; ++i) {
        const auto at = kHeaderBytes + static_cast<std::size_t>(i) * kEntryBytes;
        const std::pair<std::uint32_t, std::uint32_t> fields[3] = {
            {read32(bytes, at), read32(bytes, at + 4)},       // contract
            {read32(bytes, at + 8), read32(bytes, at + 12)},  // importer
            {read32(bytes, at + 16), read32(bytes, at + 20)}, // host
        };
        Entry entry;
        for (unsigned f = 0; f < 3; ++f) {
            const auto& [offset, length] = fields[f];
            if (length > kMaxStringBytes ||
                static_cast<std::uint64_t>(offset) + length > pool.size()) {
                return std::unexpected(fail(ApiSetMapError::kOutOfBounds,
                                            std::format("entry {} field {} range {}+{} vs pool {}",
                                                        i, f, offset, length, pool.size())));
            }
            std::string text{reinterpret_cast<const char*>(pool.data() + offset), length};
            if (f == 2 && text.empty()) {
                return std::unexpected(fail(ApiSetMapError::kOutOfBounds,
                                            std::format("entry {} carries an empty host", i)));
            }
            if (f == 0 && text.empty()) {
                return std::unexpected(fail(ApiSetMapError::kOutOfBounds,
                                            std::format("entry {} carries an empty contract", i)));
            }
            if (f == 0) {
                entry.contract = std::move(text);
            } else if (f == 1) {
                entry.importer = std::move(text);
            } else {
                entry.host = std::move(text);
            }
        }
        // one (contract, importer) pair maps to one host: a repeat pair is a
        // conflict whether or not the two rows agree (the generator dedups,
        // so any duplicate is a hand-built or stale artifact)
        const auto key =
            std::make_pair(std::string_view(entry.contract), std::string_view(entry.importer));
        if (const auto it = seen.find(key); it != seen.end()) {
            return std::unexpected(
                fail(ApiSetMapError::kConflict,
                     std::format("contract '{}' (importer '{}') maps to '{}' "
                                 "and '{}'",
                                 entry.contract, entry.importer, it->second, entry.host)));
        }
        seen.emplace(key, entry.host);
        view.entries_.push_back(std::move(entry));
    }
    return view;
}

std::optional<std::string_view> ApiSetMapView::host_for(const std::string_view contract,
                                                        const std::string_view importer) const
{
    std::optional<std::string_view> unconditional;
    for (const auto& entry : entries_) {
        if (entry.contract != contract) {
            continue;
        }
        if (entry.importer.empty()) {
            unconditional = entry.host;
        } else if (entry.importer == importer) {
            // the importer-conditional entry wins over the unconditional one
            return entry.host;
        }
    }
    return unconditional;
}

} // namespace sheller::loader
