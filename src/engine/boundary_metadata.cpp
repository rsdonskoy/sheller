#include "boundary_metadata.h"

#include <xxhash.h>

#include <algorithm>
#include <cstring>
#include <format>

namespace sheller::engine::boundary_metadata {
namespace {

// The payload layout (all fields little-endian; strings inline as
// u16 length + bytes, so the encoding is a pure function of the input
// order):
//   Header (fixed 56 bytes)
//     0  magic   "SBDMETA1"
//     8  u32     semantic version
//     12 u32     header bytes (56)
//     16 u32     module count
//     20 u32     boundary count
//     24 u32     counter count
//     28 u32     intercept count
//     32 u32     embedded API Set map bytes
//     36 u32     payload bytes (the exact content length after the header;
//                the mapped region pads zero beyond it)
//     40 u64     the embedded map's anchor xxhash64
//     48 u64     payload xxhash64 over bytes [56, 56 + payload bytes)
//   Then, in order: module records, boundary records, counter records,
//   intercept records, and the embedded API Set map bytes.
constexpr std::size_t kHeaderBytes = 56;
constexpr std::array<std::uint8_t, 8> kMagic{'S', 'B', 'D', 'M', 'E', 'T', 'A', '1'};
constexpr std::uint16_t kMaxStringBytes = 0xFFFF;

Failure fail(const MetadataError code, std::string detail)
{
    return Failure{code, std::move(detail)};
}

void put16(std::vector<std::uint8_t>& out, const std::uint16_t value)
{
    out.push_back(static_cast<std::uint8_t>(value));
    out.push_back(static_cast<std::uint8_t>(value >> 8));
}

void put32(std::vector<std::uint8_t>& out, const std::uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) {
        out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
    }
}

void put64(std::vector<std::uint8_t>& out, const std::uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
    }
}

void put_string(std::vector<std::uint8_t>& out, const std::string& text)
{
    put16(out, static_cast<std::uint16_t>(text.size()));
    out.insert(out.end(), text.begin(), text.end());
}

struct Reader {
    std::span<const std::uint8_t> bytes;
    std::size_t cursor{};

    bool avail(const std::size_t count) const
    {
        return cursor + count <= bytes.size();
    }
    std::uint16_t u16()
    {
        const auto value = static_cast<std::uint16_t>(
            bytes[cursor] | (static_cast<unsigned>(bytes[cursor + 1]) << 8));
        cursor += 2;
        return value;
    }
    std::uint32_t u32()
    {
        std::uint32_t value = 0;
        std::memcpy(&value, bytes.data() + cursor, sizeof value);
        cursor += 4;
        return value;
    }
    std::uint64_t u64()
    {
        std::uint64_t value = 0;
        std::memcpy(&value, bytes.data() + cursor, sizeof value);
        cursor += 8;
        return value;
    }
    std::string string()
    {
        if (!avail(2)) {
            return {};
        }
        const auto length = u16();
        if (!avail(length)) {
            return {};
        }
        std::string text{reinterpret_cast<const char*>(bytes.data() + cursor), length};
        cursor += length;
        return text;
    }
};

} // namespace

std::string_view metadata_error_message(const MetadataError error)
{
    switch (error) {
    case MetadataError::kNone:
        return "ok";
    case MetadataError::kOverLimit:
        return "boundary metadata payload exceeds the fixed capacity";
    case MetadataError::kBadMagic:
        return "boundary metadata magic mismatch";
    case MetadataError::kUnknownVersion:
        return "boundary metadata version is unknown to this reader";
    case MetadataError::kBadPayloadHash:
        return "boundary metadata payload checksum mismatch";
    case MetadataError::kOutOfBounds:
        return "boundary metadata record or string range exceeds the payload";
    case MetadataError::kBadMarker:
        return "the DOS e_res2 mode-marker slot is damaged";
    }
    return "unknown boundary metadata error";
}

std::expected<std::vector<std::uint8_t>, Failure> encode(const MetadataInput& input)
{
    std::vector<std::uint8_t> out;
    out.reserve(kHeaderBytes);
    out.insert(out.end(), kMagic.begin(), kMagic.end());
    put32(out, kSemanticVersion);
    put32(out, static_cast<std::uint32_t>(kHeaderBytes));
    put32(out, static_cast<std::uint32_t>(input.modules.size()));
    put32(out, static_cast<std::uint32_t>(input.boundaries.size()));
    put32(out, static_cast<std::uint32_t>(input.counters.size()));
    put32(out, static_cast<std::uint32_t>(input.intercepts.size()));
    put32(out, static_cast<std::uint32_t>(input.apiset_bytes.size()));
    put32(out, 0); // payload bytes, patched below
    put64(out, input.apiset_anchor);
    put64(out, 0); // payload hash, patched below
    if (out.size() != kHeaderBytes) {
        return std::unexpected(fail(MetadataError::kOverLimit, "header size drifted"));
    }

    for (const auto& module : input.modules) {
        put_string(out, module.name);
        put64(out, module.base);
        put32(out, module.size);
        out.push_back(module.source);
        put64(out, module.image_xxhash64);
    }
    for (const auto& boundary : input.boundaries) {
        put_string(out, boundary.name);
        put32(out, static_cast<std::uint32_t>(boundary.exports.size()));
        for (const auto& entry : boundary.exports) {
            put_string(out, entry.name);
            put32(out, entry.ordinal);
            out.push_back(entry.kind);
            put64(out, entry.va);
            put32(out, entry.syscall_number);
        }
    }
    for (const auto& counter : input.counters) {
        put_string(out, counter.module);
        put_string(out, counter.name);
        out.push_back(counter.klass);
    }
    for (const auto& intercept : input.intercepts) {
        put64(out, intercept.va);
        put32(out, intercept.id);
    }
    out.insert(out.end(), input.apiset_bytes.begin(), input.apiset_bytes.end());

    if (out.size() > kMetadataMaxBytes) {
        // the named over-limit rejection: never a truncation
        return std::unexpected(
            fail(MetadataError::kOverLimit,
                 std::format("{} bytes vs the {} capacity", out.size(), kMetadataMaxBytes)));
    }
    const auto payload_bytes = static_cast<std::uint32_t>(out.size() - kHeaderBytes);
    for (unsigned i = 0; i < 4; ++i) {
        out[36 + i] = static_cast<std::uint8_t>(payload_bytes >> (8 * i));
    }
    const auto hash = XXH64(out.data() + kHeaderBytes, payload_bytes, 0);
    for (unsigned i = 0; i < 8; ++i) {
        out[48 + i] = static_cast<std::uint8_t>(hash >> (8 * i));
    }
    return out;
}

std::expected<MetadataInput, Failure> decode(const std::span<const std::uint8_t> payload)
{
    if (payload.size() < kHeaderBytes) {
        return std::unexpected(fail(MetadataError::kOutOfBounds,
                                    std::format("{} bytes vs the header", payload.size())));
    }
    if (std::memcmp(payload.data(), kMagic.data(), kMagic.size()) != 0) {
        return std::unexpected(fail(MetadataError::kBadMagic, "payload magic mismatch"));
    }
    Reader header{payload, 8}; // the magic is verified above
    if (const auto version = header.u32(); version != kSemanticVersion) {
        return std::unexpected(
            fail(MetadataError::kUnknownVersion, std::format("version {}", version)));
    }
    if (header.u32() != kHeaderBytes) {
        return std::unexpected(fail(MetadataError::kOutOfBounds, "header size drifted"));
    }
    const auto module_count = header.u32();
    const auto boundary_count = header.u32();
    const auto counter_count = header.u32();
    const auto intercept_count = header.u32();
    const auto apiset_bytes = header.u32();
    const auto payload_bytes = header.u32();
    const auto apiset_anchor = header.u64();
    const auto payload_hash = header.u64();
    if (static_cast<std::uint64_t>(payload_bytes) + kHeaderBytes > payload.size()) {
        return std::unexpected(
            fail(MetadataError::kOutOfBounds,
                 std::format("payload bytes {} vs {} available", payload_bytes, payload.size())));
    }
    // the mapped region pads zero beyond the payload: anything else there is
    // corruption the checksum would not see (it covers the payload only)
    for (auto i = static_cast<std::size_t>(kHeaderBytes) + payload_bytes; i < payload.size(); ++i) {
        if (payload[i] != 0) {
            return std::unexpected(
                fail(MetadataError::kBadPayloadHash, "non-zero padding beyond the payload"));
        }
    }
    const auto expected_hash = XXH64(payload.data() + kHeaderBytes, payload_bytes, 0);
    if (expected_hash != payload_hash) {
        return std::unexpected(fail(MetadataError::kBadPayloadHash, "payload checksum"));
    }

    Reader body{payload, kHeaderBytes};
    MetadataInput input;
    input.apiset_anchor = apiset_anchor;
    const auto bounded = [&body, payload](const std::uint32_t count) {
        // every count must be small enough that its records could fit - a
        // huge count cannot walk past the payload's end
        return static_cast<std::uint64_t>(count) <= payload.size();
    };
    if (!bounded(module_count) || !bounded(boundary_count) || !bounded(counter_count) ||
        !bounded(intercept_count)) {
        return std::unexpected(fail(MetadataError::kOutOfBounds, "record count exceeds payload"));
    }
    input.modules.reserve(module_count);
    for (std::uint32_t i = 0; i < module_count; ++i) {
        ModuleRecord record;
        record.name = body.string();
        if (!body.avail(8 + 4 + 1 + 8)) {
            return std::unexpected(
                fail(MetadataError::kOutOfBounds, std::format("module record {} truncated", i)));
        }
        record.base = body.u64();
        record.size = body.u32();
        record.source = body.bytes[body.cursor++];
        record.image_xxhash64 = body.u64();
        input.modules.push_back(std::move(record));
    }
    input.boundaries.reserve(boundary_count);
    for (std::uint32_t i = 0; i < boundary_count; ++i) {
        BoundaryRecord record;
        record.name = body.string();
        if (!body.avail(4)) {
            return std::unexpected(
                fail(MetadataError::kOutOfBounds, std::format("boundary record {} truncated", i)));
        }
        const auto export_count = body.u32();
        if (!bounded(export_count)) {
            return std::unexpected(fail(MetadataError::kOutOfBounds,
                                        std::format("boundary record {} export count", i)));
        }
        record.exports.reserve(export_count);
        for (std::uint32_t e = 0; e < export_count; ++e) {
            BoundaryExportRecord entry;
            entry.name = body.string();
            if (!body.avail(4 + 1 + 8 + 4)) {
                return std::unexpected(
                    fail(MetadataError::kOutOfBounds,
                         std::format("boundary record {} export {} truncated", i, e)));
            }
            entry.ordinal = body.u32();
            entry.kind = body.bytes[body.cursor++];
            entry.va = body.u64();
            entry.syscall_number = body.u32();
            record.exports.push_back(std::move(entry));
        }
        input.boundaries.push_back(std::move(record));
    }
    input.counters.reserve(counter_count);
    for (std::uint32_t i = 0; i < counter_count; ++i) {
        CounterRecord record;
        record.module = body.string();
        record.name = body.string();
        if (!body.avail(1)) {
            return std::unexpected(
                fail(MetadataError::kOutOfBounds, std::format("counter record {} truncated", i)));
        }
        record.klass = body.bytes[body.cursor++];
        input.counters.push_back(std::move(record));
    }
    input.intercepts.reserve(intercept_count);
    for (std::uint32_t i = 0; i < intercept_count; ++i) {
        if (!body.avail(8 + 4)) {
            return std::unexpected(
                fail(MetadataError::kOutOfBounds, std::format("intercept record {} truncated", i)));
        }
        InterceptRecord record;
        record.va = body.u64();
        record.id = body.u32();
        input.intercepts.push_back(record);
    }
    if (apiset_bytes > payload_bytes ||
        body.cursor + apiset_bytes > static_cast<std::size_t>(payload_bytes) + kHeaderBytes) {
        return std::unexpected(fail(MetadataError::kOutOfBounds,
                                    std::format("embedded API Set map {} bytes", apiset_bytes)));
    }
    input.apiset_bytes.assign(payload.begin() + static_cast<std::ptrdiff_t>(body.cursor),
                              payload.begin() +
                                  static_cast<std::ptrdiff_t>(body.cursor + apiset_bytes));
    body.cursor += apiset_bytes;
    if (body.cursor != static_cast<std::size_t>(payload_bytes) + kHeaderBytes) {
        return std::unexpected(fail(
            MetadataError::kOutOfBounds,
            std::format("{} trailing payload bytes", payload_bytes + kHeaderBytes - body.cursor)));
    }
    return input;
}

std::expected<void, Failure> write_marker(std::span<std::uint8_t> derived_image,
                                          const std::uint64_t metadata_va)
{
    if (derived_image.size() < kMarkerOffset + kMarkerBytes) {
        return std::unexpected(fail(MetadataError::kBadMarker, "image too small"));
    }
    for (std::uint32_t i = 0; i < kMarkerBytes; ++i) {
        if (derived_image[kMarkerOffset + i] != 0) {
            return std::unexpected(
                fail(MetadataError::kBadMarker, "the reserved slot is not zero"));
        }
    }
    std::memcpy(derived_image.data() + kMarkerOffset, kMarkerMagic, sizeof kMarkerMagic);
    const std::uint32_t version = kSemanticVersion;
    std::memcpy(derived_image.data() + kMarkerOffset + 8, &version, sizeof version);
    std::memcpy(derived_image.data() + kMarkerOffset + 12, &metadata_va, sizeof metadata_va);
    return {};
}

std::expected<std::optional<std::uint64_t>, Failure>
read_marker(std::span<const std::uint8_t> image)
{
    if (image.size() < kMarkerOffset + kMarkerBytes) {
        return std::unexpected(fail(MetadataError::kBadMarker, "image too small"));
    }
    const auto slot = image.subspan(kMarkerOffset, kMarkerBytes);
    const bool all_zero =
        std::all_of(slot.begin(), slot.end(), [](const std::uint8_t b) { return b == 0; });
    if (all_zero) {
        return std::nullopt; // an unmarked image
    }
    if (std::memcmp(slot.data(), kMarkerMagic, sizeof kMarkerMagic) != 0) {
        return std::unexpected(fail(MetadataError::kBadMarker, "marker magic mismatch"));
    }
    std::uint32_t version = 0;
    std::memcpy(&version, slot.data() + 8, sizeof version);
    if (version != kSemanticVersion) {
        return std::unexpected(
            fail(MetadataError::kBadMarker, std::format("marker version {}", version)));
    }
    std::uint64_t va = 0;
    std::memcpy(&va, slot.data() + 12, sizeof va);
    return va;
}

} // namespace sheller::engine::boundary_metadata
