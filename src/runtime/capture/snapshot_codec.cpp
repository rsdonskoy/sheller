// Snapshot v1 codec: field-level little-endian encode/decode. The byte layout
// is part of the format contract (golden-file tested), so blocks are written
// field by field - never as raw struct images, whose padding and alignment
// would be platform-dependent.

#include <sheller/snapshot.h>

#include <sheller/byte_order.h>
#include <sheller/clock_policy.h>

#include <algorithm>
#include <cstring>
#include <istream>
#include <ostream>

namespace sheller::snapshot {

std::string_view error_message(const Error error)
{
    switch (error) {
    case Error::kNone:
        return "ok";
    case Error::kIoFailure:
        return "stream I/O failure";
    case Error::kBadMagic:
        return "not a sheller snapshot file";
    case Error::kUnsupportedVersion:
        return "snapshot format version not supported by this reader";
    case Error::kBitnessMismatch:
        return "snapshot bitness not supported by this reader";
    case Error::kTruncated:
        return "snapshot data truncated";
    case Error::kBadContent:
        return "region content flag is invalid";
    case Error::kBadPending:
        return "pending-module block is invalid or out of place";
    case Error::kBadClock:
        return "clock-policy block is invalid, out of place, or repeated";
    }
    return "unknown snapshot error";
}

Writer::Writer(std::ostream& out) : out_(out)
{
}

std::expected<void, Error> Writer::write_bytes(const void* data, const std::size_t size)
{
    out_.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
    if (!out_) {
        return std::unexpected(Error::kIoFailure);
    }
    return {};
}

std::expected<void, Error> Writer::write_header(const Header& header)
{
    std::array<std::uint8_t, kHeaderSize> block{};
    std::ranges::copy(kMagic, block.begin());
    le::store_le32(block.data() + kVersionOffset, header.version);
    block[kBitnessOffset] = header.bitness;
    le::store_le32(block.data() + kRegionCountOffset, header.region_count);
    region_count_ = header.region_count;
    header_version_ = header.version;
    return write_bytes(block.data(), block.size());
}

std::expected<void, Error> Writer::write_registers(const Registers& registers)
{
    std::array<std::uint8_t, kRegistersSize> block{};
    for (std::size_t i = 0; i < kGprCount; ++i) {
        le::store_le64(block.data() + i * sizeof(std::uint64_t), registers.gpr[i]);
    }
    le::store_le64(block.data() + kRipOffset, registers.rip);
    le::store_le64(block.data() + kRflagsOffset, registers.rflags);
    return write_bytes(block.data(), block.size());
}

std::expected<void, Error> Writer::write_metadata(const Metadata& metadata)
{
    std::array<std::uint8_t, kMetadataSize> block{};
    le::store_le64(block.data(), metadata.peb_address);
    le::store_le64(block.data() + kMetadataTebOffset, metadata.teb_address);
    le::store_le64(block.data() + kMetadataImageBaseOffset, metadata.image_base);
    le::store_le64(block.data() + kMetadataEntryOffset, metadata.entry_address);
    std::ranges::copy(metadata.original_entry_bytes, block.data() + kMetadataOriginalEntryOffset);
    return write_bytes(block.data(), block.size());
}

std::expected<void, Error> Writer::write_region(const RegionHeader& region,
                                                const std::uint8_t* content)
{
    if (region.content != kContentAbsent && region.content != kContentPresent) {
        return std::unexpected(Error::kBadContent);
    }
    if (region.content == kContentPresent && content == nullptr && region.size != 0) {
        return std::unexpected(Error::kIoFailure);
    }
    std::array<std::uint8_t, kRegionRecordSize> record{};
    le::store_le64(record.data(), region.base_address);
    le::store_le64(record.data() + kRegionSizeOffset, region.size);
    le::store_le32(record.data() + kRegionProtectionOffset, region.protection);
    le::store_le32(record.data() + kRegionTypeOffset, region.type);
    record[kRegionContentFlagOffset] = region.content;
    return write_bytes(record.data(), record.size())
        .and_then([&] -> std::expected<void, Error> {
            if (region.content == kContentPresent && region.size > 0) {
                return write_bytes(content, static_cast<std::size_t>(region.size));
            }
            return {};
        })
        .and_then([&] -> std::expected<void, Error> {
            ++region_count_;
            return {};
        });
}

std::expected<void, Error> Writer::finalize_region_count()
{
    const std::streampos end = out_.tellp();
    if (end < 0) {
        return std::unexpected(Error::kIoFailure);
    }
    out_.seekp(static_cast<std::streamoff>(kRegionCountOffset));
    std::array<std::uint8_t, sizeof(std::uint32_t)> count{};
    le::store_le32(count.data(), region_count_);
    return write_bytes(count.data(), count.size()).and_then([&] -> std::expected<void, Error> {
        out_.seekp(end);
        if (!out_) {
            return std::unexpected(Error::kIoFailure);
        }
        return {};
    });
}

std::expected<void, Error> Writer::write_pending(const PendingModule& pending)
{
    // v2 (the pending-only DLL container) and v3 (pending + clock block) are
    // both legal carriers; v1 keeps its exact legacy layout.
    if (header_version_ != kVersionV2 && header_version_ != kVersionV3) {
        return std::unexpected(Error::kBadPending);
    }
    if (pending.name.empty() || pending.name.size() > kMaxPendingNameBytes ||
        (pending.bitness != kBitness64 && pending.bitness != kBitness32) || pending.bytes.empty() ||
        pending.bytes.size() > kMaxPendingModuleBytes) {
        return std::unexpected(Error::kBadPending);
    }
    return write_bytes(kPendingMarker, sizeof kPendingMarker)
        .and_then([&] {
            std::array<std::uint8_t, kPendingNameOffset - kPendingNameLenOffset> head{};
            le::store_le32(head.data(), static_cast<std::uint32_t>(pending.name.size()));
            return write_bytes(head.data(), head.size());
        })
        .and_then([&] { return write_bytes(pending.name.data(), pending.name.size()); })
        .and_then([&] {
            // bitness + 3 reserved + payload length
            std::array<std::uint8_t, 4 + sizeof(std::uint64_t)> tail{};
            tail[0] = pending.bitness;
            le::store_le64(tail.data() + 4, static_cast<std::uint64_t>(pending.bytes.size()));
            return write_bytes(tail.data(), tail.size());
        })
        .and_then([&] { return write_bytes(pending.bytes.data(), pending.bytes.size()); });
}

std::expected<void, Error> Writer::write_clock(const ClockPolicy& clock)
{
    if (header_version_ != kVersionV3 || clock_written_) {
        return std::unexpected(Error::kBadClock);
    }
    // The engine divides by blocks_per_tick in the TickCount publish and
    // publishes qpc_frequency verbatim: a policy without them is not a
    // clock, and the writer refuses it here rather than letting a corrupt
    // replay divide by zero later.
    if (clock.policy_version != kClockPolicyVersion || clock.blocks_per_tick == 0 ||
        clock.qpc_frequency == 0) {
        return std::unexpected(Error::kBadClock);
    }
    std::array<std::uint8_t, kClockBlockSize> block{};
    std::ranges::copy(kClockMarker, block.begin());
    le::store_le32(block.data() + kClockVersionOffset, clock.policy_version);
    le::store_le32(block.data() + kClockPayloadLenOffset, kClockPayloadSize);
    le::store_le64(block.data() + kClockBaseTscOffset, clock.base_tsc);
    le::store_le64(block.data() + kClockTscPerBlockOffset, clock.tsc_per_block);
    le::store_le64(block.data() + kClockBlocksPerTickOffset, clock.blocks_per_tick);
    le::store_le64(block.data() + kClockQpcFrequencyOffset, clock.qpc_frequency);
    le::store_le64(block.data() + kClockBaseQpcOffset, clock.base_qpc);
    le::store_le64(block.data() + kClockQpcPerBlockOffset, clock.qpc_per_block);
    for (std::size_t i = 0; i < 3; ++i) {
        le::store_le32(block.data() + kClockCpuid0x15Offset + i * sizeof(std::uint32_t),
                       clock.cpuid_0x15[i]);
        le::store_le32(block.data() + kClockCpuid0x16Offset + i * sizeof(std::uint32_t),
                       clock.cpuid_0x16[i]);
    }
    clock_written_ = true;
    return write_bytes(block.data(), block.size());
}

Reader::Reader(std::istream& in) : in_(in)
{
}

Error Reader::read_bytes(void* data, const std::size_t size)
{
    in_.read(static_cast<char*>(data), static_cast<std::streamsize>(size));
    if (in_.bad()) {
        return Error::kIoFailure;
    }
    if (static_cast<std::size_t>(in_.gcount()) != size) {
        return Error::kTruncated;
    }
    return Error::kNone;
}

std::expected<Header, Error> Reader::read_header()
{
    std::array<std::uint8_t, kHeaderSize> block{};
    if (const Error error = read_bytes(block.data(), block.size()); error != Error::kNone) {
        return std::unexpected(error);
    }
    if (std::memcmp(block.data(), kMagic, sizeof kMagic) != 0) {
        return std::unexpected(Error::kBadMagic);
    }
    const Header header{
        .version = le::load_le32(block.data() + kVersionOffset),
        .bitness = block[kBitnessOffset],
        .region_count = le::load_le32(block.data() + kRegionCountOffset),
    };
    if (header.version != kVersion && header.version != kVersionV2 &&
        header.version != kVersionV3) {
        return std::unexpected(Error::kUnsupportedVersion);
    }
    if (header.bitness != kBitness64 && header.bitness != kBitness32) {
        return std::unexpected(Error::kBitnessMismatch);
    }
    header_bitness = header.bitness;
    header_version = header.version;
    return header;
}

std::expected<Registers, Error> Reader::read_registers()
{
    std::array<std::uint8_t, kRegistersSize> block{};
    if (const Error error = read_bytes(block.data(), block.size()); error != Error::kNone) {
        return std::unexpected(error);
    }
    Registers registers;
    for (std::size_t i = 0; i < kGprCount; ++i) {
        registers.gpr[i] = le::load_le64(block.data() + i * sizeof(std::uint64_t));
    }
    registers.rip = le::load_le64(block.data() + kRipOffset);
    registers.rflags = le::load_le64(block.data() + kRflagsOffset);
    return registers;
}

std::expected<Metadata, Error> Reader::read_metadata()
{
    std::array<std::uint8_t, kMetadataSize> block{};
    if (const Error error = read_bytes(block.data(), block.size()); error != Error::kNone) {
        return std::unexpected(error);
    }
    Metadata metadata;
    metadata.bitness = header_bitness;
    metadata.peb_address = le::load_le64(block.data());
    metadata.teb_address = le::load_le64(block.data() + kMetadataTebOffset);
    metadata.image_base = le::load_le64(block.data() + kMetadataImageBaseOffset);
    metadata.entry_address = le::load_le64(block.data() + kMetadataEntryOffset);
    std::ranges::copy(block.data() + kMetadataOriginalEntryOffset, block.data() + kMetadataSize,
                      metadata.original_entry_bytes.begin());
    return metadata;
}

std::expected<Region, Error> Reader::read_region()
{
    std::array<std::uint8_t, kRegionRecordSize> record{};
    if (const Error error = read_bytes(record.data(), record.size()); error != Error::kNone) {
        return std::unexpected(error);
    }
    const RegionHeader header{
        .base_address = le::load_le64(record.data()),
        .size = le::load_le64(record.data() + kRegionSizeOffset),
        .protection = le::load_le32(record.data() + kRegionProtectionOffset),
        .type = le::load_le32(record.data() + kRegionTypeOffset),
        .content = record[kRegionContentFlagOffset],
    };
    if (header.content != kContentAbsent && header.content != kContentPresent) {
        return std::unexpected(Error::kBadContent);
    }
    Region region{.header = header};
    if (header.content == kContentPresent && header.size > 0) {
        region.content.resize(static_cast<std::size_t>(header.size));
        if (const Error error = read_bytes(region.content.data(), region.content.size());
            error != Error::kNone) {
            return std::unexpected(error);
        }
    }
    return region;
}

std::expected<PendingModule, Error> Reader::read_pending()
{
    if ((header_version != kVersionV2 && header_version != kVersionV3) || pending_read_) {
        return std::unexpected(Error::kBadPending);
    }
    // Peek the first marker byte before consuming anything: "no pending
    // block" (a v3 EXE container, or a v1/v2 file) fails this check
    // non-destructively, so the caller's clock read starts at the right
    // offset. A first byte that opens a pending-like block is read fully;
    // a full-marker mismatch there means a corrupt container, and whatever
    // the caller reads next fails on its own marker.
    const int first = in_.peek();
    if (first == std::char_traits<char>::eof()) {
        return std::unexpected(Error::kTruncated);
    }
    if (static_cast<std::uint8_t>(first) != kPendingMarker[0]) {
        return std::unexpected(Error::kBadPending);
    }
    return parse_pending_block();
}

std::expected<std::optional<PendingModule>, Error> Reader::read_pending_optional()
{
    if ((header_version != kVersionV2 && header_version != kVersionV3) || pending_read_) {
        return std::unexpected(Error::kBadPending);
    }
    // Absence is decided by the first marker byte alone (the only two legal
    // trailing markers open with different bytes): anything not opening a
    // pending-like block means the pending block is absent and the stream
    // stays untouched for the clock read. A pending-like first byte commits
    // to the full strict parse - a block that starts like pending and then
    // fails its bounds is a corrupt container, not an absent one, so every
    // parse error is a named rejection.
    const int first = in_.peek();
    if (first == std::char_traits<char>::eof()) {
        return std::unexpected(Error::kTruncated);
    }
    if (static_cast<std::uint8_t>(first) != kPendingMarker[0]) {
        return std::nullopt;
    }
    auto pending = parse_pending_block();
    if (!pending) {
        return std::unexpected(pending.error());
    }
    return std::optional(std::move(*pending));
}

std::expected<PendingModule, Error> Reader::parse_pending_block()
{
    std::array<std::uint8_t, sizeof kPendingMarker> marker{};
    if (const Error error = read_bytes(marker.data(), marker.size()); error != Error::kNone) {
        return std::unexpected(error);
    }
    if (std::memcmp(marker.data(), kPendingMarker, sizeof kPendingMarker) != 0) {
        return std::unexpected(Error::kBadPending);
    }
    std::array<std::uint8_t, sizeof(std::uint32_t)> name_len_block{};
    if (const Error error = read_bytes(name_len_block.data(), name_len_block.size());
        error != Error::kNone) {
        return std::unexpected(error);
    }
    const auto name_len = le::load_le32(name_len_block.data());
    if (name_len == 0 || name_len > kMaxPendingNameBytes) {
        return std::unexpected(Error::kBadPending);
    }
    PendingModule pending;
    pending.name.resize(name_len);
    if (const Error error = read_bytes(pending.name.data(), pending.name.size());
        error != Error::kNone) {
        return std::unexpected(error);
    }
    std::array<std::uint8_t, 4 + sizeof(std::uint64_t)> tail{};
    if (const Error error = read_bytes(tail.data(), tail.size()); error != Error::kNone) {
        return std::unexpected(error);
    }
    pending.bitness = tail[0];
    if (pending.bitness != kBitness64 && pending.bitness != kBitness32) {
        return std::unexpected(Error::kBadPending);
    }
    const auto payload_len = le::load_le64(tail.data() + 4);
    if (payload_len == 0 || payload_len > kMaxPendingModuleBytes) {
        return std::unexpected(Error::kBadPending);
    }
    pending.bytes.resize(static_cast<std::size_t>(payload_len));
    if (const Error error = read_bytes(pending.bytes.data(), pending.bytes.size());
        error != Error::kNone) {
        return std::unexpected(error);
    }
    pending_read_ = true;
    return pending;
}

std::expected<ClockPolicy, Error> Reader::read_clock()
{
    if (header_version != kVersionV3 || clock_read_) {
        return std::unexpected(Error::kBadClock);
    }
    std::array<std::uint8_t, sizeof kClockMarker> marker{};
    if (const Error error = read_bytes(marker.data(), marker.size()); error != Error::kNone) {
        return std::unexpected(error);
    }
    if (std::memcmp(marker.data(), kClockMarker, sizeof kClockMarker) != 0) {
        return std::unexpected(Error::kBadClock);
    }
    std::array<std::uint8_t, kClockBaseTscOffset - kClockVersionOffset> head{};
    if (const Error error = read_bytes(head.data(), head.size()); error != Error::kNone) {
        return std::unexpected(error);
    }
    ClockPolicy clock;
    clock.policy_version = le::load_le32(head.data());
    const auto payload_len = le::load_le32(head.data() + sizeof(std::uint32_t));
    if (clock.policy_version != kClockPolicyVersion || payload_len != kClockPayloadSize) {
        // An unknown policy version, or a payload length that does not match
        // the known field layout - both mean this reader would guess at
        // shifted fields, so the block is refused instead.
        return std::unexpected(Error::kBadClock);
    }
    std::array<std::uint8_t, kClockPayloadSize> payload{};
    if (const Error error = read_bytes(payload.data(), payload.size()); error != Error::kNone) {
        return std::unexpected(error);
    }
    clock.base_tsc = le::load_le64(payload.data() + kClockBaseTscOffset - kClockBaseTscOffset);
    clock.tsc_per_block =
        le::load_le64(payload.data() + kClockTscPerBlockOffset - kClockBaseTscOffset);
    clock.blocks_per_tick =
        le::load_le64(payload.data() + kClockBlocksPerTickOffset - kClockBaseTscOffset);
    clock.qpc_frequency =
        le::load_le64(payload.data() + kClockQpcFrequencyOffset - kClockBaseTscOffset);
    clock.base_qpc = le::load_le64(payload.data() + kClockBaseQpcOffset - kClockBaseTscOffset);
    clock.qpc_per_block =
        le::load_le64(payload.data() + kClockQpcPerBlockOffset - kClockBaseTscOffset);
    for (std::size_t i = 0; i < 3; ++i) {
        clock.cpuid_0x15[i] = le::load_le32(payload.data() + kClockCpuid0x15Offset -
                                            kClockBaseTscOffset + i * sizeof(std::uint32_t));
        clock.cpuid_0x16[i] = le::load_le32(payload.data() + kClockCpuid0x16Offset -
                                            kClockBaseTscOffset + i * sizeof(std::uint32_t));
    }
    if (clock.blocks_per_tick == 0 || clock.qpc_frequency == 0) {
        return std::unexpected(Error::kBadClock);
    }
    clock_read_ = true;
    return clock;
}

} // namespace sheller::snapshot
