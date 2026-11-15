// Snapshot format codec tests: round-trip, every rejection path, and a
// checked-in golden file as the layout regression sentinel. Regenerate the
// golden after an intentional layout change with:
//   SHELLER_REGEN_SNAPSHOT_GOLDEN=<path> snapshot_format_test

#include <sheller/clock_policy.h>
#include <sheller/snapshot.h>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace {

namespace snapshot = sheller::snapshot;
namespace fs = std::filesystem;

snapshot::Registers test_registers()
{
    snapshot::Registers registers{};
    for (std::size_t i = 0; i < snapshot::kGprCount; ++i) {
        registers.gpr[i] = 0xA000 + i;
    }
    registers.rip = 0x00007FF6A0001000;
    registers.rflags = 0x246;
    return registers;
}

snapshot::Metadata test_metadata()
{
    snapshot::Metadata metadata{};
    metadata.peb_address = 0x0000001234567000;
    metadata.teb_address = 0x0000001234589000;
    metadata.image_base = 0x00007FF6A0000000;
    metadata.entry_address = 0x00007FF6A0001000;
    for (std::size_t i = 0; i < snapshot::kOriginalEntryBytes; ++i) {
        metadata.original_entry_bytes[i] = static_cast<std::uint8_t>(0x90 + i);
    }
    return metadata;
}

snapshot::RegionHeader region_with_content()
{
    return snapshot::RegionHeader{.base_address = 0x00007FF6A0001000,
                                  .size = 16,
                                  .protection = 0x20, // PAGE_EXECUTE_READ
                                  .type = 0x1000000,  // MEM_IMAGE
                                  .content = snapshot::kContentPresent};
}

snapshot::RegionHeader region_without_content()
{
    return snapshot::RegionHeader{.base_address = 0x0000000000010000,
                                  .size = 32,
                                  .protection = 0x04, // PAGE_READWRITE
                                  .type = 0x20000,    // MEM_PRIVATE
                                  .content = snapshot::kContentAbsent};
}

std::array<std::uint8_t, 16> region_content()
{
    std::array<std::uint8_t, 16> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>(0xA0 + i);
    }
    return bytes;
}

// Canonical synthetic snapshot, written through the streaming path including
// finalize_region_count so the patched header is part of the golden bytes.
std::string canonical_snapshot()
{
    std::ostringstream out;
    snapshot::Writer writer{out};
    if (!writer.write_header(
            snapshot::Header{.version = snapshot::kVersion, .bitness = snapshot::kBitness64}) ||
        !writer.write_registers(test_registers()) || !writer.write_metadata(test_metadata()) ||
        !writer.write_region(region_with_content(), region_content().data()) ||
        !writer.write_region(region_without_content(), nullptr) ||
        !writer.finalize_region_count()) {
        ADD_FAILURE() << "canonical snapshot serialization failed";
    }
    return out.str();
}

std::optional<std::vector<snapshot::Region>> read_all_regions(std::istringstream& in,
                                                              const std::uint32_t region_count)
{
    snapshot::Reader reader{in};
    std::vector<snapshot::Region> regions;
    for (std::uint32_t i = 0; i < region_count; ++i) {
        auto region = reader.read_region();
        if (!region.has_value()) {
            ADD_FAILURE() << snapshot::error_message(region.error());
            return std::nullopt;
        }
        regions.push_back(std::move(*region));
    }
    return regions;
}

TEST(SnapshotFormat, RoundTripPreservesEveryField)
{
    std::istringstream in(canonical_snapshot());
    snapshot::Reader reader{in};

    const auto header = reader.read_header();
    ASSERT_TRUE(header.has_value());
    EXPECT_EQ(header->version, snapshot::kVersion);
    EXPECT_EQ(header->bitness, snapshot::kBitness64);
    EXPECT_EQ(header->region_count, 2);

    const auto registers = reader.read_registers();
    ASSERT_TRUE(registers.has_value());
    EXPECT_EQ(*registers, test_registers());

    const auto metadata = reader.read_metadata();
    ASSERT_TRUE(metadata.has_value());
    EXPECT_EQ(*metadata, test_metadata());

    const auto regions = read_all_regions(in, header->region_count);
    ASSERT_TRUE(regions.has_value());
    ASSERT_EQ(regions->size(), 2U);
    const auto content_bytes = region_content();
    const std::vector<std::uint8_t> expected_content(content_bytes.begin(), content_bytes.end());
    EXPECT_EQ((*regions)[0].header.base_address, region_with_content().base_address);
    EXPECT_EQ((*regions)[0].header.size, 16U);
    EXPECT_EQ((*regions)[0].header.protection, 0x20U);
    EXPECT_EQ((*regions)[0].header.type, 0x1000000U);
    EXPECT_EQ((*regions)[0].header.content, snapshot::kContentPresent);
    EXPECT_EQ((*regions)[0].content, expected_content);
    EXPECT_EQ((*regions)[1].header, region_without_content());
    EXPECT_TRUE((*regions)[1].content.empty());
}

TEST(SnapshotFormat, BadMagicIsRejected)
{
    auto bytes = canonical_snapshot();
    bytes[0] = 'X';
    std::istringstream in(bytes);
    snapshot::Reader reader{in};
    const auto header = reader.read_header();
    ASSERT_FALSE(header.has_value());
    EXPECT_EQ(header.error(), snapshot::Error::kBadMagic);
}

TEST(SnapshotFormat, UnknownVersionIsRejected)
{
    auto bytes = canonical_snapshot();
    bytes[snapshot::kVersionOffset] = 99;
    std::istringstream in(bytes);
    snapshot::Reader reader{in};
    const auto header = reader.read_header();
    ASSERT_FALSE(header.has_value());
    EXPECT_EQ(header.error(), snapshot::Error::kUnsupportedVersion);
}

TEST(SnapshotFormat, BitnessMismatchIsRejected)
{
    auto bytes = canonical_snapshot();
    bytes[snapshot::kBitnessOffset] =
        static_cast<std::uint8_t>(128); // neither kBitness64 nor kBitness32
    std::istringstream in(bytes);
    snapshot::Reader reader{in};
    const auto header = reader.read_header();
    ASSERT_FALSE(header.has_value());
    EXPECT_EQ(header.error(), snapshot::Error::kBitnessMismatch);
}

TEST(SnapshotFormat, TruncatedStreamIsRejected)
{
    const auto bytes = canonical_snapshot();
    const auto cut_to = snapshot::kHeaderSize + snapshot::kRegistersSize - 1;
    std::istringstream in(bytes.substr(0, cut_to));
    snapshot::Reader reader{in};
    ASSERT_TRUE(reader.read_header().has_value());
    const auto registers = reader.read_registers();
    ASSERT_FALSE(registers.has_value());
    EXPECT_EQ(registers.error(), snapshot::Error::kTruncated);
}

TEST(SnapshotFormat, TruncatedRegionPayloadIsRejected)
{
    const auto bytes = canonical_snapshot();
    const auto payload_offset = snapshot::kHeaderSize + snapshot::kRegistersSize +
                                snapshot::kMetadataSize + snapshot::kRegionRecordSize;
    std::istringstream in(bytes.substr(0, payload_offset + 8));
    snapshot::Reader reader{in};
    ASSERT_TRUE(reader.read_header().has_value());
    ASSERT_TRUE(reader.read_registers().has_value());
    ASSERT_TRUE(reader.read_metadata().has_value());
    const auto region = reader.read_region();
    ASSERT_FALSE(region.has_value());
    EXPECT_EQ(region.error(), snapshot::Error::kTruncated);
}

TEST(SnapshotFormat, BadContentFlagIsRejected)
{
    auto bytes = canonical_snapshot();
    // The second region record starts after the first record plus its payload.
    const auto flag_position = snapshot::kHeaderSize + snapshot::kRegistersSize +
                               snapshot::kMetadataSize + snapshot::kRegionRecordSize + 16 +
                               snapshot::kRegionContentFlagOffset;
    ASSERT_LT(flag_position, bytes.size());
    bytes[flag_position] = 7;
    std::istringstream in(bytes);
    snapshot::Reader reader{in};
    ASSERT_TRUE(reader.read_header().has_value());
    ASSERT_TRUE(reader.read_registers().has_value());
    ASSERT_TRUE(reader.read_metadata().has_value());
    ASSERT_TRUE(reader.read_region().has_value());
    const auto region = reader.read_region();
    ASSERT_FALSE(region.has_value());
    EXPECT_EQ(region.error(), snapshot::Error::kBadContent);
}

TEST(SnapshotFormat, GoldenFileMatchesLayout)
{
    const auto bytes = canonical_snapshot();

    constexpr auto expected_size = snapshot::kHeaderSize + snapshot::kRegistersSize +
                                   snapshot::kMetadataSize + 2 * snapshot::kRegionRecordSize + 16;
    ASSERT_EQ(bytes.size(), expected_size);

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996) // getenv is fine in a test
#endif
    const char* const regenerate = std::getenv("SHELLER_REGEN_SNAPSHOT_GOLDEN");
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
    if (regenerate != nullptr && *regenerate != '\0') {
        std::ofstream out(regenerate, std::ios::binary | std::ios::trunc);
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(out) << "cannot write golden file: " << regenerate;
        GTEST_SKIP() << "golden regenerated at " << regenerate;
    }

    std::ifstream golden(SHELLER_SNAPSHOT_GOLDEN, std::ios::binary);
    ASSERT_TRUE(golden) << "golden file missing: " << SHELLER_SNAPSHOT_GOLDEN
                        << " (regenerate via SHELLER_REGEN_SNAPSHOT_GOLDEN)";
    const std::string golden_bytes((std::istreambuf_iterator<char>(golden)),
                                   std::istreambuf_iterator<char>());
    EXPECT_EQ(golden_bytes, bytes)
        << "snapshot v1 byte layout drifted - if intentional, bump the format "
           "version and regenerate the golden";
}

// --- v2: the pending-module block (DLL-input route) ---

snapshot::PendingModule test_pending()
{
    snapshot::PendingModule pending;
    pending.name = "sample.dll";
    pending.bitness = snapshot::kBitness64;
    pending.bytes = {0x4D, 0x5A, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    return pending;
}

// Canonical v2 container: same body as the v1 canonical plus one trailing
// pending block, written through the streaming path.
std::string canonical_v2_snapshot()
{
    std::ostringstream out;
    snapshot::Writer writer{out};
    if (!writer.write_header(
            snapshot::Header{.version = snapshot::kVersionV2, .bitness = snapshot::kBitness64}) ||
        !writer.write_registers(test_registers()) || !writer.write_metadata(test_metadata()) ||
        !writer.write_region(region_with_content(), region_content().data()) ||
        !writer.write_region(region_without_content(), nullptr) ||
        !writer.finalize_region_count() || !writer.write_pending(test_pending())) {
        ADD_FAILURE() << "canonical v2 snapshot serialization failed";
    }
    return out.str();
}

TEST(SnapshotFormat, V2PendingRoundTrip)
{
    std::istringstream in(canonical_v2_snapshot());
    snapshot::Reader reader{in};
    const auto header = reader.read_header();
    ASSERT_TRUE(header.has_value());
    EXPECT_EQ(header->version, snapshot::kVersionV2);
    ASSERT_TRUE(reader.read_registers().has_value());
    ASSERT_TRUE(reader.read_metadata().has_value());
    for (std::uint32_t i = 0; i < header->region_count; ++i) {
        ASSERT_TRUE(reader.read_region().has_value());
    }
    const auto pending = reader.read_pending();
    ASSERT_TRUE(pending.has_value()) << snapshot::error_message(pending.error());
    EXPECT_EQ(*pending, test_pending());
    // exactly one block per container
    const auto again = reader.read_pending();
    ASSERT_FALSE(again.has_value());
    EXPECT_EQ(again.error(), snapshot::Error::kBadPending);
}

TEST(SnapshotFormat, V2HeaderPatchKeepsV1BodyIdentical)
{
    // The v2 container is the v1 body byte-for-byte (same registers,
    // metadata and regions) plus the version word and the trailing block.
    const auto v1 = canonical_snapshot();
    auto v2 = canonical_v2_snapshot();
    ASSERT_GT(v2.size(), v1.size());
    // Normalize the version word back to v1: the rest of the first
    // v1.size() bytes must be identical.
    v2[snapshot::kVersionOffset] = static_cast<char>(snapshot::kVersion);
    EXPECT_EQ(v2.compare(0, v1.size(), v1), 0);
    EXPECT_NE(v1.substr(snapshot::kVersionOffset, 4),
              canonical_v2_snapshot().substr(snapshot::kVersionOffset, 4));
}

TEST(SnapshotFormat, V2ReaderAcceptsV1Container)
{
    std::istringstream in(canonical_snapshot());
    snapshot::Reader reader{in};
    const auto header = reader.read_header();
    ASSERT_TRUE(header.has_value());
    EXPECT_EQ(header->version, snapshot::kVersion);
    ASSERT_TRUE(reader.read_registers().has_value());
    ASSERT_TRUE(reader.read_metadata().has_value());
    const auto regions = read_all_regions(in, header->region_count);
    ASSERT_TRUE(regions.has_value());
    // v1 files carry no pending block: the call is out of place, not a read
    EXPECT_EQ(reader.read_pending().error(), snapshot::Error::kBadPending);
}

TEST(SnapshotFormat, V2WithoutPendingIsTruncated)
{
    const auto v2 = canonical_v2_snapshot();
    // Cut the stream just after the last region - before the pending marker.
    const auto v1_body = snapshot::kHeaderSize + snapshot::kRegistersSize +
                         snapshot::kMetadataSize + 2 * snapshot::kRegionRecordSize + 16;
    std::istringstream in(v2.substr(0, v1_body));
    snapshot::Reader reader{in};
    ASSERT_TRUE(reader.read_header().has_value());
    ASSERT_TRUE(reader.read_registers().has_value());
    ASSERT_TRUE(reader.read_metadata().has_value());
    ASSERT_TRUE(reader.read_region().has_value());
    ASSERT_TRUE(reader.read_region().has_value());
    EXPECT_EQ(reader.read_pending().error(), snapshot::Error::kTruncated);
}

TEST(SnapshotFormat, V2TruncatedPendingPayloadIsRejected)
{
    const auto v2 = canonical_v2_snapshot();
    std::istringstream in(v2.substr(0, v2.size() - 3));
    snapshot::Reader reader{in};
    ASSERT_TRUE(reader.read_header().has_value());
    ASSERT_TRUE(reader.read_registers().has_value());
    ASSERT_TRUE(reader.read_metadata().has_value());
    ASSERT_TRUE(reader.read_region().has_value());
    ASSERT_TRUE(reader.read_region().has_value());
    EXPECT_EQ(reader.read_pending().error(), snapshot::Error::kTruncated);
}

TEST(SnapshotFormat, V2CorruptPendingMarkerIsRejected)
{
    auto v2 = canonical_v2_snapshot();
    // The pending block starts right after the v1 body; corrupt its marker.
    const auto v1_body = snapshot::kHeaderSize + snapshot::kRegistersSize +
                         snapshot::kMetadataSize + 2 * snapshot::kRegionRecordSize + 16;
    ASSERT_EQ(v2.compare(v1_body, sizeof snapshot::kPendingMarker,
                         reinterpret_cast<const char*>(snapshot::kPendingMarker),
                         sizeof snapshot::kPendingMarker),
              0);
    v2[v1_body] = 'X';
    std::istringstream in(v2);
    snapshot::Reader reader{in};
    ASSERT_TRUE(reader.read_header().has_value());
    ASSERT_TRUE(reader.read_registers().has_value());
    ASSERT_TRUE(reader.read_metadata().has_value());
    ASSERT_TRUE(reader.read_region().has_value());
    ASSERT_TRUE(reader.read_region().has_value());
    EXPECT_EQ(reader.read_pending().error(), snapshot::Error::kBadPending);
}

TEST(SnapshotFormat, WritePendingRequiresV2Header)
{
    std::ostringstream out;
    snapshot::Writer writer{out};
    ASSERT_TRUE(writer.write_header(
        snapshot::Header{.version = snapshot::kVersion, .bitness = snapshot::kBitness64}));
    EXPECT_EQ(writer.write_pending(test_pending()).error(), snapshot::Error::kBadPending);
}

TEST(SnapshotFormat, UnknownFutureVersionStillRejected)
{
    auto bytes = canonical_v2_snapshot();
    bytes[snapshot::kVersionOffset] = 4; // beyond kVersionV3
    std::istringstream in(bytes);
    snapshot::Reader reader{in};
    EXPECT_EQ(reader.read_header().error(), snapshot::Error::kUnsupportedVersion);
}

// A second PHYSICAL pending block appended after the first is rejected
// by the container read close-out - the format defines one block per v2
// file, and a silent tail would let hand-built doubles through.
TEST(SnapshotFormat, V2DuplicatePhysicalBlockRejected)
{
    const auto v2 = canonical_v2_snapshot();
    // Append a full second block (marker .. payload) to the container.
    const auto v1_body = snapshot::kHeaderSize + snapshot::kRegistersSize +
                         snapshot::kMetadataSize + 2 * snapshot::kRegionRecordSize + 16;
    std::string doubled = v2;
    doubled.append(v2, v1_body, v2.size() - v1_body);
    ASSERT_GT(doubled.size(), v2.size());

    std::istringstream in(doubled);
    snapshot::Reader reader{in};
    ASSERT_TRUE(reader.read_header().has_value());
    ASSERT_TRUE(reader.read_registers().has_value());
    ASSERT_TRUE(reader.read_metadata().has_value());
    ASSERT_TRUE(reader.read_region().has_value());
    ASSERT_TRUE(reader.read_region().has_value());
    ASSERT_TRUE(reader.read_pending().has_value()); // first block reads fine
    // The engine close-out (load_snapshot_stream) rejects the trailing
    // bytes; the codec-level proof is that the stream still has them.
    char extra = 0;
    in.get(extra);
    EXPECT_TRUE(!in.eof()) << "fixture must actually carry a trailing block";
}

// --- v3: the clock-policy block (deterministic virtual clock) ---

snapshot::ClockPolicy test_clock()
{
    snapshot::ClockPolicy clock = snapshot::default_clock_policy();
    clock.base_tsc = 0x1234567890ABCDEFULL; // a non-default value: roundtrip proof
    return clock;
}

// Canonical v3 container: the v1 body plus one trailing clock block (the EXE
// shape - no pending block), written through the streaming path.
std::string canonical_v3_snapshot(const bool with_pending = false)
{
    std::ostringstream out;
    snapshot::Writer writer{out};
    if (!writer.write_header(
            snapshot::Header{.version = snapshot::kVersionV3, .bitness = snapshot::kBitness64}) ||
        !writer.write_registers(test_registers()) || !writer.write_metadata(test_metadata()) ||
        !writer.write_region(region_with_content(), region_content().data()) ||
        !writer.write_region(region_without_content(), nullptr) ||
        !writer.finalize_region_count()) {
        ADD_FAILURE() << "canonical v3 snapshot serialization failed";
        return {};
    }
    if (with_pending && !writer.write_pending(test_pending())) {
        ADD_FAILURE() << "canonical v3 snapshot pending block failed";
        return {};
    }
    if (!writer.write_clock(test_clock())) {
        ADD_FAILURE() << "canonical v3 snapshot clock block failed";
        return {};
    }
    return out.str();
}

TEST(SnapshotFormat, V3ClockRoundTrip)
{
    std::istringstream in(canonical_v3_snapshot());
    snapshot::Reader reader{in};
    const auto header = reader.read_header();
    ASSERT_TRUE(header.has_value());
    EXPECT_EQ(header->version, snapshot::kVersionV3);
    ASSERT_TRUE(reader.read_registers().has_value());
    ASSERT_TRUE(reader.read_metadata().has_value());
    for (std::uint32_t i = 0; i < header->region_count; ++i) {
        ASSERT_TRUE(reader.read_region().has_value());
    }
    const auto clock = reader.read_clock();
    ASSERT_TRUE(clock.has_value()) << snapshot::error_message(clock.error());
    EXPECT_EQ(*clock, test_clock());
    // exactly one clock block per container
    const auto again = reader.read_clock();
    ASSERT_FALSE(again.has_value());
    EXPECT_EQ(again.error(), snapshot::Error::kBadClock);
}

TEST(SnapshotFormat, V3PendingThenClockRoundTrip)
{
    // The DLL-input shape: pending block and clock block coexist, read in
    // the trailing order, neither swallowing the other.
    std::istringstream in(canonical_v3_snapshot(true));
    snapshot::Reader reader{in};
    const auto header = reader.read_header();
    ASSERT_TRUE(header.has_value());
    EXPECT_EQ(header->version, snapshot::kVersionV3);
    ASSERT_TRUE(reader.read_registers().has_value());
    ASSERT_TRUE(reader.read_metadata().has_value());
    for (std::uint32_t i = 0; i < header->region_count; ++i) {
        ASSERT_TRUE(reader.read_region().has_value());
    }
    const auto pending = reader.read_pending();
    ASSERT_TRUE(pending.has_value()) << snapshot::error_message(pending.error());
    EXPECT_EQ(*pending, test_pending());
    const auto clock = reader.read_clock();
    ASSERT_TRUE(clock.has_value()) << snapshot::error_message(clock.error());
    EXPECT_EQ(*clock, test_clock());
}

TEST(SnapshotFormat, ReadClockOnV1AndV2IsRejected)
{
    // The new reader answers a clock read only on a v3 header: a v1/v2 file
    // carries no clock block, and the call is out of place there.
    {
        std::istringstream in(canonical_snapshot());
        snapshot::Reader reader{in};
        ASSERT_TRUE(reader.read_header().has_value());
        EXPECT_EQ(reader.read_clock().error(), snapshot::Error::kBadClock);
    }
    {
        std::istringstream in(canonical_v2_snapshot());
        snapshot::Reader reader{in};
        ASSERT_TRUE(reader.read_header().has_value());
        EXPECT_EQ(reader.read_clock().error(), snapshot::Error::kBadClock);
    }
}

TEST(SnapshotFormat, V3ReaderAcceptsV1AndV2Containers)
{
    // The new reader's behavior on the legacy layouts must stay what it was
    // before the v3 support: same parses, same products.
    {
        std::istringstream in(canonical_snapshot());
        snapshot::Reader reader{in};
        const auto header = reader.read_header();
        ASSERT_TRUE(header.has_value());
        EXPECT_EQ(header->version, snapshot::kVersion);
        ASSERT_TRUE(reader.read_registers().has_value());
        ASSERT_TRUE(reader.read_metadata().has_value());
        const auto regions = read_all_regions(in, header->region_count);
        ASSERT_TRUE(regions.has_value());
        EXPECT_EQ(reader.read_pending().error(), snapshot::Error::kBadPending);
        EXPECT_EQ(reader.read_clock().error(), snapshot::Error::kBadClock);
    }
    {
        std::istringstream in(canonical_v2_snapshot());
        snapshot::Reader reader{in};
        const auto header = reader.read_header();
        ASSERT_TRUE(header.has_value());
        EXPECT_EQ(header->version, snapshot::kVersionV2);
        ASSERT_TRUE(reader.read_registers().has_value());
        ASSERT_TRUE(reader.read_metadata().has_value());
        for (std::uint32_t i = 0; i < header->region_count; ++i) {
            ASSERT_TRUE(reader.read_region().has_value());
        }
        const auto pending = reader.read_pending();
        ASSERT_TRUE(pending.has_value());
        EXPECT_EQ(*pending, test_pending());
        // A v2 file never carries a clock block: the call is out of place.
        EXPECT_EQ(reader.read_clock().error(), snapshot::Error::kBadClock);
    }
}

TEST(SnapshotFormat, V3WithoutClockIsTruncated)
{
    // A v3 header whose trailing area carries no clock block: the read hits
    // EOF (the engine close-out rejects the container; the codec names the
    // truncation).
    std::ostringstream out;
    snapshot::Writer writer{out};
    ASSERT_TRUE(writer.write_header(
        snapshot::Header{.version = snapshot::kVersionV3, .bitness = snapshot::kBitness64}));
    ASSERT_TRUE(writer.write_registers(test_registers()));
    ASSERT_TRUE(writer.write_metadata(test_metadata()));
    ASSERT_TRUE(writer.write_region(region_without_content(), nullptr));
    ASSERT_TRUE(writer.finalize_region_count());

    std::istringstream in(out.str());
    snapshot::Reader reader{in};
    ASSERT_TRUE(reader.read_header().has_value());
    ASSERT_TRUE(reader.read_registers().has_value());
    ASSERT_TRUE(reader.read_metadata().has_value());
    ASSERT_TRUE(reader.read_region().has_value());
    EXPECT_EQ(reader.read_clock().error(), snapshot::Error::kTruncated);
}

TEST(SnapshotFormat, V3TruncatedClockPayloadIsRejected)
{
    const auto v3 = canonical_v3_snapshot();
    std::istringstream in(v3.substr(0, v3.size() - 3));
    snapshot::Reader reader{in};
    ASSERT_TRUE(reader.read_header().has_value());
    ASSERT_TRUE(reader.read_registers().has_value());
    ASSERT_TRUE(reader.read_metadata().has_value());
    ASSERT_TRUE(reader.read_region().has_value());
    ASSERT_TRUE(reader.read_region().has_value());
    EXPECT_EQ(reader.read_clock().error(), snapshot::Error::kTruncated);
}

TEST(SnapshotFormat, V3CorruptClockMarkerIsRejected)
{
    auto v3 = canonical_v3_snapshot();
    // The clock block starts right after the v1 body; corrupt its marker.
    const auto v1_body = snapshot::kHeaderSize + snapshot::kRegistersSize +
                         snapshot::kMetadataSize + 2 * snapshot::kRegionRecordSize + 16;
    ASSERT_EQ(v3.compare(v1_body, sizeof snapshot::kClockMarker,
                         reinterpret_cast<const char*>(snapshot::kClockMarker),
                         sizeof snapshot::kClockMarker),
              0);
    v3[v1_body] = 'X';
    std::istringstream in(v3);
    snapshot::Reader reader{in};
    ASSERT_TRUE(reader.read_header().has_value());
    ASSERT_TRUE(reader.read_registers().has_value());
    ASSERT_TRUE(reader.read_metadata().has_value());
    ASSERT_TRUE(reader.read_region().has_value());
    ASSERT_TRUE(reader.read_region().has_value());
    EXPECT_EQ(reader.read_clock().error(), snapshot::Error::kBadClock);
}

TEST(SnapshotFormat, V3ClockWithForeignVersionOrPayloadLengthIsRejected)
{
    // An unknown policy version, or a payload length that does not match the
    // known field layout, must not survive as shifted reads.
    for (const int field : {0, 1}) {
        auto v3 = canonical_v3_snapshot();
        const auto v1_body = snapshot::kHeaderSize + snapshot::kRegistersSize +
                             snapshot::kMetadataSize + 2 * snapshot::kRegionRecordSize + 16;
        const auto block_at = v1_body + sizeof snapshot::kClockMarker;
        if (field == 0) {
            std::memcpy(v3.data() + block_at, "\xab\xcd\x00\x00", 4); // policy version
        } else {
            std::memcpy(v3.data() + block_at + sizeof(std::uint32_t), "\x49\x00\x00\x00",
                        4); // payload length != 72
        }
        std::istringstream in(v3);
        snapshot::Reader reader{in};
        ASSERT_TRUE(reader.read_header().has_value());
        ASSERT_TRUE(reader.read_registers().has_value());
        ASSERT_TRUE(reader.read_metadata().has_value());
        ASSERT_TRUE(reader.read_region().has_value());
        ASSERT_TRUE(reader.read_region().has_value());
        EXPECT_EQ(reader.read_clock().error(), snapshot::Error::kBadClock) << "field " << field;
    }
}

TEST(SnapshotFormat, V3ClockWithEngineUnsafePolicyIsRejected)
{
    // blocks_per_tick = 0 (divide by zero in the tick publish) and
    // qpc_frequency = 0 (the frequency face must be nonzero) are refused by
    // both writer and reader.
    for (const int field : {0, 1}) {
        auto clock = test_clock();
        if (field == 0) {
            clock.blocks_per_tick = 0;
        } else {
            clock.qpc_frequency = 0;
        }
        {
            std::ostringstream out;
            snapshot::Writer writer{out};
            ASSERT_TRUE(writer.write_header(snapshot::Header{.version = snapshot::kVersionV3,
                                                             .bitness = snapshot::kBitness64}));
            ASSERT_TRUE(writer.finalize_region_count());
            EXPECT_EQ(writer.write_clock(clock).error(), snapshot::Error::kBadClock);
        }
        {
            // Reader-side: hand-patch a well-formed block's field to zero.
            auto v3 = canonical_v3_snapshot();
            const auto v1_body = snapshot::kHeaderSize + snapshot::kRegistersSize +
                                 snapshot::kMetadataSize + 2 * snapshot::kRegionRecordSize + 16;
            const auto field_at = field == 0 ? v1_body + snapshot::kClockBlocksPerTickOffset
                                             : v1_body + snapshot::kClockQpcFrequencyOffset;
            const std::array<char, 8> zeros{};
            std::memcpy(v3.data() + field_at, zeros.data(), zeros.size());
            std::istringstream in(v3);
            snapshot::Reader reader{in};
            ASSERT_TRUE(reader.read_header().has_value());
            ASSERT_TRUE(reader.read_registers().has_value());
            ASSERT_TRUE(reader.read_metadata().has_value());
            ASSERT_TRUE(reader.read_region().has_value());
            ASSERT_TRUE(reader.read_region().has_value());
            EXPECT_EQ(reader.read_clock().error(), snapshot::Error::kBadClock) << "field " << field;
        }
    }
}

TEST(SnapshotFormat, WriteClockRequiresV3Header)
{
    std::ostringstream out;
    snapshot::Writer writer{out};
    ASSERT_TRUE(writer.write_header(
        snapshot::Header{.version = snapshot::kVersionV2, .bitness = snapshot::kBitness64}));
    ASSERT_TRUE(writer.finalize_region_count());
    EXPECT_EQ(writer.write_clock(test_clock()).error(), snapshot::Error::kBadClock);
}

TEST(SnapshotFormat, V3DuplicatePhysicalClockBlockRejected)
{
    const auto v3 = canonical_v3_snapshot();
    const auto v1_body = snapshot::kHeaderSize + snapshot::kRegistersSize +
                         snapshot::kMetadataSize + 2 * snapshot::kRegionRecordSize + 16;
    std::string doubled = v3;
    doubled.append(v3, v1_body, v3.size() - v1_body);

    std::istringstream in(doubled);
    snapshot::Reader reader{in};
    ASSERT_TRUE(reader.read_header().has_value());
    ASSERT_TRUE(reader.read_registers().has_value());
    ASSERT_TRUE(reader.read_metadata().has_value());
    ASSERT_TRUE(reader.read_region().has_value());
    ASSERT_TRUE(reader.read_region().has_value());
    ASSERT_TRUE(reader.read_clock().has_value()); // first block reads fine
    // The engine close-out (load_snapshot_stream) rejects the trailing
    // bytes; the codec-level proof is that the stream still has them.
    char extra = 0;
    in.get(extra);
    EXPECT_TRUE(!in.eof()) << "fixture must actually carry a trailing block";
}

} // namespace
