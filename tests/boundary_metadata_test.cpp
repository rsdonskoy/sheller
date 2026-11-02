// Boundary metadata codec (change real-dll-module-dir, task 4.1): the
// versioned payload encodes deterministically (same input, byte-identical
// bytes), rejects an over-capacity payload by name instead of truncating,
// validates magic/version/checksum/ranges on decode, and the DOS e_res2
// mode marker round-trips over the reserved slot. Portable by design.

#include "boundary_metadata.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

namespace {

using namespace sheller::engine::boundary_metadata;

MetadataInput sample_input()
{
    MetadataInput input;
    // source byte 3 = kDirectoryDerived's ordinal in the engine enum
    input.modules.push_back({"ntdll.dll", 0x7FF800000000ULL, 0x42000, 3, 0x21efce8c9258a643ULL});
    input.modules.push_back({"kernel32.dll", 0x7FFB00000000ULL, 0x42000, 1, 0xdeadbeefULL});
    BoundaryRecord boundary;
    boundary.name = "ntdll.dll";
    boundary.exports.push_back({"NtCreateFile", 0, 0, 0x7FF800000000ULL + 0x1000, 0x55});
    boundary.exports.push_back({"", 5, 0, 0x7FF800000000ULL + 0x1040, 0x66});
    boundary.exports.push_back({"NtWeird", 3, 2, 0x7FF800000000ULL + 0x1030, 0});
    input.boundaries.push_back(std::move(boundary));
    input.counters.push_back({"ucrtbase.dll", "malloc", 1});
    input.intercepts.push_back({0x7FF800000000ULL + 0x1020, 11});
    input.apiset_bytes = {0x41, 0x50, 0x53, 0x4D, 0x4D, 0x41, 0x50, 0x31}; // fake map bytes
    input.apiset_anchor = 0x21efce8c9258a643ULL;
    return input;
}

} // namespace

TEST(BoundaryMetadata, EncodeDecodeRoundTrip)
{
    const auto input = sample_input();
    const auto payload = encode(input);
    ASSERT_TRUE(payload.has_value()) << payload.error().detail;
    const auto decoded = decode(*payload);
    ASSERT_TRUE(decoded.has_value()) << decoded.error().detail;

    ASSERT_EQ(decoded->modules.size(), input.modules.size());
    for (std::size_t i = 0; i < input.modules.size(); ++i) {
        EXPECT_EQ(decoded->modules[i].name, input.modules[i].name);
        EXPECT_EQ(decoded->modules[i].base, input.modules[i].base);
        EXPECT_EQ(decoded->modules[i].size, input.modules[i].size);
        EXPECT_EQ(decoded->modules[i].source, input.modules[i].source);
        EXPECT_EQ(decoded->modules[i].image_xxhash64, input.modules[i].image_xxhash64);
    }
    ASSERT_EQ(decoded->boundaries.size(), 1u);
    EXPECT_EQ(decoded->boundaries[0].name, "ntdll.dll");
    ASSERT_EQ(decoded->boundaries[0].exports.size(), 3u);
    EXPECT_EQ(decoded->boundaries[0].exports[0].name, "NtCreateFile");
    EXPECT_EQ(decoded->boundaries[0].exports[0].syscall_number, 0x55u);
    EXPECT_EQ(decoded->boundaries[0].exports[1].name, ""); // unnamed ordinal
    EXPECT_EQ(decoded->boundaries[0].exports[1].ordinal, 5u);
    EXPECT_EQ(decoded->boundaries[0].exports[2].kind, 2u); // trap
    EXPECT_EQ(decoded->boundaries[0].exports[2].va, 0x7FF800000000ULL + 0x1030);
    ASSERT_EQ(decoded->counters.size(), 1u);
    EXPECT_EQ(decoded->counters[0].module, "ucrtbase.dll");
    EXPECT_EQ(decoded->counters[0].klass, 1u);
    ASSERT_EQ(decoded->intercepts.size(), 1u);
    EXPECT_EQ(decoded->intercepts[0].va, 0x7FF800000000ULL + 0x1020);
    EXPECT_EQ(decoded->intercepts[0].id, 11u);
    EXPECT_EQ(decoded->apiset_bytes, input.apiset_bytes);
    EXPECT_EQ(decoded->apiset_anchor, input.apiset_anchor);
}

TEST(BoundaryMetadata, EncodeIsDeterministic)
{
    const auto first = encode(sample_input());
    const auto second = encode(sample_input());
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    ASSERT_EQ(first->size(), second->size());
    EXPECT_EQ(0, std::memcmp(first->data(), second->data(), first->size()));
    EXPECT_LE(first->size(), kMetadataMaxBytes);
}

TEST(BoundaryMetadata, OverLimitIsNamedRejection)
{
    auto input = sample_input();
    // an apiset map far past the fixed capacity: rejected whole, never
    // truncated
    input.apiset_bytes.assign(kMetadataMaxBytes + 1, std::uint8_t{0x42});
    const auto payload = encode(input);
    ASSERT_FALSE(payload.has_value());
    EXPECT_EQ(payload.error().code, MetadataError::kOverLimit);
    EXPECT_EQ(metadata_error_message(MetadataError::kOverLimit),
              std::string_view("boundary metadata payload exceeds the fixed capacity"));
}

TEST(BoundaryMetadata, DecodeRejectsDamageByName)
{
    const auto payload = encode(sample_input());
    ASSERT_TRUE(payload.has_value());

    // a flipped payload byte: the checksum catches it
    auto damaged = *payload;
    damaged[damaged.size() - 1] ^= 0xFF;
    const auto hash = decode(damaged);
    ASSERT_FALSE(hash.has_value());
    EXPECT_EQ(hash.error().code, MetadataError::kBadPayloadHash);

    // broken magic
    auto bad_magic = *payload;
    bad_magic[0] ^= 0xFF;
    EXPECT_EQ(decode(bad_magic).error().code, MetadataError::kBadMagic);

    // unknown version
    auto bad_version = *payload;
    bad_version[8] = 99;
    EXPECT_EQ(decode(bad_version).error().code, MetadataError::kUnknownVersion);

    // truncated payload
    const auto short_payload = decode(std::span<const std::uint8_t>(payload->data(), 20));
    EXPECT_EQ(short_payload.error().code, MetadataError::kOutOfBounds);
}

TEST(BoundaryMetadata, MarkerRoundTrip)
{
    std::vector<std::uint8_t> image(0x1000, std::uint8_t{0});

    // an unmarked image reads as no marker
    auto unmarked = read_marker(image);
    ASSERT_TRUE(unmarked.has_value());
    EXPECT_FALSE(unmarked->has_value());

    // write, then read back
    ASSERT_TRUE(write_marker(image, kMetadataBase).has_value());
    const auto marked = read_marker(image);
    ASSERT_TRUE(marked.has_value());
    ASSERT_TRUE(marked->has_value());
    EXPECT_EQ(**marked, kMetadataBase);

    // a dirty reserved slot refuses the write
    std::vector<std::uint8_t> dirty(0x1000, std::uint8_t{0});
    dirty[kMarkerOffset] = 1;
    const auto refused = write_marker(dirty, kMetadataBase);
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().code, MetadataError::kBadMarker);

    // a damaged magic reads as the named marker rejection
    std::vector<std::uint8_t> broken = image;
    broken[kMarkerOffset + 3] ^= 0xFF;
    EXPECT_EQ(read_marker(broken).error().code, MetadataError::kBadMarker);
}
