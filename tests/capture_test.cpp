// Windows-only end-to-end capture tests: spawn the compiler-built sample
// under the real loader, photograph it, and validate the snapshot contents -
// the acceptance path (a snapshot produced from a sample). The sample is
// a real linker-built PE (tests/capture_sample.c) with an exported marker
// variable and a TLS callback that would set it.

#include "capture_detail.h"
#include "pe_headers.h"

#include <sheller/capture.h>
#include <sheller/snapshot.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace {

namespace capture = sheller::capture;
namespace fs = std::filesystem;
namespace snapshot = sheller::snapshot;

// The capture pipeline opens the output file strictly (no parent directory
// creation), so every test materializes its scratch directory first.
fs::path test_dir()
{
    static const fs::path dir = [] {
        const auto path = fs::temp_directory_path() / "sheller_capture_test";
        std::error_code ec;
        fs::create_directories(path, ec);
        return path;
    }();
    return dir;
}

std::string read_bytes(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

struct SnapshotContents {
    snapshot::Header header{};
    snapshot::Registers registers{};
    snapshot::Metadata metadata{};
    std::vector<snapshot::Region> regions;
};

std::optional<SnapshotContents> read_snapshot(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        ADD_FAILURE() << "cannot open snapshot: " << path.string();
        return std::nullopt;
    }
    snapshot::Reader reader{in};
    SnapshotContents contents;
    auto header = reader.read_header();
    if (!header) {
        ADD_FAILURE() << snapshot::error_message(header.error());
        return std::nullopt;
    }
    contents.header = *header;
    auto registers = reader.read_registers();
    auto metadata = reader.read_metadata();
    if (!registers || !metadata) {
        ADD_FAILURE() << "snapshot header ok but blocks unreadable";
        return std::nullopt;
    }
    contents.registers = *registers;
    contents.metadata = *metadata;
    for (std::uint32_t i = 0; i < contents.header.region_count; ++i) {
        auto region = reader.read_region();
        if (!region) {
            ADD_FAILURE() << snapshot::error_message(region.error());
            return std::nullopt;
        }
        contents.regions.push_back(std::move(*region));
    }
    return contents;
}

const snapshot::Region* region_containing(const SnapshotContents& contents,
                                          const std::uint64_t address)
{
    for (const auto& region : contents.regions) {
        if (region.header.base_address <= address &&
            address < region.header.base_address + region.header.size) {
            return &region;
        }
    }
    return nullptr;
}

std::uint64_t read_scalar(const SnapshotContents& contents, const std::uint64_t address,
                          const std::size_t width)
{
    const auto* region = region_containing(contents, address);
    EXPECT_NE(region, nullptr) << std::format("no region at 0x{:X}", address);
    if (region == nullptr) {
        return 0;
    }
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i) {
        value |= static_cast<std::uint64_t>(
                     region->content.at(address - region->header.base_address + i))
                 << (8 * i);
    }
    return value;
}

std::string read_c_string(const SnapshotContents& contents, const std::uint64_t address)
{
    const auto* region = region_containing(contents, address);
    EXPECT_NE(region, nullptr);
    if (region == nullptr) {
        return {};
    }
    std::string text;
    for (std::uint64_t cursor = address; cursor < region->header.base_address + region->header.size;
         ++cursor) {
        const auto byte = region->content.at(cursor - region->header.base_address);
        if (byte == 0) {
            return text;
        }
        text.push_back(static_cast<char>(byte));
    }
    return text;
}

// Resolves an exported variable's VA by walking the export directory inside
// the snapshot's own captured image bytes.
std::optional<std::uint64_t> find_export(const SnapshotContents& contents,
                                         const std::string_view name)
{
    const auto base = contents.metadata.image_base;
    const auto* headers = region_containing(contents, base);
    if (headers == nullptr || headers->content.size() < 0x200 || headers->content.at(0) != 'M' ||
        headers->content.at(1) != 'Z') {
        return std::nullopt;
    }
    const auto* dos = reinterpret_cast<const capture::DosHeader*>(headers->content.data());
    const auto* nt =
        reinterpret_cast<const capture::NtHeaders64*>(headers->content.data() + dos->e_lfanew);
    const auto& export_directory = nt->optional_header.data_directory[0];
    if (export_directory.virtual_address == 0) {
        return std::nullopt;
    }
    const auto directory_va = base + export_directory.virtual_address;
    const auto number_of_names = read_scalar(contents, directory_va + 24, 4);
    const auto names_va = base + read_scalar(contents, directory_va + 32, 4);
    const auto ordinals_va = base + read_scalar(contents, directory_va + 36, 4);
    const auto functions_va = base + read_scalar(contents, directory_va + 28, 4);
    for (std::uint32_t i = 0; i < number_of_names; ++i) {
        if (read_c_string(contents, base + read_scalar(contents, names_va + 4 * i, 4)) == name) {
            const auto ordinal = read_scalar(contents, ordinals_va + 2 * i, 2);
            return base + read_scalar(contents, functions_va + 4 * ordinal, 4);
        }
    }
    return std::nullopt;
}

TEST(Capture, ProducesSnapshotFromSyntheticSample)
{
    const auto output = test_dir() / "plain.snap";
    const auto result = capture::detail::run_impl(
        capture::Options{.sample_path = SHELLER_CAPTURE_SAMPLE_PATH, .output_path = output});
    ASSERT_EQ(result.status, capture::Status::kOk) << result.detail;

    const auto contents = read_snapshot(output);
    ASSERT_TRUE(contents);
    EXPECT_EQ(contents->header.version, snapshot::kVersionV3); // production path pins the clock
    EXPECT_EQ(contents->header.bitness, snapshot::kBitness64);
    EXPECT_GT(contents->header.region_count, 0U);

    // Snapshot point is the entry spin: RIP sits exactly on the entry VA, and
    // PEB/TEB plus the main image base are recorded.
    EXPECT_EQ(contents->registers.rip, contents->metadata.entry_address);
    EXPECT_NE(contents->metadata.peb_address, 0U);
    EXPECT_NE(contents->metadata.teb_address, 0U);
    EXPECT_NE(contents->metadata.image_base, 0U);

    // The region under the entry still carries the patched spin bytes; the
    // headers page keeps the loader-mapped image; the saved originals are the
    // linker entry bytes the engine side restores before execution.
    const auto* entry_region = region_containing(*contents, contents->metadata.entry_address);
    ASSERT_NE(entry_region, nullptr);
    const auto entry_offset = contents->metadata.entry_address - entry_region->header.base_address;
    ASSERT_LT(entry_offset + 2, entry_region->content.size());
    EXPECT_EQ(entry_region->content.at(entry_offset), 0xEB);
    EXPECT_EQ(entry_region->content.at(entry_offset + 1), 0xFE);
    for (std::size_t i = 0; i < 2; ++i) {
        EXPECT_NE(contents->metadata.original_entry_bytes.at(i), 0xEB);
    }

    // PEB and TEB live inside captured committed regions.
    EXPECT_NE(region_containing(*contents, contents->metadata.peb_address), nullptr);
    EXPECT_NE(region_containing(*contents, contents->metadata.teb_address), nullptr);
}

TEST(Capture, TlsCallbackNeverRunsInRealProcess)
{
    const auto output = test_dir() / "with_tls.snap";
    const auto result = capture::detail::run_impl(
        capture::Options{.sample_path = SHELLER_CAPTURE_SAMPLE_PATH, .output_path = output});
    ASSERT_EQ(result.status, capture::Status::kOk) << result.detail;

    const auto contents = read_snapshot(output);
    ASSERT_TRUE(contents);
    const auto base = contents->metadata.image_base;

    // The loader processed relocations before the snapshot point, so the TLS
    // directory inside the captured image holds actual addresses.
    const auto* headers = region_containing(*contents, base);
    ASSERT_NE(headers, nullptr);
    const auto* dos = reinterpret_cast<const capture::DosHeader*>(headers->content.data());
    const auto* nt =
        reinterpret_cast<const capture::NtHeaders64*>(headers->content.data() + dos->e_lfanew);
    const auto& tls_entry = nt->optional_header.data_directory[capture::kTlsDirectoryIndex];
    ASSERT_NE(tls_entry.virtual_address, 0U);
    const auto tls_directory_va = base + tls_entry.virtual_address;
    const auto callbacks_va = read_scalar(*contents, tls_directory_va + 24, 8);
    ASSERT_NE(callbacks_va, 0U);

    // The callback array was zeroed before the loader ran: its first entry
    // must still be zero in the snapshot (the loader skips a null array).
    EXPECT_EQ(read_scalar(*contents, callbacks_va, 8), 0U);

    // The callback's visible side effect never happened in the real process.
    const auto marker_va = find_export(*contents, "g_marker");
    ASSERT_TRUE(marker_va.has_value());
    EXPECT_EQ(read_scalar(*contents, *marker_va, 1), 0U);

    // Loader-built TLS structures exist: TEB ThreadLocalStoragePointer at +0x58.
    const auto tls_pointer = read_scalar(*contents, contents->metadata.teb_address + 0x58, 8);
    EXPECT_NE(tls_pointer, 0U);
}

TEST(Capture, NoAslrReproducesImageLayout)
{
    const auto dir = test_dir();
    const auto first = dir / "deterministic1.snap";
    const auto second = dir / "deterministic2.snap";

    const auto first_run = capture::detail::run_impl(capture::Options{
        .sample_path = SHELLER_CAPTURE_SAMPLE_PATH, .output_path = first, .disable_aslr = true});
    ASSERT_EQ(first_run.status, capture::Status::kOk) << first_run.detail;
    const auto second_run = capture::detail::run_impl(capture::Options{
        .sample_path = SHELLER_CAPTURE_SAMPLE_PATH, .output_path = second, .disable_aslr = true});
    ASSERT_EQ(second_run.status, capture::Status::kOk) << second_run.detail;

    // With dynamic base disabled the loader honors preferred bases, so the
    // module layout (image plus system DLLs) is reproducible run to run. Heap
    // segments have their own allocator-level randomization and are excluded.
    const auto image_bases_of = [](const fs::path& path) {
        const auto contents = read_snapshot(path);
        EXPECT_TRUE(contents);
        std::set<std::uint64_t> bases;
        for (const auto& region : contents->regions) {
            if (region.header.type == 0x1000000U) { // MEM_IMAGE
                bases.insert(region.header.base_address);
            }
        }
        return bases;
    };
    EXPECT_EQ(image_bases_of(first), image_bases_of(second));
}

TEST(Capture, ArgsTailRidesTheRealCommandLine)
{
    // --args appends to the sample's OS command line: the OS-built
    // ProcessParameters (command line buffer included) are photographed, so
    // a distinctive argument shows up in the captured bytes as UTF-16.
    const auto dir = test_dir();
    const auto output = dir / "args_tail.snap";
    const auto result =
        capture::detail::run_impl(capture::Options{.sample_path = SHELLER_CAPTURE_SAMPLE_PATH,
                                                   .output_path = output,
                                                   .sample_args = "-MARKER_ARG_7B41"});
    ASSERT_EQ(result.status, capture::Status::kOk) << result.detail;
    const auto contents = read_snapshot(output);
    ASSERT_TRUE(contents);

    const auto utf16_of = [](const std::string& text) {
        std::vector<std::uint8_t> wide;
        for (const char c : text) {
            wide.push_back(static_cast<std::uint8_t>(c));
            wide.push_back(0);
        }
        return wide;
    };
    const auto needle = utf16_of("-MARKER_ARG_7B41");
    bool found = false;
    for (const auto& region : contents->regions) {
        if (region.content.size() < needle.size()) {
            continue;
        }
        for (std::size_t i = 0; i + needle.size() <= region.content.size(); ++i) {
            if (std::equal(needle.begin(), needle.end(), region.content.begin() + i)) {
                found = true;
                break;
            }
        }
        if (found) {
            break;
        }
    }
    EXPECT_TRUE(found) << "the argument tail must ride the photographed command line";

    // the zero-argument capture carries no such bytes
    const auto plain = dir / "args_plain.snap";
    const auto plain_run = capture::detail::run_impl(
        capture::Options{.sample_path = SHELLER_CAPTURE_SAMPLE_PATH, .output_path = plain});
    ASSERT_EQ(plain_run.status, capture::Status::kOk) << plain_run.detail;
    const auto plain_contents = read_snapshot(plain);
    ASSERT_TRUE(plain_contents);
    for (const auto& region : plain_contents->regions) {
        ASSERT_FALSE(std::search(region.content.begin(), region.content.end(), needle.begin(),
                                 needle.end()) != region.content.end());
    }
}

TEST(Capture, MissingSampleIsRejected)
{
    const auto result = capture::detail::run_impl(
        capture::Options{.sample_path = fs::temp_directory_path() / "sheller_missing_sample.exe",
                         .output_path = fs::temp_directory_path() / "sheller_missing.snap"});
    EXPECT_EQ(result.status, capture::Status::kSampleNotFound);
    EXPECT_NE(result.detail.find("sample not found"), std::string::npos);
}

TEST(Capture, JunkSampleIsRejected)
{
    const auto dir = test_dir();
    fs::create_directories(dir);
    const auto sample = dir / "junk.exe";
    {
        std::ofstream out(sample, std::ios::binary | std::ios::trunc);
        out << "MZ\x0D\x0Athis is definitely not a PE file"; // PE-looking junk
    }
    const auto result = capture::detail::run_impl(
        capture::Options{.sample_path = sample, .output_path = dir / "junk.snap"});
    EXPECT_EQ(result.status, capture::Status::kNotX64Pe);
}

} // namespace
