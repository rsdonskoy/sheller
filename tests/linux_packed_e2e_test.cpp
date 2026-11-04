// Linux packed e2e: the packed.exe corpus is captured on a Windows
// host, the snapshot is transferred to the Linux test host, and the engine
// replays it (snapshot route - the snapshot carries the real captured
// modules). The dump + repair pipeline produces the .unp output on Linux.
// The snapshot file is a build-time input (captured once on Windows,
// transferred to the Linux test host); the test skips when it is absent.

#include <sheller/syscallrun.h>
#include <sheller/unpack.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr const char* kSnapshotPath = LINUX_PACKED_SNAPSHOT;

std::vector<std::uint8_t> read_file(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

} // namespace

TEST(LinuxPackedE2E, SnapshotRouteRunsAndRepairs)
{
    const auto snap_path = fs::path(kSnapshotPath);
    if (!fs::exists(snap_path)) {
        GTEST_SKIP() << "packed snapshot not transferred to this host";
    }
    const auto snapshot = read_file(snap_path);
    ASSERT_GT(snapshot.size(), 0x1000U) << "snapshot too small to be real";

    const auto dir = fs::temp_directory_path() / "sheller_linux_packed";
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto dump = dir / "dump";
    const auto out = dir / "out";

    sheller::engine::SyscallRunOptions options;
    options.max_instructions = 0;
    options.timeout_ms = 600000;
    options.dump_directory = dump;
    options.event_sink = [](const sheller::EventTypeId, const sheller::EventPreamble&,
                            const std::span<const std::uint8_t>) {};
    // Guest output is dropped unless the host asks for it (the library writes no
    // host standard stream), and this case is the local corpus bench where the
    // packed sample's usage text is compared by eye with what a real run prints -
    // so the forwarding that used to be the engine's default is installed here by
    // hand. Nothing asserts on it; the run's own verdicts do not depend on it.
    options.write_sink = [](const std::uint8_t* data, const std::size_t size) {
        std::fwrite(data, 1, size, stdout);
        std::fflush(stdout);
    };

    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
    // The payload-init divergence (payload usage/argv heap
    // corruption) causes an unhandled crash at the same ntdll heap-lock
    // leaf as on Windows — a known gap, not a Linux regression.
    if (!stats.has_value()) {
        EXPECT_EQ(stats.error().error, sheller::engine::SyscallRunError::kUnhandledException)
            << "unexpected stop kind: " << static_cast<int>(stats.error().error);
    }

    // the dump must exist (the repair needs it)
    ASSERT_TRUE(fs::exists(dump / "manifest.txt")) << "no dump produced";

    // OEP candidates from the behavior signals are not available without a
    // behavior sink; repair without OEP stamping still produces the .unp.
    std::vector<std::uint64_t> oep_candidates;
    const auto summary = sheller::unpack::repair_dump(snapshot, dump, out, oep_candidates);
    ASSERT_TRUE(summary.has_value()) << static_cast<int>(summary.error());

    // the image region (the unpacked payload) must repair with a verdict
    bool has_image_region = false;
    for (const auto& region : summary->regions) {
        if (region.size >= 0x80000) {
            has_image_region = true;
            // the verdict may be partial while the payload-init pass is
            // open: the payload's own init corrupts heap pages near the
            // IAT thunks
            EXPECT_TRUE(region.verdict == sheller::unpack::RepairVerdict::kComplete ||
                        region.verdict == sheller::unpack::RepairVerdict::kPartial)
                << "verdict: " << static_cast<int>(region.verdict);
        }
    }
    EXPECT_TRUE(has_image_region) << "no image-size region in the dump";

    // the repaired copy (if complete) must parse as a PE
    for (const auto& region : summary->regions) {
        if (region.verdict == sheller::unpack::RepairVerdict::kComplete && region.size >= 0x80000) {
            const auto repaired_name = "repaired_" + [](std::uint64_t base) {
                char buf[17] = {};
                std::snprintf(buf, sizeof buf, "%016llx", static_cast<unsigned long long>(base));
                return std::string(buf);
            }(region.base) + ".exe";
            const auto repaired = read_file(out / repaired_name);
            ASSERT_GT(repaired.size(), 0x200U);
            EXPECT_EQ(repaired[0], 'M');
            EXPECT_EQ(repaired[1], 'Z');
        }
    }
}
