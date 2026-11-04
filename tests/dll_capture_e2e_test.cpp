// DLL-input route, live-capture replay chain (Windows): the captured runner
// world replayed with --guest-stdout must print the DllMain marker (the
// synthetic load reached the real DllMain body and its NtWriteFile rode the
// sink), the run's own saved snapshot must re-enact it, the esp stop
// must close the unpack normally on its documented miss, and the artifact
// chain (raw event stream, dump, repaired .unp) must be byte-identical
// across two independent helper processes over one container.
//
// This suite is excluded from shared CI runners: past the OEP the payload's
// CRT init used to be steered by per-process entropy from the live loader,
// and on runner hardware it crashed before the DllMain print. That entropy
// is now part of the deterministic answer face - the replay is cross-process
// byte-identical on the development machine - but the fixed trajectory has
// not been exercised on shared runner hardware, so the exclusion stands while
// the suite is green here.

#include <gtest/gtest.h>

#ifdef _WIN32
#include <sheller/snapshot.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#endif

#include "test_temp.hpp"
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

namespace fs = std::filesystem;

#ifdef _WIN32
constexpr std::string_view kCliCommand = SHELLER_CLI_FILE_NAME;
#else
constexpr std::string_view kCliCommand = "./" SHELLER_CLI_FILE_NAME;
#endif

std::string run_and_capture(std::string_view args)
{
    const auto out_path = sheller_test::temp_path("sheller_dll_capture_out.txt").string();
    const auto cmd = std::format("{} {} > \"{}\" 2>&1", kCliCommand, args, out_path);
    const auto exit_code = std::system(cmd.c_str());
    std::ifstream file(out_path);
    const std::string output((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
    std::error_code ec;
    fs::remove(out_path, ec);
    return std::format("{}|{}", exit_code, output);
}

#ifdef _WIN32

fs::path packed_dll()
{
    return fs::path{SHELLER_SAMPLE_PACKED_DLL_PATH};
}

// The esp stop face on the packed DLL: the UPX stub's DllMain opens with
// argument-shadow stores and a reason branch before its register saves, so
// the esp scan finds no contiguous push sequence at the re-armed entry and
// esp/esp+xfer are a documented silent miss - the run closes normally and
// the unpack still completes.
TEST(DllCaptureE2E, EspStopMissClosesTheRunNormally)
{
    const auto dir = sheller_test::temp_path("sheller_dll_capture_esp");
    fs::create_directories(dir);
    const auto output = dir / "esp.dll.unp";
    const auto result =
        run_and_capture(std::format("unpack \"{}\" -o \"{}\" --stop esp -b 60M --timeout-ms"
                                    " 300000",
                                    packed_dll().string(), output.string()));
    EXPECT_NE(result.find("esp target not reached"), std::string::npos) << result;
    EXPECT_NE(result.find("terminated=1 exit=0x5a"), std::string::npos) << result;
    EXPECT_TRUE(fs::exists(output)); // the miss closes the run on its own terms
}

// The replay chain: the captured runner world, replayed with --guest-stdout,
// prints the DllMain marker - proof the synthetic load reached the real
// DllMain body (the ATTACH mainline) and its NtWriteFile rode the sink.
TEST(DllCaptureE2E, ReplayPrintsDllMainMarkerThroughGuestStdout)
{
    const auto dir = sheller_test::temp_path("sheller_dll_capture_replay");
    fs::create_directories(dir);
    const auto snap = dir / "packed_dll_v2.snap";
    ASSERT_EQ(run_and_capture(
                  std::format("capture \"{}\" -o \"{}\"", packed_dll().string(), snap.string()))
                  .substr(0, 1),
              "0");
    ASSERT_TRUE(fs::exists(snap));
    const auto result = run_and_capture(std::format(
        "run --from-snapshot \"{}\" --guest-stdout -b 60M --timeout-ms 300000", snap.string()));
    EXPECT_NE(result.find("hello world from dllmain"), std::string::npos) << result;
    // the designed finish: the runner stub's ExitProcess after a TRUE return
    EXPECT_NE(result.find("terminated=1 exit=0x5a"), std::string::npos) << result;
}

// Round trip: the run's own --save-snapshot re-arms the same synthetic
// load from the container block on --from-snapshot - the replayed run prints
// the same DllMain marker and finishes the same way (replay is re-enactment).
TEST(DllCaptureE2E, SavedSnapshotRoundTripReplaysTheSameSemantics)
{
    const auto dir = sheller_test::temp_path("sheller_dll_capture_roundtrip");
    fs::create_directories(dir);
    const auto saved = dir / "saved.snap";
    ASSERT_EQ(run_and_capture(
                  std::format(
                      "run \"{}\" --save-snapshot \"{}\" --guest-stdout -b 60M --timeout-ms 300000",
                      packed_dll().string(), saved.string()))
                  .substr(0, 1),
              "0");
    ASSERT_TRUE(fs::exists(saved));
    const auto result = run_and_capture(std::format(
        "run --from-snapshot \"{}\" --guest-stdout -b 60M --timeout-ms 300000", saved.string()));
    EXPECT_NE(result.find("hello world from dllmain"), std::string::npos) << result;
    EXPECT_NE(result.find("terminated=1 exit=0x5a"), std::string::npos) << result;
}

// The load-stub runner temp file never outlives the capture: the RAII guard
// in the CLI removes it on every exit path (the spawned process may hold the
// image mapped for a moment, so the removal waits for the kernel). After a
// successful CLI capture no sheller_run_*.exe remains in the system temp
// directory - and the capture added none even next to a stale leftover from
// an older crashed run, so the comparison is against the before-set.
TEST(DllCaptureE2E, RunnerTempFileIsGoneAfterCapture)
{
    const auto temp = fs::temp_directory_path();
    const auto runner_temps = [](const fs::path& dir) {
        std::vector<std::string> names;
        for (const auto& entry : fs::directory_iterator(dir)) {
            const auto name = entry.path().filename().string();
            if (name.rfind("sheller_run_", 0) == 0 && name.size() > 4 &&
                name.compare(name.size() - 4, 4, ".exe") == 0) {
                names.push_back(name);
            }
        }
        std::sort(names.begin(), names.end());
        return names;
    };
    const auto before = runner_temps(temp);
    const auto dir = sheller_test::temp_path("sheller_dll_capture_cleanup");
    fs::create_directories(dir);
    const auto snap = dir / "cleanup.snap";
    ASSERT_EQ(run_and_capture(
                  std::format("capture \"{}\" -o \"{}\"", packed_dll().string(), snap.string()))
                  .substr(0, 1),
              "0");
    ASSERT_TRUE(fs::exists(snap));
    EXPECT_EQ(runner_temps(temp), before);
}

#ifdef _WIN32

std::vector<std::uint8_t> read_all_bytes(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::vector<std::string> sorted_dir_names(const fs::path& dir)
{
    std::vector<std::string> names;
    for (const auto& entry : fs::directory_iterator(dir)) {
        names.push_back(entry.path().filename().string());
    }
    std::sort(names.begin(), names.end());
    return names;
}

std::uint32_t pe_entry_rva(const std::vector<std::uint8_t>& pe)
{
    const auto e_lfanew =
        static_cast<std::uint32_t>(pe[0x3C]) | (static_cast<std::uint32_t>(pe[0x3D]) << 8);
    return static_cast<std::uint32_t>(pe[e_lfanew + 40]) |
           (static_cast<std::uint32_t>(pe[e_lfanew + 41]) << 8) |
           (static_cast<std::uint32_t>(pe[e_lfanew + 42]) << 16) |
           (static_cast<std::uint32_t>(pe[e_lfanew + 43]) << 24);
}

#endif // _WIN32

// The artifact-chain determinism pin:
// one capture, then two independent det_helper processes replay the same
// container - the complete raw event stream (type/seq/pc/payload records),
// the exit dump directory (.bin files and manifest) and the repaired .unp
// must be byte-identical across processes. The helper carries no wall clock
// and no instruction budget; the compare runs only after both helpers
// reached the deterministic termination (terminated=1). The two captures'
// own container differences are the live-loader world's and stay outside
// this pin's scope.
TEST(DllCaptureE2E, ReplayArtifactsAreIdenticalAcrossProcesses)
{
    const auto dir = sheller_test::temp_path("sheller_dll_capture_determinism");
    fs::create_directories(dir);
    const auto snap = dir / "packed_dll_v2.snap";
    ASSERT_EQ(run_and_capture(
                  std::format("capture \"{}\" -o \"{}\"", packed_dll().string(), snap.string()))
                  .substr(0, 1),
              "0");
    ASSERT_TRUE(fs::exists(snap));

    // cmd chokes on a quoted forward-slash command, and the generator
    // expression spells the helper path with forward slashes.
    const auto helper_path = fs::path{SHELLER_DET_HELPER_PATH}.make_preferred().string();
    const auto run_helper = [&dir, &snap, &helper_path](const std::string_view tag) {
        const auto work = dir / std::format("work_{}", tag);
        // cmd /c needs the whole line under an extra quote pair when the
        // command token itself is quoted (std::system appends one /c).
        const auto inner =
            std::format("\"{}\" \"{}\" \"{}\"", helper_path, snap.string(), work.string());
        const auto cmd = std::format("\"{}\"", inner);
        return std::pair{std::system(cmd.c_str()), work};
    };
    const auto [code_a, work_a] = run_helper("a");
    const auto [code_b, work_b] = run_helper("b");
    ASSERT_EQ(code_a, 0) << "helper a failed";
    ASSERT_EQ(code_b, 0) << "helper b failed";

    // Deterministic stop first: a helper that aborted on anything but its own
    // termination has nothing to compare.
    const auto stats_text = [](const fs::path& work) {
        const auto bytes = read_all_bytes(work / "stats.txt");
        return std::string(bytes.begin(), bytes.end());
    };
    const auto stats_a = stats_text(work_a);
    const auto stats_b = stats_text(work_b);
    ASSERT_NE(stats_a.find("terminated=1"), std::string::npos) << stats_a;
    ASSERT_NE(stats_b.find("terminated=1"), std::string::npos) << stats_b;

    // OEP correctness, not just cross-process agreement: both helpers could
    // miss the entry point the same way and still match byte for byte. The
    // corpus anchor is the reference entry (0x13E4, the real DllMain - the
    // same line `upx -d` reproduces).
    ASSERT_NE(stats_a.find("oep_found=1"), std::string::npos) << stats_a;
    ASSERT_NE(stats_a.find("oep_rva=0x13e4"), std::string::npos) << stats_a;
    ASSERT_NE(stats_b.find("oep_found=1"), std::string::npos) << stats_b;
    ASSERT_NE(stats_b.find("oep_rva=0x13e4"), std::string::npos) << stats_b;

    // Raw event stream: type/seq/pc/payload records, whole run.
    EXPECT_EQ(read_all_bytes(work_a / "events.bin"), read_all_bytes(work_b / "events.bin"))
        << "raw event streams differ across processes";

    // Dump directory: identical file set, byte-identical contents.
    const auto names_a = sorted_dir_names(work_a / "dump");
    const auto names_b = sorted_dir_names(work_b / "dump");
    ASSERT_EQ(names_a, names_b) << "dump file sets differ across processes";
    for (const auto& name : names_a) {
        EXPECT_EQ(read_all_bytes(work_a / "dump" / name), read_all_bytes(work_b / "dump" / name))
            << "dump file " << name << " differs across processes";
    }

    // The repaired artifact: byte-identical across processes AND carrying
    // the reference entry point in its PE header (an agreeing-but-wrong
    // entry stamps must not pass).
    const auto unpacked_a = read_all_bytes(work_a / "unpacked.unp");
    ASSERT_GE(unpacked_a.size(), 0x40u + 44u) << "unpacked.unp too small for a PE header";
    EXPECT_EQ(pe_entry_rva(unpacked_a), 0x13E4u) << "repaired .unp entry point drifted";
    EXPECT_EQ(unpacked_a, read_all_bytes(work_b / "unpacked.unp"))
        << "repaired .unp differs across processes";
}

#endif // _WIN32

} // namespace
