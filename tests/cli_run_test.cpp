// CLI-level run tests: the run subcommand executes a snapshot's syscalls and
// prints the run statistics; per-number rejection config goes in as plain
// --reject data, and the event surface is one report artifact at either
// --event-level (semantic by default, full merges the ledger window into it).
// The route is stated, not guessed: --from-snapshot replays, the bare
// positional is a sample pass-through, and a snapshot file without the flag is
// a capture-class refusal. The snapshot source is the Windows capture route, so
// the positive paths are Windows-only; the negative paths run everywhere.

#include <gtest/gtest.h>

#include "esp_fixture.h"
#include "snapshot_fixture.h"
#include "test_temp.hpp"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

#ifdef _WIN32
constexpr std::string_view kCliCommand = SHELLER_CLI_FILE_NAME;
#else
constexpr std::string_view kCliCommand = "./" SHELLER_CLI_FILE_NAME;
#endif

// The esp stop-goal fixtures (see the Esp scenarios at the bottom).
using sheller_test::craft_esp_arm_snapshot;
using sheller_test::craft_esp_snapshot;
using sheller_test::esp_anti_debug_code;
using sheller_test::esp_hit_code;
using sheller_test::esp_pop_rsp_code;
using sheller_test::esp_probe_guard_code;
using sheller_test::esp_relocated_stack_code;

// Runs the CLI with the given args (output captured), returns "rc|output".
// The capture file is a per-process temp path: every CLI suite runs with its
// working directory set to the CLI directory, so a fixed name here lets
// concurrent ctest jobs clobber each other's output.
//
// `prefix` is placed before the executable name, for the cases that have to set an
// environment variable in the same invocation as the run it affects: the library reads
// its switches once per process, so the value has to be in place before it starts.
std::string run_and_capture(std::string_view args, std::string_view prefix = {})
{
    const auto out_path = sheller_test::temp_path("sheller_run_cli_out.txt").string();
    const auto cmd = std::format("{}{} {} > \"{}\" 2>&1", prefix, kCliCommand, args, out_path);
    const auto exit_code = std::system(cmd.c_str());
    std::ifstream file(out_path);
    const std::string output((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
    std::error_code ec;
    std::filesystem::remove(out_path, ec);
    return std::format("{}|{}", exit_code, output);
}

std::string_view exit_code_of(const std::string& result)
{
    return std::string_view{result}.substr(0, result.find('|'));
}

std::string read_file(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

std::size_t occurrences(const std::string& text, std::string_view needle)
{
    std::size_t count = 0;
    for (auto pos = text.find(needle); pos != std::string::npos;
         pos = text.find(needle, pos + needle.size())) {
        ++count;
    }
    return count;
}

// The counts header's value for an event type: only the header spells
// "<name>":N (a detail entry reads "type":"<name>" and then a comma), so the
// header and the rendered entries can be checked against each other.
std::uint64_t counted_in_header(const std::string& json, std::string_view type)
{
    const auto key = std::string("\"") + std::string{type} + "\":";
    const auto at = json.find(key);
    EXPECT_NE(at, std::string::npos) << json;
    if (at == std::string::npos) {
        return 0;
    }
    return std::strtoull(json.c_str() + at + key.size(), nullptr, 10);
}

#ifdef _WIN32

std::string captured_hello_snapshot()
{
    const auto dir = sheller_test::temp_path("sheller_run_cli_test");
    std::filesystem::create_directories(dir);
    const auto snapshot = dir / "run_cli.snap";
    const auto capture = run_and_capture(
        std::format("capture \"{}\" -o \"{}\"", SHELLER_SAMPLE_HELLO_PATH, snapshot.string()));
    EXPECT_EQ(exit_code_of(capture), "0") << capture;
    return snapshot.string();
}

std::string captured_xfer_snapshot()
{
    const auto dir = sheller_test::temp_path("sheller_run_cli_test");
    std::filesystem::create_directories(dir);
    const auto snapshot = dir / "run_cli_xfer.snap";
    const auto capture = run_and_capture(
        std::format("capture \"{}\" -o \"{}\"", SHELLER_SAMPLE_XFER_PATH, snapshot.string()));
    EXPECT_EQ(exit_code_of(capture), "0") << capture;
    return snapshot.string();
}

// The merged-stream helper above cannot tell a line printed on the error
// stream from one echoed on standard output; the refusal's contract is about
// exactly that split, so this one captures the two separately.
struct CliStreams {
    std::string exit_code;
    std::string standard_out;
    std::string standard_err;
};

CliStreams run_with_split_streams(std::string_view args)
{
    const auto dir = sheller_test::temp_path("sheller_run_cli_streams");
    std::filesystem::create_directories(dir);
    const auto out_path = (dir / "out.txt").string();
    const auto err_path = (dir / "err.txt").string();
    const auto cmd = std::format("{} {} > \"{}\" 2> \"{}\"", kCliCommand, args, out_path, err_path);
    const auto exit_code = std::system(cmd.c_str());
    std::error_code ec;
    const auto outcome =
        CliStreams{std::to_string(exit_code), read_file(out_path), read_file(err_path)};
    std::filesystem::remove(out_path, ec);
    std::filesystem::remove(err_path, ec);
    return outcome;
}

TEST(RunCli, FromSnapshotReplayMatchesLibraryDefaults)
{
    const auto result =
        run_and_capture(std::format("run \"{}\" --from-snapshot", captured_hello_snapshot()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("terminated=1"), std::string::npos) << result;
    EXPECT_NE(result.find("exit=0x1234"), std::string::npos) << result;
    EXPECT_NE(result.find("syscalls=3"), std::string::npos) << result;
    EXPECT_NE(result.find("rejects=0"), std::string::npos) << result;
}

TEST(RunCli, XferStopPrintsTheStopAndWritesTheDump)
{
    const auto dir = sheller_test::temp_path("sheller_run_cli_xfer");
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    const auto dump = dir / "dump";
    const auto result =
        run_and_capture(std::format("run \"{}\" --from-snapshot --stop xfer=1 --dump \"{}\"",
                                    captured_xfer_snapshot(), dump.string()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("xfer target reached (xfers=1)"), std::string::npos) << result;
    EXPECT_NE(result.find("terminated=0"), std::string::npos) << result;
    EXPECT_NE(result.find("syscalls=0"), std::string::npos) << result;
    EXPECT_TRUE(std::filesystem::exists(dump / "manifest.txt")) << result;
}

TEST(RunCli, XferMissPrintsAHintAndKeepsTheExitCode)
{
    const auto result = run_and_capture(
        std::format("run \"{}\" --from-snapshot --stop xfer=5", captured_xfer_snapshot()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("xfer target 5 not reached (xfers=2)"), std::string::npos) << result;
    EXPECT_NE(result.find("terminated=1"), std::string::npos) << result;
    EXPECT_NE(result.find("exit=0x5678"), std::string::npos) << result;
}

TEST(RunCli, XferZeroLeavesTheRunAlone)
{
    const auto result = run_and_capture(
        std::format("run \"{}\" --from-snapshot --stop xfer=0", captured_xfer_snapshot()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("terminated=1"), std::string::npos) << result;
    EXPECT_EQ(result.find("xfer target"), std::string::npos) << result;
}

TEST(RunCli, XferBudgetArrivingFirstIsAMiss)
{
    // packed.exe reaches its OEP transfer only after millions of
    // instructions; an explicit 1M instruction budget (smaller than the 3M
    // default) is the deterministic stop, and the miss hint names it.
    const std::filesystem::path sample = SHELLER_SAMPLE_PACKED_PATH;
    if (!std::filesystem::exists(sample)) {
        GTEST_SKIP() << "packed sample not present on this host";
    }
    const auto result = run_and_capture(
        std::format("run \"{}\" --stop xfer=1 -b 1M --timeout-ms 30000", sample.string()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("instruction budget exhausted"), std::string::npos) << result;
    EXPECT_NE(result.find("xfer target 1 not reached (xfers=0)"), std::string::npos) << result;
    EXPECT_NE(result.find("; instruction budget arrived first"), std::string::npos) << result;
    EXPECT_EQ(result.find("xfer target reached"), std::string::npos) << result;
}

TEST(RunCli, XferGoalIsReachableOnTheDefaults)
{
    // The 3M default budget and the 10s default wall clock reach packed's OEP
    // transfer: the goal face is the default run's, no limit flags needed.
    const std::filesystem::path sample = SHELLER_SAMPLE_PACKED_PATH;
    if (!std::filesystem::exists(sample)) {
        GTEST_SKIP() << "packed sample not present on this host";
    }
    const auto result = run_and_capture(std::format("run \"{}\" --stop xfer=1", sample.string()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("xfer target reached (xfers=1)"), std::string::npos) << result;
    EXPECT_EQ(result.find("instruction budget exhausted"), std::string::npos) << result;
}

TEST(RunCli, XferWallClockArrivingFirstIsATimeoutWithHint)
{
    const auto result = run_and_capture(std::format(
        "run \"{}\" --stop xfer=1 -b 0M --timeout-ms 200", std::string(SHELLER_SAMPLE_SPIN_PATH)));
    EXPECT_NE(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("xfer target 1 not reached (xfers=0)"), std::string::npos) << result;
    EXPECT_NE(result.find("; wall clock arrived first"), std::string::npos) << result;
    EXPECT_NE(result.find("timeout"), std::string::npos) << result;
}

TEST(RunCli, XferKeepsTheRunDefaults)
{
    // No -b and no --timeout-ms: the default 3M instruction budget still ends
    // the spin sample before its 10s wall clock, and the stop goal changes
    // neither default.
    const auto result = run_and_capture(
        std::format("run \"{}\" --stop xfer=1", std::string(SHELLER_SAMPLE_SPIN_PATH)));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("instruction budget exhausted"), std::string::npos) << result;
    EXPECT_NE(result.find("xfer target 1 not reached (xfers=0)"), std::string::npos) << result;
    EXPECT_NE(result.find("; instruction budget arrived first"), std::string::npos) << result;
    EXPECT_EQ(result.find("timeout"), std::string::npos) << result;
}

TEST(RunCli, BareSnapshotInputIsRefused)
{
    // The route is the flag's: a snapshot file on the default sample route is a
    // capture-class refusal naming the magic, never a silently rerouted replay.
    // The refusal is told on the error stream - standard output keeps only the
    // artifact line - and nothing ran, so the report the failure path still
    // writes carries no signals and no events and no statistics line appears.
    const auto dir = sheller_test::temp_path("sheller_run_cli_bare_refusal");
    std::filesystem::create_directories(dir);
    const auto report = dir / "refused.json";
    const auto outcome = run_with_split_streams(
        std::format("run \"{}\" --report \"{}\"", captured_hello_snapshot(), report.string()));
    EXPECT_NE(outcome.exit_code, "0") << outcome.standard_out << outcome.standard_err;
    EXPECT_NE(outcome.standard_err.find("capture failed"), std::string::npos)
        << outcome.standard_err;
    EXPECT_NE(outcome.standard_err.find("snapshot magic"), std::string::npos)
        << outcome.standard_err;
    EXPECT_EQ(outcome.standard_out.find("capture failed"), std::string::npos)
        << "the refusal echoed on standard output";
    EXPECT_EQ(outcome.standard_out.find("terminated="), std::string::npos) << outcome.standard_out;
    const auto json = read_file(report);
    EXPECT_EQ(json.find("\"signals\""), std::string::npos) << json;
    EXPECT_NE(json.find("\"events\":{\"counts\":{},\"detail\":[]"), std::string::npos) << json;
    EXPECT_EQ(json.find("\"type\":\"syscall\""), std::string::npos) << json;
}

TEST(RunCli, RejectOverrideTakesEffect)
{
    const auto result = run_and_capture(std::format("run \"{}\" --from-snapshot "
                                                    "--reject 0x1000=0xC0000123",
                                                    captured_hello_snapshot()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    // WriteFile was rejected with the override status; the guest still ran to
    // its own termination (same observable behavior as the in-memory
    // override covered by the syscall e2e tests).
    EXPECT_NE(result.find("rejects=1"), std::string::npos) << result;
    EXPECT_NE(result.find("syscalls=3"), std::string::npos) << result;
    EXPECT_NE(result.find("exit=0x1234"), std::string::npos) << result;
}

TEST(RunCli, BadRejectSpecExitsNonZero)
{
    const auto result = run_and_capture(
        std::format("run \"{}\" --from-snapshot --reject not-a-spec", captured_hello_snapshot()));
    EXPECT_NE(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("--reject"), std::string::npos) << result;
}

TEST(RunCli, GuestOutputStaysSilentUnlessRequested)
{
    // hello writes through NtWriteFile: default discards (the library's
    // embedded-host default), --guest-stdout restores the old behavior.
    const auto snapshot = captured_hello_snapshot();

    const auto quiet = run_and_capture(std::format("run \"{}\" --from-snapshot", snapshot));
    EXPECT_EQ(exit_code_of(quiet), "0") << quiet;
    EXPECT_EQ(quiet.find("hello"), std::string::npos) << quiet;

    const auto loud =
        run_and_capture(std::format("run \"{}\" --from-snapshot --guest-stdout", snapshot));
    EXPECT_EQ(exit_code_of(loud), "0") << loud;
    EXPECT_NE(loud.find("hello"), std::string::npos) << loud;
}

TEST(RunCli, FullEventLevelMergesTheLedgerWindowIntoTheReport)
{
    // --event-level full lights the facade's timeline tier and renders it into
    // the one report: instruction-level entries appear, the semantic entry
    // wins the ordinal its wire twin carries (so no event is spelled twice),
    // and the loss key states what the retained window gave up.
    const auto dir = sheller_test::temp_path("sheller_run_cli_full");
    std::filesystem::create_directories(dir);
    const auto report = dir / "run_cli_full.json";
    const auto result =
        run_and_capture(std::format("run \"{}\" --from-snapshot --report \"{}\" --event-level full",
                                    captured_hello_snapshot(), report.string()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    ASSERT_TRUE(std::filesystem::exists(report));
    const auto json = read_file(report);
    EXPECT_NE(json.find("\"type\":\"block-exec\""), std::string::npos) << json;
    EXPECT_GT(counted_in_header(json, "block-exec"), 0U) << json;
    EXPECT_NE(json.find("\"tid\":"), std::string::npos) << json;
    EXPECT_NE(json.find("\"loss\":{\"dropped\":0,\"truncated\":0}"), std::string::npos) << json;
    EXPECT_EQ(occurrences(json, "\"type\":\"syscall\""), counted_in_header(json, "syscall"))
        << json;
}

TEST(RunCli, FullEventLevelWritesNoCompanionFiles)
{
    // The timeline artifact family is retired: the single report is the whole
    // event surface, with no siblings to join or align.
    const auto dir = sheller_test::temp_path("sheller_run_cli_full");
    std::filesystem::create_directories(dir);
    const auto report = dir / "run_cli_nocompanions.json";
    const auto result =
        run_and_capture(std::format("run \"{}\" --from-snapshot --report \"{}\" --event-level full",
                                    captured_hello_snapshot(), report.string()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    ASSERT_TRUE(std::filesystem::exists(report));
    const auto path = report.string();
    EXPECT_FALSE(std::filesystem::exists(path + ".timeline.json")) << path;
    EXPECT_FALSE(std::filesystem::exists(path + ".calls.json")) << path;
    EXPECT_FALSE(std::filesystem::exists(path + ".stubcalls.json")) << path;
}

// Every detail entry's (type, seq) pair in order. Nested objects (param
// records) carry no "type" key, so the scan only sees entries.
std::vector<std::pair<std::string, std::uint64_t>> detail_type_seqs(const std::string& json)
{
    std::vector<std::pair<std::string, std::uint64_t>> entries;
    const auto detail = json.find("\"detail\":[");
    if (detail == std::string::npos) {
        return entries;
    }
    for (auto at = json.find("\"type\":\"", detail); at != std::string::npos;
         at = json.find("\"type\":\"", at + 8)) {
        const auto type_begin = at + 8;
        const auto type_end = json.find('"', type_begin);
        if (type_end == std::string::npos) {
            break;
        }
        const auto seq_at = json.find("\"seq\":", type_end);
        if (seq_at == std::string::npos) {
            break;
        }
        entries.emplace_back(json.substr(type_begin, type_end - type_begin),
                             std::strtoull(json.c_str() + seq_at + 6, nullptr, 10));
    }
    return entries;
}

bool is_window_type(const std::string& type)
{
    return type == "block-exec" || type == "sample-code" || type == "smc-execute";
}

TEST(RunCli, LevelSwitchOnlyAddsWindowEntriesAndLossShape)
{
    // The two levels share the default-column set, seq values and order; the
    // full level only inserts window-side entries and turns loss into
    // counters.
    const auto dir = sheller_test::temp_path("sheller_run_cli_levels");
    std::filesystem::create_directories(dir);
    const auto semantic_report = dir / "semantic.json";
    const auto full_report = dir / "full.json";
    const auto snapshot = captured_hello_snapshot();
    const auto semantic_run = run_and_capture(std::format(
        "run \"{}\" --from-snapshot --report \"{}\"", snapshot, semantic_report.string()));
    EXPECT_EQ(exit_code_of(semantic_run), "0") << semantic_run;
    const auto full_run =
        run_and_capture(std::format("run \"{}\" --from-snapshot --report \"{}\" --event-level full",
                                    snapshot, full_report.string()));
    EXPECT_EQ(exit_code_of(full_run), "0") << full_run;

    const auto semantic_json = read_file(semantic_report);
    const auto full_json = read_file(full_report);
    const auto semantic_entries = detail_type_seqs(semantic_json);
    auto full_entries = detail_type_seqs(full_json);
    EXPECT_FALSE(semantic_entries.empty()) << semantic_json;
    // Full level adds the window-side types and every mem-write the default
    // column did not carry (the default mem-write subset is the sample-code
    // write into a system module). Remove exactly those additions; what
    // remains must be the semantic list, entry by entry.
    std::erase_if(full_entries, [&](const auto& entry) {
        if (is_window_type(entry.first)) {
            return true;
        }
        return (entry.first == "mem-write" || entry.first == "mem-read") &&
               std::ranges::find(semantic_entries, entry) == semantic_entries.end();
    });
    EXPECT_EQ(semantic_entries, full_entries)
        << "the levels disagree on the default-column entries";
    EXPECT_NE(full_json.find("\"type\":\"block-exec\""), std::string::npos) << full_json;
    EXPECT_NE(semantic_json.find("\"loss\":{\"dropped\":null,\"truncated\":null}"),
              std::string::npos)
        << semantic_json;
    EXPECT_NE(full_json.find("\"loss\":{\"dropped\":0,\"truncated\":0}"), std::string::npos)
        << full_json;
}

TEST(RunCli, DefaultEventLevelIsTheSemanticReport)
{
    // No --event-level: the default column only (semantic seven, mem reads
    // and writes, low-frequency judgments), whole-run seq in every entry, and
    // the null loss pair - and asking for it explicitly spells the same
    // bytes.
    const auto dir = sheller_test::temp_path("sheller_run_cli_default_level");
    std::filesystem::create_directories(dir);
    const auto implicit_report = dir / "implicit.json";
    const auto explicit_report = dir / "explicit.json";
    const auto snapshot = captured_hello_snapshot();
    const auto implicit_run = run_and_capture(std::format(
        "run \"{}\" --from-snapshot --report \"{}\"", snapshot, implicit_report.string()));
    EXPECT_EQ(exit_code_of(implicit_run), "0") << implicit_run;
    const auto explicit_run =
        run_and_capture(std::format("run \"{}\" --from-snapshot --report \"{}\" "
                                    "--event-level semantic",
                                    snapshot, explicit_report.string()));
    EXPECT_EQ(exit_code_of(explicit_run), "0") << explicit_run;

    const auto json = read_file(implicit_report);
    EXPECT_EQ(json, read_file(explicit_report));
    // No ledger at the default level: the loss pair says "not observable".
    EXPECT_NE(json.find("\"loss\":{\"dropped\":null,\"truncated\":null}"), std::string::npos)
        << json;
    EXPECT_EQ(json.find("\"type\":\"block-exec\""), std::string::npos) << json;
    EXPECT_NE(json.find("\"type\":\"syscall\",\"seq\":"), std::string::npos) << json;
}

TEST(RunCli, CountsLevelWritesNoDetailEntries)
{
    // counts is the compact report: exact counts and the side tables, no
    // detail entries and no ledger (the null loss pair).
    const auto dir = sheller_test::temp_path("sheller_run_cli_counts");
    std::filesystem::create_directories(dir);
    const auto report = dir / "run_cli_counts.json";
    const auto result = run_and_capture(
        std::format("run \"{}\" --from-snapshot --report \"{}\" --event-level counts",
                    captured_hello_snapshot(), report.string()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("counts-only"), std::string::npos) << result;
    const auto json = read_file(report);
    EXPECT_NE(json.find("\"counts\":{"), std::string::npos) << json;
    EXPECT_NE(json.find("\"detail\":[]"), std::string::npos) << json;
    EXPECT_NE(json.find("\"loss\":{\"dropped\":null,\"truncated\":null}"), std::string::npos)
        << json;
    EXPECT_EQ(json.find("\"type\":\"syscall\""), std::string::npos) << json;
}

TEST(RunCli, FailedRunStillWritesTheReport)
{
    // A rejected NtTerminateProcess returns to the sample, whose ret lands on
    // an unmapped address: an unhandled crash whose artifacts still carry
    // counts. The report must land even on rc != 0.
    const auto dir = sheller_test::temp_path("sheller_run_cli_test");
    std::filesystem::create_directories(dir);
    const auto report = dir / "run_cli_crash.json";
    const auto result = run_and_capture(
        std::format("run \"{}\" --from-snapshot --reject 0x1002=0xC0000034 --budget "
                    "1M --report \"{}\"",
                    captured_hello_snapshot(), report.string()));
    EXPECT_NE(exit_code_of(result), "0") << result;
    ASSERT_TRUE(std::filesystem::exists(report));
    std::ifstream in(report);
    const std::string json((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_NE(json.find("\"events\":{"), std::string::npos);
    EXPECT_NE(json.find("\"syscall\":"), std::string::npos);
}

TEST(RunCli, BudgetStopWritesTheReportAndExitsZero)
{
    // The spin sample cannot terminate; the budget is the deterministic end
    // of a bounded run at this surface. The report and statistics land, the
    // failure wording is never printed, and the exit code is 0.
    const auto dir = sheller_test::temp_path("sheller_run_cli_test");
    std::filesystem::create_directories(dir);
    const auto report = dir / "run_cli_budget.json";
    const auto result = run_and_capture(
        std::format("run \"{}\" -b 1M --report \"{}\"", SHELLER_SAMPLE_SPIN_PATH, report.string()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("instruction budget exhausted"), std::string::npos) << result;
    EXPECT_EQ(result.find("run failed"), std::string::npos) << result;
    ASSERT_TRUE(std::filesystem::exists(report));
    std::ifstream in(report);
    const std::string json((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_NE(json.find("\"events\":{"), std::string::npos);
    EXPECT_NE(json.find("\"block-exec\":"), std::string::npos);
}

TEST(RunCli, SamplePassThroughRunsAndSavesTheSnapshot)
{
    // The default route is the sample one: a PE positional argument is captured
    // in-process on a Windows host, and the mid-run snapshot lands only when
    // --save-snapshot asks for it.
    const auto dir = sheller_test::temp_path("sheller_run_cli_test");
    std::filesystem::create_directories(dir);
    const auto saved = dir / "passthrough.mid.snap";
    const auto result = run_and_capture(std::format("run \"{}\" -b 1M --save-snapshot \"{}\"",
                                                    SHELLER_SAMPLE_HELLO_PATH, saved.string()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    ASSERT_TRUE(std::filesystem::exists(saved));
    std::ifstream mid(saved, std::ios::binary);
    char magic[8] = {};
    mid.read(magic, sizeof magic);
    const std::string_view magic_view{magic, sizeof magic};
    EXPECT_EQ(magic_view, "SHELLSNP");
}

// The shipped CLI is a host like any other, and until --log-level existed it had no way
// to say so: three environment variables could turn the traces on and the threshold was
// fixed at kWarning, which meant the flags did nothing in the only executable that
// ships. These two runs differ only by the threshold, with the switch on in both - the
// pair that makes the threshold rule documented in docs/cli.md executable rather than
// aspirational.
TEST(RunCli, TracesStayBelowTheDefaultThresholdWithTheSwitchOn)
{
    const auto snapshot = captured_hello_snapshot();
    const auto result = run_and_capture(std::format("run \"{}\" --from-snapshot", snapshot),
                                        "set SHELLER_LOOP_GATE_TRACE=1 && ");
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_EQ(result.find("loop-gate"), std::string::npos)
        << "a kDebug trace reached the CLI at its default threshold";
    // The run really executed, or "no trace" would be a statement about a run that
    // never happened.
    EXPECT_NE(result.find("terminated=1"), std::string::npos) << result;
}

TEST(RunCli, LogLevelDebugBringsTheTracesIntoTheOutput)
{
    const auto snapshot = captured_hello_snapshot();
    const auto result =
        run_and_capture(std::format("run \"{}\" --from-snapshot --log-level debug", snapshot),
                        "set SHELLER_LOOP_GATE_TRACE=1 && ");
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("loop-gate"), std::string::npos)
        << "--log-level debug did not reach the library's records: the facade threshold, "
           "the spdlog level, or the routing between them is not what the option claims";
    // Both halves still work with the channel opened: the run's own summary is the
    // artifact, and it must not move when the diagnostics do.
    EXPECT_NE(result.find("terminated=1"), std::string::npos) << result;
    EXPECT_NE(result.find("syscalls=3"), std::string::npos) << result;
}

#endif

TEST(RunCli, XferStopVetoesTheWallClockMidLeg)
{
    // Portable crafted fixture: the transfer ends a leg the 1ms wall clock was
    // already crossed before, and no leg-boundary clock check runs in between
    // (the probe legs continue ahead of it), so only the finish-time veto keeps
    // this a dump-eligible success. The CLI has to report the stop, exit 0 and
    // leave a dump behind.
    const auto dir = sheller_test::temp_path("sheller_run_cli_xfer_midleg");
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    const auto snapshot = dir / "xfer_delay.snap";
    const auto& bytes = sheller_test::xfer_delay_snapshot_bytes();
    {
        std::ofstream out(snapshot, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(out.good());
    }
    const auto dump = dir / "dump";
    const auto result =
        run_and_capture(std::format("run \"{}\" --from-snapshot --stop xfer=1 --timeout-ms 1 -b 0M "
                                    "--dump \"{}\"",
                                    snapshot.string(), dump.string()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("xfer target reached (xfers=1)"), std::string::npos) << result;
    EXPECT_NE(result.find("terminated=0"), std::string::npos) << result;
    EXPECT_TRUE(std::filesystem::exists(dump / "manifest.txt")) << result;
}

TEST(RunCli, MissingSnapshotExitsNonZero)
{
    const auto result = run_and_capture("run sheller_missing_snapshot.snap");
    EXPECT_NE(exit_code_of(result), "0") << result;
}

TEST(RunCli, LogLevelRejectsAnUnknownName)
{
    // The option takes a set, not a string: a typo has to be a usage error rather than a
    // flag that silently does nothing, which is the failure this whole option exists to
    // stop being.
    const auto quiet = run_and_capture("run sheller_missing_snapshot.snap --log-level debug");
    EXPECT_NE(exit_code_of(quiet), "0") << quiet;
    const auto typo = run_and_capture("run sheller_missing_snapshot.snap --log-level deubg");
    EXPECT_NE(exit_code_of(typo), "0") << typo;
    EXPECT_NE(typo.find("--log-level"), std::string::npos) << typo;
}

TEST(RunCli, EventLevelRejectsAnUnknownName)
{
    // The option takes a set, not a string: a typo is a usage error, never a
    // flag that silently runs the other level. The pair below differs only in
    // the value, and only the rejected one names the option in its error - the
    // run failure of a missing snapshot does not.
    const auto accepted = run_and_capture("run sheller_missing_snapshot.snap --event-level full");
    EXPECT_NE(exit_code_of(accepted), "0") << accepted;
    EXPECT_EQ(accepted.find("--event-level"), std::string::npos) << accepted;

    const auto typo = run_and_capture("run sheller_missing_snapshot.snap --event-level verbose");
    EXPECT_NE(exit_code_of(typo), "0") << typo;
    EXPECT_NE(typo.find("--event-level"), std::string::npos) << typo;
}

TEST(RunCli, BudgetRequiresIntegerMillions)
{
    // The unit is part of the value: bare integers, decimals and a lowercase
    // suffix are usage errors, never silently reinterpreted counts.
    for (const std::string_view spec : {"200000", "5.5M", "5m"}) {
        const auto rejected =
            run_and_capture(std::format("run sheller_missing_snapshot.snap --budget {}", spec));
        EXPECT_NE(exit_code_of(rejected), "0") << rejected;
        EXPECT_NE(rejected.find("integer number of millions"), std::string::npos) << rejected;
    }
}

TEST(RunCli, TimelineOptionIsGone)
{
    // The companion-file family retired with its option: the spelling is an
    // unknown argument now, which is the refusal the spec asks for - no
    // hand-written rejection to keep in sync.
    const auto result = run_and_capture("run sheller_missing_snapshot.snap --timeline t.json");
    EXPECT_NE(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("--timeline"), std::string::npos) << result;
}

// --stop goal family: the parse-level faces are portable (a rejected goal
// never reaches a run), the stop faces ride the portable crafted delay
// fixture like the xfer tests above.
TEST(RunCli, StopGoalTypoIsAUsageError)
{
    const auto result = run_and_capture("run sheller_missing_snapshot.snap --stop eps");
    EXPECT_NE(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("expected a stop goal: xfer=<n>, esp or esp+xfer"), std::string::npos)
        << result;
}

TEST(RunCli, StopXferNonIntegerIsAUsageError)
{
    for (const std::string_view goal : {"xfer=", "xfer=abc", "xfer=1x", "xfer=-1"}) {
        const auto result =
            run_and_capture(std::format("run sheller_missing_snapshot.snap --stop {}", goal));
        EXPECT_NE(exit_code_of(result), "0") << result;
        EXPECT_NE(result.find("expected a stop goal: xfer=<n>, esp or esp+xfer"), std::string::npos)
            << result;
    }
}

TEST(RunCli, XferOptionIsGone)
{
    // The sugar spelling retired with the stop-target namespace: the option is
    // an unknown argument now, which is the refusal the spec asks for - the
    // same face the retired --timeline spelling gets.
    const auto result = run_and_capture("run sheller_missing_snapshot.snap --xfer 1");
    EXPECT_NE(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("--xfer"), std::string::npos) << result;
}

TEST(RunCli, StopGivenTwiceIsAMutexError)
{
    const auto result =
        run_and_capture("run sheller_missing_snapshot.snap --stop esp --stop xfer=1");
    EXPECT_NE(exit_code_of(result), "0") << result;
}

TEST(RunCli, HelpNamesTheThreeStopGoalsWithoutTheRetiredSpelling)
{
    // CLI11 wraps help at the column limit, so the goals are matched against
    // a whitespace-collapsed rendering: the phrases must survive the wrap.
    const auto collapsed = [](std::string text) {
        auto write = text.begin();
        for (auto read = text.begin(); read != text.end(); ++read) {
            if (std::isspace(static_cast<unsigned char>(*read)) != 0) {
                if (write != text.begin() && *(write - 1) != ' ') {
                    *write++ = ' ';
                }
            } else {
                *write++ = *read;
            }
        }
        text.erase(write, text.end());
        return text;
    };
    const auto result = collapsed(run_and_capture("run --help"));
    EXPECT_NE(result.find("xfer=<n> (0 = off), esp (stop at the confirmed entry-stack "
                          "restore) or esp+xfer (arm on it, stop at the next transfer)"),
              std::string::npos)
        << result;
    EXPECT_EQ(result.find("--xfer"), std::string::npos) << result;
}

TEST(RunCli, StopXferZeroLeavesTheRunAlone)
{
    // 0 = off: no stop line, the run closes on its own terms (the crafted
    // corpus reaches its transfer; off means it does not stop there) - the
    // same close-out a no-goal run has, which is what "off" means.
    namespace fs = std::filesystem;
    const auto dir = sheller_test::temp_path("sheller_run_cli_stop_zero");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto snapshot = dir / "zero.snap";
    const auto& bytes = sheller_test::xfer_delay_snapshot_bytes();
    {
        std::ofstream out(snapshot, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(out.good());
    }
    const auto via_off = run_and_capture(std::format(
        "run \"{}\" --from-snapshot --stop xfer=0 -b 0M --timeout-ms 200", snapshot.string()));
    const auto no_goal = run_and_capture(
        std::format("run \"{}\" --from-snapshot -b 0M --timeout-ms 200", snapshot.string()));
    EXPECT_EQ(exit_code_of(via_off), exit_code_of(no_goal)) << via_off << "\n---\n" << no_goal;
    EXPECT_EQ(via_off.find("xfer target"), std::string::npos) << via_off;
}

// The esp stop-goal scenarios on the run face. The crafted esp fixtures are
// portable, so every scenario holds on both platforms.
TEST(RunCli, EspHitStopsWithDumpAndExitZero)
{
    namespace fs = std::filesystem;
    const auto dir = sheller_test::temp_path("sheller_run_cli_esp_hit");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto snapshot = dir / "esp_hit.snap";
    {
        const auto& bytes = craft_esp_snapshot(esp_hit_code());
        std::ofstream out(snapshot, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(out.good());
    }
    const auto dump = dir / "dump";
    const auto report = dir / "esp_hit.report.json";
    const auto result =
        run_and_capture(std::format("run \"{}\" --from-snapshot --stop esp --dump \"{}\" "
                                    "--report \"{}\"",
                                    snapshot.string(), dump.string(), report.string()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("esp target reached (stack restore confirmed)"), std::string::npos)
        << result;
    EXPECT_NE(result.find("terminated=0"), std::string::npos) << result;
    EXPECT_NE(result.find("syscalls=0"), std::string::npos) << result;
    EXPECT_TRUE(fs::exists(dump / "manifest.txt")) << result;
    // The confirmation emits the passive event before the stop takes
    // the run down - exactly one stack-restore in counts and detail.
    const auto json = read_file(report);
    EXPECT_NE(json.find("\"stack-restore\":1"), std::string::npos) << json;
    EXPECT_EQ(occurrences(json, "\"type\":\"stack-restore\""), 1U) << json;
}

TEST(RunCli, EspArmStopsAtTheNextXferWithTheEndpoint)
{
    namespace fs = std::filesystem;
    const auto dir = sheller_test::temp_path("sheller_run_cli_esp_arm");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto snapshot = dir / "esp_arm.snap";
    {
        const auto& bytes = craft_esp_arm_snapshot();
        std::ofstream out(snapshot, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(out.good());
    }
    const auto report = dir / "esp_arm.report.json";
    const auto result =
        run_and_capture(std::format("run \"{}\" --from-snapshot --stop esp+xfer --report \"{}\"",
                                    snapshot.string(), report.string()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    // The arm form's stop is the xfer machinery's, so the stop line names
    // both facts and the report carries the transfer with its landing
    // endpoint (module!section) - the xfer stop face.
    EXPECT_NE(result.find("esp target armed; xfer target reached (xfers=1)"), std::string::npos)
        << result;
    EXPECT_NE(result.find("terminated=0"), std::string::npos) << result;
    const auto json = read_file(report);
    EXPECT_NE(json.find("\"type\":\"xfer\""), std::string::npos) << json;
    EXPECT_NE(json.find("\"to\":"), std::string::npos) << json;
}

TEST(RunCli, StackPivotIsNotARestore)
{
    // The pop-rsp shape: the completion slot's pop writes RSP itself (a
    // stack pivot). No stop, no stack-restore event - the run closes on its
    // own terminate and the esp goal reports its miss.
    namespace fs = std::filesystem;
    const auto dir = sheller_test::temp_path("sheller_run_cli_esp_poprsp");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto snapshot = dir / "esp_poprsp.snap";
    {
        const auto& bytes = craft_esp_snapshot(esp_pop_rsp_code());
        std::ofstream out(snapshot, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(out.good());
    }
    const auto report = dir / "esp_poprsp.report.json";
    const auto result =
        run_and_capture(std::format("run \"{}\" --from-snapshot --stop esp --report \"{}\"",
                                    snapshot.string(), report.string()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("esp target not reached"), std::string::npos) << result;
    EXPECT_EQ(result.find("esp target reached"), std::string::npos) << result;
    EXPECT_NE(result.find("terminated=1"), std::string::npos) << result;
    EXPECT_NE(result.find("exit=0x1234"), std::string::npos) << result;
    const auto json = read_file(report);
    EXPECT_EQ(json.find("\"stack-restore\""), std::string::npos) << json;
}

TEST(RunCli, AntiDebugWindowReadDoesNotStop)
{
    namespace fs = std::filesystem;
    const auto dir = sheller_test::temp_path("sheller_run_cli_esp_antidebug");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto snapshot = dir / "esp_antidebug.snap";
    {
        const auto& bytes = craft_esp_snapshot(esp_anti_debug_code());
        std::ofstream out(snapshot, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(out.good());
    }
    const auto result =
        run_and_capture(std::format("run \"{}\" --from-snapshot --stop esp", snapshot.string()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_EQ(result.find("esp target reached"), std::string::npos) << result;
    // The miss prints its hint and the run closes on its own terms.
    EXPECT_NE(result.find("esp target not reached"), std::string::npos) << result;
    EXPECT_NE(result.find("terminated=1"), std::string::npos) << result;
    EXPECT_NE(result.find("exit=0x1234"), std::string::npos) << result;
}

TEST(RunCli, EntryWithoutPushesIsASilentEspMiss)
{
    // The instoll shape (entry opens with something else than a push): the
    // monitor is not established and the run closes on the miss path.
    namespace fs = std::filesystem;
    const auto dir = sheller_test::temp_path("sheller_run_cli_esp_nopush");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto snapshot = dir / "esp_nopush.snap";
    {
        const auto& bytes = sheller_test::xfer_delay_snapshot_bytes();
        std::ofstream out(snapshot, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(out.good());
    }
    const auto result =
        run_and_capture(std::format("run \"{}\" --from-snapshot --stop esp", snapshot.string()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("esp target not reached"), std::string::npos) << result;
    EXPECT_NE(result.find("terminated=1"), std::string::npos) << result;
}

TEST(RunCli, RelocatedStackIsASilentEspMiss)
{
    // The VM shape: the window arms (the entry pushes once) and is never
    // read - the run closes on the miss path.
    namespace fs = std::filesystem;
    const auto dir = sheller_test::temp_path("sheller_run_cli_esp_reloc");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto snapshot = dir / "esp_reloc.snap";
    {
        const auto& bytes = craft_esp_snapshot(esp_relocated_stack_code());
        std::ofstream out(snapshot, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(out.good());
    }
    const auto result =
        run_and_capture(std::format("run \"{}\" --from-snapshot --stop esp", snapshot.string()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("esp target not reached"), std::string::npos) << result;
    EXPECT_NE(result.find("terminated=1"), std::string::npos) << result;
    EXPECT_NE(result.find("exit=0x1234"), std::string::npos) << result;
}

TEST(RunCli, PassiveStackRestoreFiresWithoutAnyGoal)
{
    // The observation is on by default. The hit corpus with no stop
    // option runs to its own terminate and still carries exactly one
    // stack-restore event - no esp stop line, no miss hint (no goal was
    // requested), exit code the run's own.
    namespace fs = std::filesystem;
    const auto dir = sheller_test::temp_path("sheller_run_cli_esp_passive");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto snapshot = dir / "esp_passive.snap";
    {
        const auto& bytes = craft_esp_snapshot(esp_hit_code());
        std::ofstream out(snapshot, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(out.good());
    }
    const auto report = dir / "esp_passive.report.json";
    const auto result = run_and_capture(std::format("run \"{}\" --from-snapshot --report \"{}\"",
                                                    snapshot.string(), report.string()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_EQ(result.find("esp target"), std::string::npos) << result;
    EXPECT_NE(result.find("terminated=1"), std::string::npos) << result;
    EXPECT_NE(result.find("exit=0x1234"), std::string::npos) << result;
    const auto json = read_file(report);
    EXPECT_NE(json.find("\"stack-restore\":1"), std::string::npos) << json;
    EXPECT_EQ(occurrences(json, "\"type\":\"stack-restore\""), 1U) << json;
}

TEST(RunCli, MissedEspGoalAddsNoStreamBytes)
{
    // The zero-byte miss: with the monitor armed but the confirmation never
    // firing (the anti-debug corpus), requesting --stop esp and requesting
    // nothing produce byte-identical reports.
    namespace fs = std::filesystem;
    const auto dir = sheller_test::temp_path("sheller_run_cli_esp_zerobyte");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto snapshot = dir / "esp_zero.snap";
    {
        const auto& bytes = craft_esp_snapshot(esp_anti_debug_code());
        std::ofstream out(snapshot, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(out.good());
    }
    const auto plain = dir / "plain.report.json";
    const auto goal = dir / "goal.report.json";
    const auto run_plain = run_and_capture(std::format("run \"{}\" --from-snapshot --report \"{}\"",
                                                       snapshot.string(), plain.string()));
    EXPECT_EQ(exit_code_of(run_plain), "0") << run_plain;
    const auto run_goal = run_and_capture(std::format(
        "run \"{}\" --from-snapshot --stop esp --report \"{}\"", snapshot.string(), goal.string()));
    EXPECT_EQ(exit_code_of(run_goal), "0") << run_goal;
    EXPECT_EQ(read_file(plain), read_file(goal));
}

TEST(RunCli, EspStopVetoesTheWallClockMidLeg)
{
    // The esp analogue of the xfer mid-leg veto: the delay loop's leg is
    // already past the 1ms wall clock when the restore confirms inside it,
    // and only the finish-time veto keeps this a dump-eligible success
    // instead of a timeout.
    namespace fs = std::filesystem;
    const auto dir = sheller_test::temp_path("sheller_run_cli_esp_midleg");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto snapshot = dir / "esp_probe_guard.snap";
    {
        const auto& bytes = craft_esp_snapshot(esp_probe_guard_code());
        std::ofstream out(snapshot, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(out.good());
    }
    const auto dump = dir / "dump";
    const auto result =
        run_and_capture(std::format("run \"{}\" --from-snapshot --stop esp --timeout-ms 1 "
                                    "-b 0M --dump \"{}\"",
                                    snapshot.string(), dump.string()));
    EXPECT_EQ(exit_code_of(result), "0") << result;
    EXPECT_NE(result.find("esp target reached (stack restore confirmed)"), std::string::npos)
        << result;
    EXPECT_NE(result.find("terminated=0"), std::string::npos) << result;
    EXPECT_EQ(result.find("timeout"), std::string::npos) << result;
    EXPECT_TRUE(fs::exists(dump / "manifest.txt")) << result;
}

} // namespace

// Directory-mode CLI: the options
// ride run (the spec's mapping-input scenario asserts the success face in
// the engine-level tests); a bad --system-modules path exits non-zero.
TEST(CliRun, SystemModulesBadPathExitsNonZero)
{
    const std::string cli = SHELLER_CLI_FILE_NAME;
    const std::string cmd = cli + " run " + SHELLER_SAMPLE_PACKED_PATH + " --system-modules " +
                            SHELLER_SAMPLE_PACKED_PATH + " -b 0M";
    std::array<char, 256> buffer{};
    const auto pipe = _popen(cmd.c_str(), "r");
    ASSERT_NE(pipe, nullptr);
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
    }
    const int status = _pclose(pipe);
    EXPECT_NE(status, 0);
}
