// Engine trace routing: an env-gated site delivers a log record carrying its marker,
// the same corpus with the environment untouched delivers no such record, and with the
// environment set but no host sink installed the library writes to neither of the
// host's standard streams.
//
// Three runs of one binary, decided by argv, because the site switches cache their read
// in function-local statics (src/engine/diag_trace.h) and a process gets exactly one
// answer per variable. tests/CMakeLists.txt registers engine_trace (switches set, sink
// installed), engine_trace_quiet (neither) and engine_trace_nosink (switches set, no
// sink); each case asserts the half that fits its run, so none of them is a skip.
//
// What each corpus reaches, measured rather than assumed:
//   spin (portable)         [loop-gate] run summary
//   seh sample (Windows)    [seh-diag], [seh-step], [seh-cb]
//   fastfail sample         the unhandled-crash line, at kWarning, ungated
// The [file] site has no CI corpus on either platform, and that is a measurement, not
// an oversight: the captured samples open their files before the snapshot point, so a
// replay never re-issues the create (the hello sample was tried and delivered no [file]
// record), and off Windows the packed corpus dies in payload init before the fopen the
// loader route would trace. The site is still watched by the standard-stream gate on
// both platforms, and its rendering is covered by tests/engine_diag_test.cpp; what is
// missing here is an end-to-end record for that one marker.
//
// The quiet run's census case names the records that are allowed to arrive unasked.

// getenv and _putenv_s are the point of this binary's main(), and on Windows both
// carry deprecation notes; the defines must precede every include (gtest pulls the
// standard headers first).
#ifdef _WIN32
#define _CRT_NONSTDC_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "host_stream_capture.h"
#include "log_detail.h"
#include "snapshot_fixture.h"
#include "test_temp.hpp"

#include <sheller/log.h>
#include <sheller/syscallrun.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#ifdef _WIN32
#include "capture_detail.h"

#include <sheller/capture.h>

#include <filesystem>
#endif

namespace {

struct Record {
    sheller::log::level level{};
    std::string text{};
};

std::vector<Record>& records()
{
    // Heap-anchored, as in log_test.cpp: the sink closure outlives the test body, and
    // a function-local static would be destroyed before the log state it feeds.
    static auto* const held = new std::vector<Record>();
    return *held;
}

void install_sink()
{
    sheller::log::detail::set_sink_impl(
        [](const sheller::log::level level, const std::string_view message) {
            records().push_back({level, std::string{message}});
        },
        sheller::log::level::kDebug);
    records().clear();
}

// Read fresh, on the test's side of the boundary: which mode this process was started
// in is the thing being conditioned on, and the library's cached switch is the subject.
bool traces_enabled()
{
    return std::getenv("SHELLER_SEH_TRACE") != nullptr ||
           std::getenv("SHELLER_LOOP_GATE_TRACE") != nullptr ||
           std::getenv("SHELLER_FILE_TRACE") != nullptr;
}

std::vector<Record> with_marker(const std::string& marker)
{
    std::vector<Record> hits;
    for (const auto& record : records()) {
        if (record.text.find(marker) != std::string::npos) {
            hits.push_back(record);
        }
    }
    return hits;
}

// The pair every site is asserted with: the marker must arrive when its switch is set,
// at kDebug, and must not arrive when it is not. The level is part of the contract
// rather than an incidental - the traces sit below the threshold a normal host installs
// for itself, which is what makes them opt-in twice over.
void expect_site(const std::string& marker, const std::string& context)
{
    const auto hits = with_marker(marker);
    if (traces_enabled()) {
        ASSERT_FALSE(hits.empty()) << context << ": no record carrying " << marker;
        for (const auto& hit : hits) {
            EXPECT_EQ(hit.level, sheller::log::level::kDebug)
                << context << ": " << marker << " arrived at a level above kDebug";
        }
        return;
    }
    EXPECT_TRUE(hits.empty()) << context << ": " << hits.size() << " record(s) of " << marker
                              << " delivered with no switch set, first = [" << hits.front().text
                              << "]";
}

#ifdef _WIN32
std::filesystem::path captured(const char* sample_path, const std::string& name)
{
    const auto dir = sheller_test::temp_path("sheller_engine_trace_test");
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    const auto snapshot = dir / name;
    const auto run = sheller::capture::detail::run_impl(
        sheller::capture::Options{.sample_path = sample_path, .output_path = snapshot});
    EXPECT_EQ(run.status, sheller::capture::Status::kOk) << run.detail;
    return snapshot;
}
#endif

// ---- the portable site: loop-gate ------------------------------------------------

sheller::engine::SyscallRunOptions budget_options()
{
    sheller::engine::SyscallRunOptions options;
    options.max_instructions = 50000;
    return options;
}

TEST(EngineTrace, LoopGateRunSummary)
{
    install_sink();
    // jmp -2: the guest burns its budget inside one block, and the loop-gate summary
    // is written at the finish of every run whose switch is on. How the run stops is
    // not the claim, so its result is not asserted here.
    static_cast<void>(sheller::engine::run_snapshot_syscalls(
        sheller_test::craft_snapshot({0xEB, 0xFE}), budget_options()));
    expect_site("[loop-gate] run summary:", "spin run");
}

TEST(EngineTrace, QuietRunCarriesOnlyTheUngatedRecords)
{
    // The census the per-site assertions cannot make: with no switch set, the records
    // that reach the sink are exactly the ones the contract keeps ungated - the run
    // start line and, for a run that dies unhandled, the crash line. Anything else in
    // here is a diagnostic that arrived without being asked for.
    if (traces_enabled()) {
        GTEST_SKIP() << "this case is the quiet run's; the switch-on run asserts presence";
    }
    install_sink();
    static_cast<void>(sheller::engine::run_snapshot_syscalls(
        sheller_test::craft_snapshot({0xEB, 0xFE}), budget_options()));
    for (const auto& record : records()) {
        const bool run_start = record.text.rfind("engine run start:", 0) == 0;
        const bool crash = record.text.find("unhandled crash") != std::string::npos;
        EXPECT_TRUE(run_start || crash) << "ungated record: [" << record.text << "]";
    }
    // And the run-start line really is there, so the loop above is not vacuous.
    EXPECT_FALSE(with_marker("engine run start:").empty());
}

// ---- the one diagnostic that is not a trace: the unhandled crash line --------------
//
// The corpus has to end in an unhandled death, which the captured __fastfail sample
// does. Both runs of the crash case must produce exactly one record, because the line
// has no switch - it is the operator's, not a trace.

#ifdef _WIN32
void expect_one_crash_record()
{
    const auto hits = with_marker("unhandled crash");
    ASSERT_EQ(hits.size(), 1U) << "total records: " << records().size();
    EXPECT_EQ(hits.front().level, sheller::log::level::kWarning);
    // kWarning is what keeps the line reachable through the CLI's own sink, whose
    // threshold is kWarning - and the register state rides in the text, which is the
    // point of the record.
    EXPECT_NE(hits.front().text.find("rip=0x"), std::string::npos);
}

TEST(EngineTrace, UnhandledCrashLineIsWarningLevel)
{
    install_sink();
    const auto snapshot = captured(SHELLER_SAMPLE_SEH_FASTFAIL_PATH, "fastfail_trace.snap");
    sheller::engine::SyscallRunOptions options;
    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
    ASSERT_FALSE(stats.has_value());
    EXPECT_EQ(stats.error().error, sheller::engine::SyscallRunError::kUnhandledException);
    expect_one_crash_record();
}

TEST(EngineTrace, SehDispatchSites)
{
    install_sink();
    const auto snapshot = captured(SHELLER_SAMPLE_SEH_PATH, "seh_trace.snap");
    sheller::engine::SyscallRunOptions options;
    options.write_sink = [](const std::uint8_t*, const std::size_t) {};
    static_cast<void>(sheller::engine::run_snapshot_syscalls(snapshot, options));
    expect_site("[seh-diag]", "seh sample run");
    expect_site("[seh-step]", "seh sample run");
    expect_site("[seh-cb]", "seh sample run");
}

#endif

// ---- the third combination: the switches set, nobody listening ---------------------

bool no_sink_mode = false;     // decided by argv in main(), before the first case
bool no_sink_case_ran = false; // what main() checks, so a filter cannot empty this run

// Environment on and no host sink installed: the library stays silent on both of the
// host's standard streams. This is the combination that matters - the environment is
// the face of a library that an attacker can reach - and no other run of this binary
// puts those two conditions together, because every case above calls install_sink()
// before it runs anything. It has to be its own process: the switches
// are read once per process, and the second half of the case below installs a sink to
// prove the sites were live.
//
// What it can catch, stated exactly: a site that writes the host's stream itself,
// bypassing the log facade, which is the shape the reroute removed. It cannot catch a
// fallback added inside log::write(), because with no sink every call site short-circuits
// on would_log() before write() is reached - measured, that mutant was green on Linux and
// red on Windows, and the Windows half was the unhandled-crash line, the one record this
// tree emits without asking first.
TEST(EngineTraceNoSink, EnvironmentAloneReachesNeitherHostStream)
{
    no_sink_case_ran = true;
    ASSERT_TRUE(no_sink_mode) << "this case belongs to the --no-sink run only";
    ASSERT_TRUE(traces_enabled()) << "--no-sink only means something next to --traces-on";

    // Emptied explicitly rather than left at whatever the process started with: the
    // claim is about a host that is not listening, and it must not be satisfied
    // because no case before this one happened to install a sink. The threshold goes
    // to kDebug, the most permissive the facade offers, so what stays silent is the
    // missing sink rather than a record that was filtered by level on the way.
    sheller::log::detail::set_sink_impl({}, sheller::log::level::kDebug);

    std::string host_stdout;
    std::string host_stderr;
    {
        sheller_test::StandardStreamCapture capture("sheller_engine_trace_nosink");
        // The gated site: the switch is set, so the engine formats the loop-gate
        // summary and hands it to the log facade. There is nobody to hand it to.
        static_cast<void>(sheller::engine::run_snapshot_syscalls(
            sheller_test::craft_snapshot({0xEB, 0xFE}), budget_options()));
#ifdef _WIN32
        // And the ungated one. The crash line is kWarning and arrives with no switch
        // at all, which makes it the record most likely to end up on a console - the
        // fastfail corpus is here to put that to the test.
        const auto snapshot = captured(SHELLER_SAMPLE_SEH_FASTFAIL_PATH, "fastfail_nosink.snap");
        sheller::engine::SyscallRunOptions crash_options;
        const auto crash = sheller::engine::run_snapshot_syscalls(snapshot, crash_options);
        ASSERT_FALSE(crash.has_value());
        EXPECT_EQ(crash.error().error, sheller::engine::SyscallRunError::kUnhandledException);
#endif
        host_stdout = capture.stdout_text();
        host_stderr = capture.stderr_text();
    }
    EXPECT_EQ(host_stdout, std::string{}) << "the library wrote to stdout with no sink";
    EXPECT_EQ(host_stderr, std::string{}) << "the library wrote to stderr with no sink";

    // The other half, and the half that keeps the two assertions above from being a
    // statement about runs that never reached a site: the same corpora, in this same
    // process, with a listener installed, do deliver. Only the sink changed.
    install_sink();
    static_cast<void>(sheller::engine::run_snapshot_syscalls(
        sheller_test::craft_snapshot({0xEB, 0xFE}), budget_options()));
    EXPECT_FALSE(with_marker("[loop-gate] run summary:").empty())
        << "the loop-gate site delivered nothing even with a sink: the zero-byte "
           "assertion above proved nothing about it";
#ifdef _WIN32
    install_sink(); // clears the record list, so the count below is this run's
    const auto crash_snapshot =
        captured(SHELLER_SAMPLE_SEH_FASTFAIL_PATH, "fastfail_nosink_listening.snap");
    sheller::engine::SyscallRunOptions crash_options;
    static_cast<void>(sheller::engine::run_snapshot_syscalls(crash_snapshot, crash_options));
    const auto hits = with_marker("unhandled crash");
    EXPECT_EQ(hits.size(), 1U) << "the ungated crash line did not reach an installed sink either";
    if (!hits.empty()) {
        EXPECT_EQ(hits.front().level, sheller::log::level::kWarning);
    }
#endif
}

} // namespace

int main(int argc, char** argv)
{
    // Decided here, before the first record can cache a switch: the mode is which
    // process this is, not which case is running.
    bool on = false;
    bool nosink = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string_view{argv[i]} == "--traces-on") {
            on = true;
        }
        if (std::string_view{argv[i]} == "--no-sink") {
            nosink = true;
        }
    }
    if (on) {
        for (const char* name :
             {"SHELLER_SEH_TRACE", "SHELLER_LOOP_GATE_TRACE", "SHELLER_FILE_TRACE"}) {
#ifdef _WIN32
            _putenv_s(name, "1");
#else
            setenv(name, "1", 1);
#endif
        }
    }
    no_sink_mode = nosink;
    ::testing::InitGoogleTest(&argc, argv);
    const int result = RUN_ALL_TESTS();
    if (nosink && !no_sink_case_ran) {
        // The entry exists to run one case. If its filter stops matching - a rename, a
        // typo in tests/CMakeLists.txt - gtest reports a green run over nothing, so the
        // mode says what it required and fails when that requirement was not met.
        std::fprintf(stderr, "engine_trace --no-sink: no case in EngineTraceNoSink ran; the entry "
                             "is configured to execute one\n");
        return 1;
    }
    return result;
}
