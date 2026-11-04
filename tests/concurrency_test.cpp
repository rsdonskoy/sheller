// Static-side concurrency: several threads inside the library at once, through the
// static core. The shared-library side of the same claim is a case in
// tests/shared_api_test.cpp, and the wrapper-name race that used to live on this path
// is covered by tests/wrapper_pe_e2e_test.cpp.

#include "log_detail.h"
#include "snapshot_fixture.h"
#include "test_temp.hpp"
#include "wiring.h"

#include <sheller/analysis.h>
#include <sheller/log.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

namespace facade = sheller::api::detail;
namespace fs = std::filesystem;

constexpr int kThreads = 4;

// One record's worth of text, built from the fields a caller can name. Written for
// the concurrency digest below, where the question is whether two runs produced the
// same artifact rather than the same number of artifacts.
std::string param_row(const sheller::SemanticParam& param)
{
    std::ostringstream out;
    out << param.name << '/' << static_cast<int>(param.kind) << '/' << param.truncated << '/'
        << param.integer << '/' << param.text << "/bytes:";
    for (const auto byte : param.bytes) {
        out << static_cast<int>(byte) << '.';
    }
    return out.str();
}

std::string event_row(const sheller::SemanticEvent& event)
{
    std::ostringstream out;
    out << static_cast<int>(event.type) << '/' << event.seq << '/' << event.wire_seq << '/'
        << event.tid << '/' << event.pc << '/' << static_cast<int>(event.flags) << '/'
        << event.truncated << '/' << event.syscall_number << '/' << event.syscall_name << '/'
        << event.api_name << '/' << event.api_module << '/' << event.status << '/' << event.success
        << '/' << event.caller_retaddr << '/' << event.retval << '/' << event.from_module << '!'
        << event.from_section << '/' << event.to_module << '/' << event.to_section << '/'
        << event.exception_code << '/' << event.new_tid << '/' << event.start_routine << '/'
        << event.address << '/' << event.access_size << '/' << event.value << '/' << event.aux
        << '/' << event.subtype << '/' << event.judgment_api << "/params:";
    for (const auto& param : event.params) {
        out << '[' << param_row(param) << ']';
    }
    return out.str();
}

std::string stub_row(const sheller::StubCall& stub)
{
    std::ostringstream out;
    out << stub.module << '/' << stub.module_name << '/' << stub.name << '/' << stub.count;
    return out.str();
}

// The name tables the timeline tier's indexes resolve through. They are part of the
// artifact a caller reads, so two runs that agree on the wire bytes but disagree here
// have not produced the same artifact.
std::string names_row(const sheller::TimelineNameTable& names)
{
    std::ostringstream out;
    out << "modules:";
    for (const auto& module : names.modules) {
        out << '[' << module << ']';
    }
    out << "|sections:";
    for (const auto& per_module : names.sections) {
        out << '[';
        for (const auto& section : per_module) {
            out << section << '.';
        }
        out << ']';
    }
    out << "|syscalls:";
    for (const auto& [number, mnemonic] : names.syscalls) {
        out << '[' << number << '=' << mnemonic << ']';
    }
    out << "|apicall_params:";
    for (const auto& [api, params] : names.apicall_params) {
        out << '[' << api << '=';
        for (const auto& param : params) {
            out << param << '.';
        }
        out << ']';
    }
    out << "|module_ranges:";
    for (const auto& [base, size] : names.module_ranges) {
        out << '[' << base << '-' << size << ']';
    }
    out << "|sample_image_range:" << names.sample_image_range.first << '-'
        << names.sample_image_range.second;
    return out.str();
}

// The observable half of an analysis, as one byte string: the statistics, the exact
// per-type counts, the loss counters, the timeline tier's own wire bytes, and the
// *values* of every record the caller can read out - semantic events field by field,
// signals, OEP candidate addresses, stub-call rows and the name tables the wire indexes
// resolve through. Two digests being equal says the two runs produced the same
// artifacts; counting alone would let four threads agree on how many OEP candidates
// they found while each found different ones, and for an AV host the OEP is the
// artifact. A failure below is a real divergence, not a padding difference.
std::string digest(const sheller::AnalysisArtifacts& artifacts)
{
    std::ostringstream out;
    out << (artifacts.instrumented ? 'I' : 'i') << '|' << artifacts.note << '|';
    if (artifacts.run_stats.has_value()) {
        const auto& stats = *artifacts.run_stats;
        out << 'Y' << stats.terminated << ',' << stats.exit_code << ',' << stats.blocks << ','
            << stats.syscalls << ',' << stats.rejects << ',' << stats.exceptions;
    } else {
        out << 'N';
    }
    out << '|';
    for (const auto count : artifacts.event_counts) {
        out << count << ' ';
    }
    out << '|';
    out << artifacts.semantic_events.size() << '/' << artifacts.semantic_dropped << '/'
        << artifacts.oep_candidates.size() << '/' << artifacts.stub_calls.size() << '|'
        << artifacts.timeline_dropped << '/' << artifacts.timeline_truncated << "|tlv:";
    out.write(reinterpret_cast<const char*>(artifacts.timeline_tlv.data()),
              static_cast<std::streamsize>(artifacts.timeline_tlv.size()));
    out << "|events:";
    for (const auto& event : artifacts.semantic_events) {
        out << '[' << event_row(event) << ']';
    }
    out << "|oep:";
    for (const auto candidate : artifacts.oep_candidates) {
        out << candidate << ',';
    }
    out << "|stubs:";
    for (const auto& stub : artifacts.stub_calls) {
        out << '[' << stub_row(stub) << ']';
    }
    out << "|names:" << names_row(artifacts.timeline_names);
    return out.str();
}

sheller::AnalysisOptions timed_options()
{
    sheller::AnalysisOptions options;
    options.timeline = true; // the wire tier is the byte-level part of the artifact
    return options;
}

fs::path worker_dir(const std::string& tag, const int index)
{
    const auto dir =
        sheller_test::temp_path("sheller_concurrency_test") / (tag + std::to_string(index));
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
}

std::string file_bytes(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

TEST(FacadeConcurrency, AnalyzeFromFourThreadsMatchesTheSingleThreadBaseline)
{
    // One deterministic snapshot bytes, shared read-only by every thread: the engine
    // restores its own state per call, so the question is whether anything leaked
    // between the runs.
    const auto& bytes = sheller_test::two_write_snapshot_bytes();
    const auto options = timed_options();
    const auto baseline = facade::analyze_bytes_impl(bytes, options);
    ASSERT_TRUE(baseline.has_value()) << baseline.error().message;
    const auto want = digest(*baseline);
    // A non-empty timeline is what makes the byte comparison mean something; an empty
    // artifact would let any two runs "agree".
    ASSERT_FALSE(baseline->timeline_tlv.empty());

    std::vector<std::string> got(kThreads);
    // int, not bool: a vector<bool> packs its elements into one word, and four
    // threads writing neighbouring flags is a data race in the fixture (found by
    // the linux-tsan run, not by inspection).
    std::vector<int> ok(kThreads, 0);
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        workers.emplace_back([&, i] {
            const auto result = facade::analyze_bytes_impl(bytes, options);
            ok[i] = result.has_value() ? 1 : 0;
            if (result.has_value()) {
                got[i] = digest(*result);
            }
        });
    }
    for (auto& worker : workers) {
        worker.join();
    }
    for (int i = 0; i < kThreads; ++i) {
        EXPECT_TRUE(ok[i]) << "thread " << i << " failed";
        EXPECT_EQ(got[i], want) << "thread " << i << " diverged from the single-thread baseline";
    }
}

TEST(FacadeConcurrency, UnpackFromFourThreadsGetsDistinctWorkDirs)
{
    // Leaving work_dir empty asks the library to name a directory of its own. Four
    // concurrent calls must not land on one name, and each has to produce its image.
    std::vector<std::string> work_dirs(kThreads);
    std::vector<std::string> errors(kThreads);
    std::vector<int> ok(kThreads, 0);
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        workers.emplace_back([&, i] {
            const auto dir = worker_dir("unpack_", i);
            sheller::UnpackOptions options;
            options.output = dir / "packed.unp";
            options.synthetic_module_dir = SYNTH_MODULE_DIR;
            const auto outcome = facade::unpack_sample_impl(SHELLER_SAMPLE_PACKED_PATH, options);
            if (outcome.failure.has_value()) {
                errors[i] = outcome.failure->message;
                return;
            }
            work_dirs[i] = outcome.work_dir.string();
            std::error_code ec;
            ok[i] = (fs::exists(options.output, ec) && !file_bytes(options.output).empty()) ? 1 : 0;
        });
    }
    for (auto& worker : workers) {
        worker.join();
    }

    std::set<std::string> distinct;
    for (int i = 0; i < kThreads; ++i) {
        EXPECT_TRUE(ok[i]) << "thread " << i << ": " << errors[i];
        if (!work_dirs[i].empty()) {
            distinct.insert(work_dirs[i]);
        }
    }
    EXPECT_EQ(distinct.size(), static_cast<std::size_t>(kThreads))
        << "the generated work directories collided";
}

#ifndef _WIN32
// The byte-level half of the unpack claim, where the route is deterministic. Off
// Windows the sample runs through the loader route over the generated synthetic
// modules, which is a fixed input; on Windows it rides the live capture route, whose
// layout drifts from run to run (which is why the byte judgment there goes through
// frozen snapshots instead).
TEST(FacadeConcurrency, UnpackBytesMatchTheSingleThreadBaseline)
{
    const auto base_dir = worker_dir("unpack_base", 0);
    sheller::UnpackOptions baseline_options;
    baseline_options.output = base_dir / "packed.unp";
    baseline_options.synthetic_module_dir = SYNTH_MODULE_DIR;
    const auto baseline = facade::unpack_sample_impl(SHELLER_SAMPLE_PACKED_PATH, baseline_options);
    ASSERT_FALSE(baseline.failure.has_value()) << baseline.failure->message;
    const auto want = file_bytes(baseline_options.output);
    ASSERT_FALSE(want.empty());

    std::vector<std::string> got(kThreads);
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        workers.emplace_back([&, i] {
            const auto dir = worker_dir("unpack_cmp_", i);
            sheller::UnpackOptions options;
            options.output = dir / "packed.unp";
            options.synthetic_module_dir = SYNTH_MODULE_DIR;
            const auto outcome = facade::unpack_sample_impl(SHELLER_SAMPLE_PACKED_PATH, options);
            if (!outcome.failure.has_value()) {
                got[i] = file_bytes(options.output);
            }
        });
    }
    for (auto& worker : workers) {
        worker.join();
    }
    for (int i = 0; i < kThreads; ++i) {
        EXPECT_EQ(got[i].size(), want.size()) << "thread " << i << " image size";
        EXPECT_TRUE(got[i] == want) << "thread " << i << " image bytes diverged";
    }
}
#endif

// What the comparison above actually compares. The concurrency case is only as strong
// as this function's sensitivity: four threads that agree on how many things they
// found have not necessarily found the same things, and for an AV host the OEP address
// is the artifact. Each pair below has the same sizes everywhere and different contents
// in one place - a digester that read only .size() would call the two halves equal,
// which is precisely the hole this closes. The corpus's own rows are perturbed in place
// as well, so the proof is about the records a real run produces and not only about
// records the test wrote.
TEST(FacadeConcurrency, DigestComparesValuesNotOnlyCounts)
{
    const auto& bytes = sheller_test::two_write_snapshot_bytes();
    const auto baseline = facade::analyze_bytes_impl(bytes, timed_options());
    ASSERT_TRUE(baseline.has_value()) << baseline.error().message;
    const auto want = digest(*baseline);

    // An untouched copy digests identically: without this, the assertions below would
    // pass on a digester that returned something different every time it was called.
    const auto untouched = *baseline;
    EXPECT_EQ(digest(untouched), want);

    { // OEP candidates: two addresses each, one of them different.
        auto left = *baseline;
        auto right = *baseline;
        left.oep_candidates = {0x110000, 0x220000};
        right.oep_candidates = {0x110000, 0x330000};
        ASSERT_EQ(left.oep_candidates.size(), right.oep_candidates.size());
        EXPECT_NE(digest(left), digest(right)) << "OEP candidate values are not in the digest";
    }
    { // Stub-call rows: same count of rows, different call named.
        auto left = *baseline;
        auto right = *baseline;
        const sheller::StubCall row_a{.module = 1, .module_name = "m", .name = "a", .count = 3};
        const sheller::StubCall row_b{.module = 1, .module_name = "m", .name = "b", .count = 3};
        left.stub_calls = {row_a};
        right.stub_calls = {row_b};
        EXPECT_NE(digest(left), digest(right)) << "stub-call names are not in the digest";
        right.stub_calls = {
            sheller::StubCall{.module = 1, .module_name = "m", .name = "a", .count = 4}};
        EXPECT_NE(digest(left), digest(right)) << "stub-call counts are not in the digest";
    }
    { // Judgment events: same type, different site.
        auto left = *baseline;
        auto right = *baseline;
        sheller::SemanticEvent judgment_a{};
        judgment_a.type = sheller::EventTypeId::kDirectSyscall;
        judgment_a.pc = 0x401000;
        auto judgment_b = judgment_a;
        judgment_b.pc = 0x402000;
        left.semantic_events.push_back(judgment_a);
        right.semantic_events.push_back(judgment_b);
        ASSERT_EQ(left.semantic_events.size(), right.semantic_events.size());
        EXPECT_NE(digest(left), digest(right)) << "judgment fields are not in the digest";
    }
    { // The name tables the timeline indexes resolve through.
        auto left = *baseline;
        auto right = *baseline;
        left.timeline_names.modules = {"kernel32.dll"};
        right.timeline_names.modules = {"ntdll.dll"};
        EXPECT_NE(digest(left), digest(right)) << "the timeline name tables are not in the digest";
    }

    // In place, on what this corpus actually produced.
    ASSERT_FALSE(baseline->semantic_events.empty()) << "no semantic event on this corpus";
    {
        auto copy = *baseline;
        copy.semantic_events[0].pc += 1;
        EXPECT_NE(digest(copy), want) << "semantic event fields are not in the digest";
        auto status = *baseline;
        status.semantic_events[0].status += 1;
        EXPECT_NE(digest(status), want) << "semantic status values are not in the digest";
        if (!baseline->semantic_events[0].params.empty()) {
            auto params = *baseline;
            params.semantic_events[0].params[0].integer += 1;
            EXPECT_NE(digest(params), want) << "semantic parameter values are not in the digest";
        }
    }
    ASSERT_FALSE(baseline->timeline_tlv.empty()) << "no timeline wire bytes on this corpus";
    {
        auto copy = *baseline;
        copy.timeline_tlv[0] = static_cast<std::uint8_t>(copy.timeline_tlv[0] ^ 0xFF);
        EXPECT_NE(digest(copy), want) << "the timeline wire bytes are not in the digest";
    }
}

// ---- the thread a record is delivered on -------------------------------------------

// Restores the facade to the state the library starts in (no callback, kWarning). The
// sink closure captures this case's stack, so leaving it installed would hand the next
// case in the binary a dangling callback that only fires if something logs.
class ScopedSink {
  public:
    ScopedSink(sheller::log::sink callback, const sheller::log::level min_level)
    {
        sheller::log::detail::set_sink_impl(std::move(callback), min_level);
    }
    ScopedSink(const ScopedSink&) = delete;
    ScopedSink& operator=(const ScopedSink&) = delete;
    ~ScopedSink()
    {
        sheller::log::detail::set_sink_impl({}, sheller::log::level::kWarning);
    }
};

// The observable half of the decision to hold the log mutex across the callback: the
// host is called on the thread that produced the record. Nothing else in the suite
// says so - grep for a thread identity in a sink came back empty - and "the callback
// runs under the library's lock" is only half of what a host has to know about a
// delivery; who delivers is the other half, and it is what makes reentrancy from the
// callback a deadlock rather than a race.
TEST(LogDeliveryThread, RecordsArriveOnTheThreadThatRan)
{
    struct Collector {
        std::mutex guard;
        std::vector<std::thread::id> deliveries;
    } collector;

    ScopedSink sink(
        [&collector](const sheller::log::level, const std::string_view) {
            const std::scoped_lock lock(collector.guard);
            collector.deliveries.push_back(std::this_thread::get_id());
        },
        sheller::log::level::kDebug);

    const auto& bytes = sheller_test::two_write_snapshot_bytes();
    const auto options = timed_options();
    const auto main_id = std::this_thread::get_id();

    // The single-thread half: a run on the calling thread delivers on that thread, and
    // delivers at all - an empty list would satisfy every "no foreign thread" check
    // below by not having looked.
    static_cast<void>(facade::analyze_bytes_impl(bytes, options));
    ASSERT_FALSE(collector.deliveries.empty())
        << "an analysis delivered nothing to an installed sink; the case proves nothing";
    for (const auto& id : collector.deliveries) {
        EXPECT_EQ(id, main_id) << "a record left the log facade on a foreign thread";
    }

    // The concurrent half: four callers, and every delivery traceable to one of them.
    std::vector<std::thread::id> callers(kThreads);
    std::vector<int> ok(kThreads, 0);
    const auto mark = collector.deliveries.size();
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        workers.emplace_back([&, i] {
            callers[i] = std::this_thread::get_id();
            const auto result = facade::analyze_bytes_impl(bytes, options);
            ok[i] = result.has_value() ? 1 : 0;
        });
    }
    for (auto& worker : workers) {
        worker.join();
    }

    std::set<std::thread::id> allowed{callers.begin(), callers.end()};
    allowed.insert(main_id);
    for (std::size_t i = mark; i < collector.deliveries.size(); ++i) {
        EXPECT_TRUE(allowed.contains(collector.deliveries[i]))
            << "delivery " << i << " came from a thread that called nothing";
    }
    for (int i = 0; i < kThreads; ++i) {
        EXPECT_TRUE(ok[i]) << "thread " << i << "'s run failed";
        const auto own = static_cast<std::size_t>(
            std::count(collector.deliveries.begin() + static_cast<std::ptrdiff_t>(mark),
                       collector.deliveries.end(), callers[i]));
        EXPECT_GT(own, 0U) << "thread " << i << " was never delivered to its own callback";
    }
}

} // namespace
