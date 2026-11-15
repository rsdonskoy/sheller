// Exception-dispatch end-to-end tests: the SEH-driven sample proves the
// engine synthesizes the kernel frame and the real ntdll dispatcher walks
// the guest's unwind tables; the fastfail sample proves the crash fallback
// never reaches the dispatcher. Windows only - the dispatch walks a real
// captured ntdll.

#include "capture_detail.h"
#include "event_ledger.h"
#include "report_events.h"

#include <sheller/syscallrun.h>

#include <gtest/gtest.h>

#include "render_test_util.hpp"
#include "snapshot_fixture.h"

#ifdef _WIN32
#include "behavior_fact.h"
#include "rebuild_probe.h"
#include <sheller/capture.h>
#include <sheller/clock_policy.h>
#include <sheller/snapshot.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <vector>
#endif

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#ifdef _WIN32

namespace fs = std::filesystem;
namespace mem_region = sheller::engine::mem_region;
namespace snapshot = sheller::snapshot;

fs::path capture_to(const char* sample_path, const std::string& name)
{
    const auto dir = fs::temp_directory_path() / "sheller_exception_test";
    fs::create_directories(dir);
    const auto snapshot = dir / name;

    const auto captured = sheller::capture::detail::run_impl(
        sheller::capture::Options{.sample_path = sample_path, .output_path = snapshot});
    EXPECT_EQ(captured.status, sheller::capture::Status::kOk) << captured.detail;
    return snapshot;
}

sheller::engine::SyscallRunOptions options_with(std::vector<std::uint8_t>& sink,
                                                sheller::behavior::EventLedger& ledger)
{
    sheller::engine::SyscallRunOptions options;
    options.write_sink = [&sink](const std::uint8_t* data, std::size_t size) {
        sink.insert(sink.end(), data, data + size);
    };
    options.event_sink = [&ledger](const sheller::EventTypeId type,
                                   const sheller::EventPreamble& preamble,
                                   const std::span<const std::uint8_t> fields) {
        ledger.record(type, preamble, fields);
    };
    return options;
}

std::size_t count_exceptions(const sheller::behavior::EventLedger& ledger, const std::uint32_t code)
{
    std::size_t seen = 0;
    for (std::size_t i = 0; i < ledger.size(); ++i) {
        const auto entry = ledger.entry(i);
        if (entry.type != sheller::EventTypeId::kException) {
            continue;
        }
        EXPECT_GE(entry.type_fields.size(), sizeof(std::uint32_t));
        EXPECT_EQ(sheller::le::load_le32(entry.type_fields.data()), code);
        EXPECT_NE(entry.preamble.pc, 0U);
        ++seen;
    }
    return seen;
}

// kException payload layout (rebuild.cpp emit_exception_payload): {u32 code,
// u32 disposition, u64 related pc}. Dispositions: 0 first-chance, 1
// last-chance, 2 handler-dispatch (the engine-side dispatcher staged a
// guest handler; the fidelity leg never knows the handler and emits none).
constexpr std::uint32_t kDispositionFirstChance = 0;
constexpr std::uint32_t kDispositionLastChance = 1;
constexpr std::uint32_t kDispositionHandlerDispatch = 2;

std::uint32_t exception_disposition(const sheller::behavior::EventLedger& ledger,
                                    const std::size_t index)
{
    const auto entry = ledger.entry(index);
    EXPECT_GE(entry.type_fields.size(), 8U);
    return sheller::le::load_le32(entry.type_fields.data() + 4);
}

std::size_t count_disposition(const sheller::behavior::EventLedger& ledger,
                              const std::uint32_t disposition)
{
    std::size_t seen = 0;
    for (std::size_t i = 0; i < ledger.size(); ++i) {
        const auto entry = ledger.entry(i);
        if (entry.type == sheller::EventTypeId::kException &&
            exception_disposition(ledger, i) == disposition) {
            ++seen;
        }
    }
    return seen;
}

TEST(ExceptionDispatch, SehDrivenSampleWalksFrames)
{
    // SEH tail closed: the guard-region mapping, the write-prot claim
    // defer and the kernel stack growth advanced the walk; the NtRaise-
    // Exception semantics ended the no-handler spin; the interrupt machine
    // frame above the record feeds KiUserExceptionDispatcher's v2 unwind
    // (UWOP_PUSH_MACHFRAME) and the IRETQ tail restore is executed by the
    // engine. The dispatch walks both frames, unwinds and the outer
    // __except handler resumes into the syscall epilogue.
    const auto snapshot = capture_to(SHELLER_SAMPLE_SEH_PATH, "seh.snap");

    sheller::behavior::EventLedger ledger;
    std::vector<std::uint8_t> sink;
    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options_with(sink, ledger));
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error)
        << " (uc=" << stats.error().unicorn_code << " blocks=" << stats.error().stats.blocks
        << " syscalls=" << stats.error().stats.syscalls
        << " exceptions=" << stats.error().stats.exceptions << ")";

    // The dispatch walked both frames; the outer handler wrote the marker
    // and the guest terminated through its own syscall.
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x5678U);
    EXPECT_EQ(stats->exceptions, 1U);
    EXPECT_EQ(std::string(sink.begin(), sink.end()), "caught");

    // Dispatch-fact counts ride the sample binary's scope-table shape: an
    // /Od build emits a real inner filter (two consultations), an /O2 build
    // folds the outer filter to the constant EXCEPTION_EXECUTE_HANDLER fast
    // path (one consultation). The invariant facts: exactly one first-chance
    // AV, at least one handler consultation, no last-chance, and every
    // dispatch fact re-reports the fault code.
    const auto first_chance = count_disposition(ledger, kDispositionFirstChance);
    const auto dispatches = count_disposition(ledger, kDispositionHandlerDispatch);
    EXPECT_EQ(first_chance, 1U);
    EXPECT_GE(dispatches, 1U);
    EXPECT_EQ(count_disposition(ledger, kDispositionLastChance), 0U);
    EXPECT_EQ(ledger.count_of(sheller::EventTypeId::kException), first_chance + dispatches);
    EXPECT_EQ(count_exceptions(ledger, 0xC0000005U), first_chance + dispatches);
}

TEST(ExceptionDispatch, VectoredHandlerSeesFaultsAndResumesContext)
{
    // Engine dispatch, VEH tail: the sample registers a vectored handler
    // through the real ntdll (replay runs the registration as guest code).
    // Fault 1 defers to the structured frame but marks that the vectored walk
    // ran first; fault 2 is resumed through the handler-rewritten CONTEXT -
    // if the engine restored the fault snapshot instead, the probe would
    // refault and the "2" marker would never be written.
    const auto snapshot = capture_to(SHELLER_SAMPLE_SEH_VEH_PATH, "seh_veh.snap");

    sheller::behavior::EventLedger ledger;
    std::vector<std::uint8_t> sink;
    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options_with(sink, ledger));
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error)
        << " (uc=" << stats.error().unicorn_code << " blocks=" << stats.error().stats.blocks
        << " syscalls=" << stats.error().stats.syscalls
        << " exceptions=" << stats.error().stats.exceptions << ")";

    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x5678U);
    EXPECT_EQ(stats->exceptions, 2U);
    // "v" proves the vectored handler ran before the structured walk; the
    // trailing "2" proves the ContinueExecution verdict resumed the rewritten
    // context rather than the faulting snapshot.
    EXPECT_EQ(std::string(sink.begin(), sink.end()), "v12");

    // Two first-chance faults; the handler-dispatch facts (VEH callback plus
    // the structured walk's staged filters) ride the sample's scope-table
    // shape - /Od stages two filters, /O2 folds to the constant-filter fast
    // path - so pin the invariants, not the codegen count.
    const auto first_chance = count_disposition(ledger, kDispositionFirstChance);
    const auto dispatches = count_disposition(ledger, kDispositionHandlerDispatch);
    EXPECT_EQ(first_chance, 2U);
    EXPECT_GE(dispatches, 1U);
    EXPECT_EQ(count_disposition(ledger, kDispositionLastChance), 0U);
    EXPECT_EQ(ledger.count_of(sheller::EventTypeId::kException), first_chance + dispatches);
    EXPECT_EQ(count_exceptions(ledger, 0xC0000005U), first_chance + dispatches);
}

TEST(ExceptionDispatch, FidelityAndEngineModesAgreeOnTheSehScenario)
{
    // The same SEH sample run through both dispatch modes must
    // agree on every observable - exit, output, exception event count/code
    // and first-chance spelling. The fidelity leg exercises the real ntdll
    // dispatch path (windows_fidelity_dispatch), the engine leg the
    // engine-side state machine.
    const auto snapshot = capture_to(SHELLER_SAMPLE_SEH_PATH, "seh_dual.snap");

    sheller::behavior::EventLedger fidelity_ledger;
    std::vector<std::uint8_t> fidelity_sink;
    sheller::engine::SyscallRunOptions fidelity = options_with(fidelity_sink, fidelity_ledger);
    fidelity.windows_fidelity_dispatch = true;
    const auto fidelity_stats = sheller::engine::run_snapshot_syscalls(snapshot, fidelity);
    ASSERT_TRUE(fidelity_stats.has_value())
        << sheller::engine::syscall_run_error_message(fidelity_stats.error().error);

    sheller::behavior::EventLedger engine_ledger;
    std::vector<std::uint8_t> engine_sink;
    const auto engine_stats =
        sheller::engine::run_snapshot_syscalls(snapshot, options_with(engine_sink, engine_ledger));
    ASSERT_TRUE(engine_stats.has_value())
        << sheller::engine::syscall_run_error_message(engine_stats.error().error);

    EXPECT_EQ(fidelity_stats->terminated, engine_stats->terminated);
    EXPECT_EQ(fidelity_stats->exit_code, engine_stats->exit_code);
    EXPECT_EQ(fidelity_stats->exceptions, engine_stats->exceptions);
    EXPECT_EQ(std::string(fidelity_sink.begin(), fidelity_sink.end()), "caught");
    EXPECT_EQ(std::string(engine_sink.begin(), engine_sink.end()),
              std::string(fidelity_sink.begin(), fidelity_sink.end()));

    // The contract, updated for the handler-dispatch reports: the
    // plain first-chance/last-chance events ({u32 code, u32 disposition})
    // agree byte for byte across the dispatch modes - the real ntdll
    // dispatch cannot know the handler, so the engine leg's disposition-2
    // handler attributions are legitimately engine-side only. The
    // syscall-level event noise legitimately differs (the real ntdll
    // dispatch issues information queries the engine dispatcher does not).
    std::vector<std::vector<std::uint8_t>> fidelity_exceptions;
    std::vector<std::vector<std::uint8_t>> engine_exceptions;
    const auto collect_exceptions = [](const sheller::behavior::EventLedger& ledger,
                                       std::vector<std::vector<std::uint8_t>>& out) {
        for (std::size_t i = 0; i < ledger.size(); ++i) {
            const auto entry = ledger.entry(i);
            if (entry.type != sheller::EventTypeId::kException) {
                continue;
            }
            ASSERT_GE(entry.type_fields.size(), 8U);
            const auto disposition = sheller::le::load_le32(entry.type_fields.data() + 4);
            if (disposition == kDispositionHandlerDispatch) {
                continue; // engine-side attribution, absent in fidelity mode
            }
            out.emplace_back(entry.type_fields.begin(), entry.type_fields.end());
        }
    };
    collect_exceptions(fidelity_ledger, fidelity_exceptions);
    collect_exceptions(engine_ledger, engine_exceptions);
    ASSERT_EQ(fidelity_exceptions.size(), engine_exceptions.size());
    for (std::size_t i = 0; i < fidelity_exceptions.size(); ++i) {
        EXPECT_EQ(fidelity_exceptions.at(i), engine_exceptions.at(i));
    }
}

// C++ dual-mode agree: the fidelity leg runs the real ntdll dispatch chain
// (real handler4, RtlUnwindEx, the catch funclet), the engine leg the
// engine-side walk handing off to the same real machinery at the C++
// accept. Both legs of the same snapshot must agree on every
// customer-observable: termination, exit code, sink flow and the first-chance
// exception facts. Handler-dispatch attributions stay engine-side only (the
// fidelity leg never knows the handler) and are excluded, exactly like the
// SEH agree contract above.
struct CppDualModeRun {
    bool valid{false};
    std::vector<std::uint8_t> fidelity_sink;
    std::vector<std::uint8_t> engine_sink;
    sheller::behavior::EventLedger fidelity_ledger;
    sheller::behavior::EventLedger engine_ledger;
    sheller::engine::SyscallRunStats fidelity;
    sheller::engine::SyscallRunStats engine;
};

CppDualModeRun run_cpp_dual_modes(const char* sample_path, const std::string& name)
{
    const auto snapshot = capture_to(sample_path, name);
    CppDualModeRun run;

    sheller::engine::SyscallRunOptions fidelity =
        options_with(run.fidelity_sink, run.fidelity_ledger);
    fidelity.windows_fidelity_dispatch = true;
    auto fidelity_stats = sheller::engine::run_snapshot_syscalls(snapshot, fidelity);
    EXPECT_TRUE(fidelity_stats.has_value())
        << sheller::engine::syscall_run_error_message(fidelity_stats.error().error);
    if (!fidelity_stats.has_value()) {
        return run;
    }
    run.fidelity = *fidelity_stats;

    auto engine_stats = sheller::engine::run_snapshot_syscalls(
        snapshot, options_with(run.engine_sink, run.engine_ledger));
    EXPECT_TRUE(engine_stats.has_value())
        << sheller::engine::syscall_run_error_message(engine_stats.error().error);
    if (!engine_stats.has_value()) {
        return run;
    }
    run.engine = *engine_stats;
    run.valid = true;
    return run;
}

void expect_dual_modes_agree(CppDualModeRun& run, const std::string& flow,
                             const std::uint32_t first_chance_code)
{
    EXPECT_EQ(run.fidelity.terminated, run.engine.terminated);
    EXPECT_EQ(run.fidelity.exit_code, run.engine.exit_code);
    const std::string fidelity_flow(run.fidelity_sink.begin(), run.fidelity_sink.end());
    const std::string engine_flow(run.engine_sink.begin(), run.engine_sink.end());
    EXPECT_EQ(fidelity_flow, flow);
    EXPECT_EQ(engine_flow, fidelity_flow);

    // First-chance facts agree byte for byte; disposition-2 handler
    // attributions are engine-side only (see the SEH agree contract).
    std::vector<std::vector<std::uint8_t>> fidelity_exceptions;
    std::vector<std::vector<std::uint8_t>> engine_exceptions;
    const auto collect = [](const sheller::behavior::EventLedger& ledger,
                            std::vector<std::vector<std::uint8_t>>& out) {
        for (std::size_t i = 0; i < ledger.size(); ++i) {
            const auto entry = ledger.entry(i);
            if (entry.type != sheller::EventTypeId::kException) {
                continue;
            }
            ASSERT_GE(entry.type_fields.size(), 8U);
            const auto disposition = sheller::le::load_le32(entry.type_fields.data() + 4);
            if (disposition == kDispositionHandlerDispatch) {
                continue;
            }
            out.emplace_back(entry.type_fields.begin(), entry.type_fields.end());
        }
    };
    collect(run.fidelity_ledger, fidelity_exceptions);
    collect(run.engine_ledger, engine_exceptions);
    ASSERT_EQ(fidelity_exceptions.size(), engine_exceptions.size());
    for (std::size_t i = 0; i < fidelity_exceptions.size(); ++i) {
        EXPECT_EQ(fidelity_exceptions.at(i), engine_exceptions.at(i));
        EXPECT_EQ(sheller::le::load_le32(fidelity_exceptions.at(i).data()), first_chance_code);
    }
}

TEST(ExceptionDispatch, FidelityAndEngineModesAgreeOnTheCppThrowScenario)
{
    // Throw entry: the whole chain (throw record, handler4 walk, unwind,
    // catch funclet reading the exception object) runs as real guest code on
    // no-debugger hosts in BOTH modes - the engine dispatch is never
    // engaged, so the legs agree trivially on the observable surface and pin
    // that the fidelity mode carries the throw corpus unchanged.
    auto run = run_cpp_dual_modes(SHELLER_SAMPLE_CPP_EH_PATH, "cpp_eh_dual.snap");
    ASSERT_TRUE(run.valid);
    ASSERT_TRUE(run.fidelity.terminated);
    EXPECT_EQ(run.fidelity.exit_code, 0x5678U);
    EXPECT_EQ(run.fidelity.exceptions, 0U);
    expect_dual_modes_agree(run, "EDC", 0U);
}

TEST(ExceptionDispatch, FidelityAndEngineModesAgreeOnTheCppAvCatchBodyScenario)
{
    // AV entry: the fidelity leg hands the fault to the real ntdll dispatch
    // (KiUserExceptionDispatcher as guest code), the engine leg stages the
    // accepting handler's search and hands off to the same real machinery at
    // the accept. The catch body marker "B" proves the non-empty catch
    // funclet executed in each leg; the exception-object read inside the
    // catch would surface a value mismatch as an "X" in the flow.
    auto run = run_cpp_dual_modes(SHELLER_SAMPLE_CPP_EH_AV_PATH, "cpp_eh_av_dual.snap");
    ASSERT_TRUE(run.valid);
    ASSERT_TRUE(run.fidelity.terminated);
    EXPECT_EQ(run.fidelity.exit_code, 0x5678U);
    expect_dual_modes_agree(run, "FEDBC", 0xC0000005U);
}

TEST(XferBudget, CrossSectionTransferEmitsXfer)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_XFER_PATH, "xfer.snap");

    sheller::behavior::EventLedger ledger;
    std::vector<std::uint8_t> sink;
    sheller::engine::SyscallRunOptions options;
    options.write_sink = [&sink](const std::uint8_t* data, std::size_t size) {
        sink.insert(sink.end(), data, data + size);
    };
    options.event_sink = [&ledger](const sheller::EventTypeId type,
                                   const sheller::EventPreamble& preamble,
                                   const std::span<const std::uint8_t> fields) {
        ledger.record(type, preamble, fields);
    };

    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error)
        << " (uc=" << stats.error().unicorn_code << " blocks=" << stats.error().stats.blocks
        << " syscalls=" << stats.error().stats.syscalls
        << " exceptions=" << stats.error().stats.exceptions << ")";
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x5678U);
    EXPECT_EQ(stats->syscalls, 1U);

    // Exactly one cross-section transfer: entry_main (.text) called
    // f2_xfer_entry (text2), which terminated the guest in place.
    ASSERT_EQ(ledger.count_of(sheller::EventTypeId::kXfer), 2U);
    for (std::size_t i = 0; i < ledger.size(); ++i) {
        const auto entry = ledger.entry(i);
        if (entry.type != sheller::EventTypeId::kXfer) {
            continue;
        }
        ASSERT_GE(entry.type_fields.size(), 8U);
        const auto from_module = sheller::le::load_le16(entry.type_fields.data());
        const auto from_section = sheller::le::load_le16(entry.type_fields.data() + 2);
        const auto to_module = sheller::le::load_le16(entry.type_fields.data() + 4);
        const auto to_section = sheller::le::load_le16(entry.type_fields.data() + 6);
        EXPECT_NE(from_section, to_section);
        EXPECT_EQ(from_module, to_module); // same module, different sections
        EXPECT_NE(to_module, 0xFFFFU);
    }
}

TEST(XferStop, CapturedSampleStopsAtTheFirstTransfer)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_XFER_PATH, "xfer_stop_first.snap");
    const auto dir = std::filesystem::path(testing::TempDir()) / "xfer_stop_first";
    std::filesystem::remove_all(dir);

    sheller::behavior::EventLedger ledger;
    std::vector<std::uint8_t> sink;
    auto options = options_with(sink, ledger);
    options.xfer_number = 1;
    options.dump_directory = dir;

    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error)
        << " (blocks=" << stats.error().stats.blocks << " syscalls=" << stats.error().stats.syscalls
        << ")";
    EXPECT_FALSE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0U);
    EXPECT_EQ(stats->syscalls, 0U); // the landing text2 block never ran
    EXPECT_EQ(stats->xfers, 1U);
    EXPECT_TRUE(stats->xfer_stop);
    // The landing block still counts and still emits block-exec, and the
    // event only goes out for the one transfer that stopped the run.
    EXPECT_EQ(ledger.count_of(sheller::EventTypeId::kBlockExec), stats->blocks);
    EXPECT_EQ(ledger.count_of(sheller::EventTypeId::kXfer), 1U);
    EXPECT_TRUE(std::filesystem::exists(dir / "manifest.txt"));
}

TEST(XferStop, CapturedSampleHonoursTheSecondOrdinal)
{
    // The sample crosses .text -> text2 for the call, then text2 -> .text for
    // the terminate thunk. Stopping at the second landing leaves the syscall
    // unexecuted.
    const auto snapshot = capture_to(SHELLER_SAMPLE_XFER_PATH, "xfer_stop_second.snap");

    sheller::behavior::EventLedger ledger;
    std::vector<std::uint8_t> sink;
    auto options = options_with(sink, ledger);
    options.xfer_number = 2;

    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error);
    EXPECT_FALSE(stats->terminated);
    EXPECT_EQ(stats->syscalls, 0U);
    EXPECT_EQ(stats->xfers, 2U);
    EXPECT_TRUE(stats->xfer_stop);
    EXPECT_EQ(ledger.count_of(sheller::EventTypeId::kXfer), 2U);
}

// Alloc-jump corpus: the runtime-region classification's headline
// sequence as real guest code - VirtualAlloc private data memory, write a
// payload, protect it executable, jump in. The landings carry the runtime
// private-exec sentinel (0xFF11) in the xfer payload, the timeline and the
// events report render the same class name for them, the payload's TEB/
// PEB reads surface as behavior facts with a runtime-region reader pc
// (the reader-fact guard), and the whole stream replays byte-identically.
TEST(AllocJump, RuntimeRegionClassificationSequence)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_ALLOCJUMP_PATH, "allocjump.snap");
    const auto probe = sheller::engine::detail::attribute_snapshot_modules(snapshot);
    ASSERT_TRUE(probe.has_value());
    sheller::TimelineNameTable names;
    for (const auto& image : probe->images) {
        names.modules.emplace_back(image.module.name.data());
        names.sections.emplace_back(); // section names are not under test here
    }

    const auto run_once = [&]() {
        sheller::behavior::EventLedger ledger;
        sheller::behavior::EventTally tally;
        std::vector<sheller::engine::BehaviorFact> facts;
        sheller::engine::SyscallRunOptions options;
        // The fact seam has no public options slot: the channel rides beside.
        sheller::engine::FactChannel fact_channel;
        fact_channel.behavior_sink = [&facts](const sheller::engine::BehaviorFact& fact) {
            facts.push_back(fact);
        };
        options.event_sink = [&](const sheller::EventTypeId type,
                                 const sheller::EventPreamble& preamble,
                                 const std::span<const std::uint8_t> fields) {
            ledger.record(type, preamble, fields);
            tally.on_event(type, preamble, fields);
        };
        options.timeout_ms = 30000;
        const auto stats = sheller::engine::detail::run_snapshot_syscalls_with_facts(
            snapshot, options, fact_channel);
        EXPECT_TRUE(stats.has_value())
            << sheller::engine::syscall_run_error_message(stats.error().error);
        // 0x3333 = both payloads returned their markers AND the MBI answers
        // matched the carved map; every shortcut died with a 0xDEADn code.
        EXPECT_TRUE(stats.has_value() && stats->terminated);
        if (stats.has_value()) {
            EXPECT_EQ(stats->exit_code, 0x3333U) << "payload or MBI check failed";
        }
        struct RunOutput {
            sheller::behavior::EventLedger ledger;
            std::string full_stream;
            std::string events_report;
            std::vector<sheller::engine::BehaviorFact> facts;
        };
        auto full_stream = render_full_events(ledger, names);
        auto events_report = sheller::cli::render_events_section(artifacts_for(tally));
        return RunOutput{std::move(ledger), std::move(full_stream), std::move(events_report),
                         std::move(facts)};
    };

    const auto first = run_once();

    // The xfer edge rules (sample image section <-> sample-allocated
    // memory, plus sample image section -> sample image section) yield
    // exactly four events for this run: the jump into each payload (to =
    // the runtime private-exec sentinel 0xFF11) and each payload's return
    // into the sample image (from = 0xFF11). Everything else - the
    // payload's kernel32 call, the return from kernelbase into the
    // payload, all pure-system crossings - stays silent by design.
    const auto slot_at = [](const std::span<const std::uint8_t>& fields, const std::size_t offset) {
        return static_cast<std::uint16_t>(fields[offset]) |
               static_cast<std::uint16_t>(static_cast<unsigned>(fields[offset + 1]) << 8);
    };
    std::vector<std::pair<std::uint64_t, std::uint16_t>> landings; // (pc, from_module)
    std::size_t from_sentinel_count = 0;
    std::size_t total_xfer = 0;
    for (std::size_t i = 0; i < first.ledger.size(); ++i) {
        const auto entry = first.ledger.entry(i);
        if (entry.type != sheller::EventTypeId::kXfer || entry.type_fields.size() < 8) {
            continue;
        }
        ++total_xfer;
        const auto from_module = slot_at(entry.type_fields, 0);
        const auto to_module = slot_at(entry.type_fields, 4);
        if (to_module == 0xFF11) {
            landings.emplace_back(entry.preamble.pc, from_module);
        }
        if (from_module == 0xFF11) {
            ++from_sentinel_count;
            EXPECT_LT(to_module, 0xFF00U); // the return lands in the sample image
        }
    }
    ASSERT_EQ(landings.size(), 2U) << "expected one landing per payload allocation";
    const std::uint64_t alloc_a = landings[0].first - 0x10; // payload entry at base+0x10
    EXPECT_GE(landings[1].first, alloc_a + 0x2000);         // the second allocation (bump)
    for (const auto& landing : landings) {
        EXPECT_LT(landing.second, 0xFF00U); // entered from the sample image
    }
    EXPECT_EQ(from_sentinel_count, 2U); // both payloads returned into the image
    EXPECT_EQ(total_xfer, 4U);          // and nothing else crosses

    // The full-level stream renders the sentinel landing as private-exec; the
    // report's detail-list counterpart (xfer entries carrying the sentinel
    // class) is pinned by report_events_test over the facade's semantic
    // events - this e2e wires the raw tally, whose section counts only.
    EXPECT_NE(first.full_stream.find("\"to\":\"private-exec\""), std::string::npos);

    // Reader-fact guard: the payload's TEB/PEB reads are recorded although
    // the reader pc sits in the runtime allocation, not the sample image.
    bool runtime_read = false;
    for (const auto& fact : first.facts) {
        if (fact.kind == sheller::engine::BehaviorFact::Kind::kMemRead && fact.pc >= alloc_a &&
            fact.pc < alloc_a + 0x2000) {
            runtime_read = true;
        }
    }
    EXPECT_TRUE(runtime_read) << "no mem-read fact from the runtime allocation";

    const auto second = run_once();
    EXPECT_EQ(first.full_stream, second.full_stream);
    EXPECT_EQ(first.events_report, second.events_report);
}

// Unknown-image attribution corpus: the sample's snapshot is extended with
// four contiguous MEM_IMAGE regions forming a hand-mapped image the Ldr
// list never enumerates - headers page (a parseable PE32+ whose
// SizeOfImage equals the chain union), a same-section RX->RWX protection
// fragment pair, and a second executable section plus the faulting leg.
// The synthesis must give the image a module record; the xfer face is
// two-directional (the fragment crossing goes silent, the section crossing
// and the landings emit); the MBI answer keeps region semantics while MII
// answers the synthesized extent in fidelity mode; and the in-image fault
// under a continue-search VEH resolves unhandled in both dispatch modes
// (the pre-synthesis non-module shape, engine iterations excluded).
TEST(UnknownImage, SynthesizedImageEventsResponsesAndEhFace)
{
    constexpr std::uint64_t kImageBase = 0x7F5000000000ULL;
    constexpr std::uint64_t kImageSize = 0x3000;

    const auto plain = capture_to(SHELLER_SAMPLE_UNKNOWNJUMP_PATH, "unknown_jump.plain.snap");

    // The crafted image's headers page: PE32+ with .text and text2, each
    // section exactly covering its region fragment (the span tie keeps the
    // image refinement most specific), SizeOfImage == chain union
    // (0x3000), no exception directory.
    constexpr std::array kSynthSections{sheller_test::PeSection{".text", 0x1000},
                                        sheller_test::PeSection{"text2", 0x2000}};
    const auto crafted_image =
        sheller_test::craft_pe_image(kImageBase, kImageSize, 0x1000, kSynthSections);
    const std::vector<std::uint8_t> headers_page(
        crafted_image.begin(),
        crafted_image.begin() + static_cast<std::ptrdiff_t>(sheller_test::kPeHeadersPageSize));

    // Splice the crafted regions into a re-read of the plain capture. The
    // region type is a parameter: MEM_IMAGE forms the synthesis chain,
    // MEM_PRIVATE the same bytes without one (the pre-synthesis world the
    // fidelity-mode dispatch is compared against).
    const auto craft = [&](const char* name, const std::uint32_t region_type) {
        const auto payload_rx = [] {
            std::vector<std::uint8_t> page(0x1000, 0);
            const std::uint8_t leg_a[] = {0xB8, 0x11, 0x11, 0x11, 0x11,
                                          0xE9, 0xF6, 0x0F, 0x00, 0x00};
            std::memcpy(page.data(), leg_a, sizeof leg_a);
            return page;
        }();
        const auto payload_rwx = [&] {
            std::vector<std::uint8_t> page(0x1000, 0);
            const std::uint8_t leg_b[] = {0xB8, 0x22, 0x22, 0x22, 0x22,
                                          0xE9, 0xF6, 0x03, 0x00, 0x00};
            std::memcpy(page.data(), leg_b, sizeof leg_b);
            const std::uint8_t leg_c[] = {0xB8, 0x33, 0x33, 0x33, 0x33, 0xC3};
            std::memcpy(page.data() + 0x400, leg_c, sizeof leg_c);
            const std::uint8_t fault[] = {0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00};
            std::memcpy(page.data() + 0x800, fault, sizeof fault);
            return page;
        }();

        std::ifstream in(plain, std::ios::binary);
        EXPECT_TRUE(in.good());
        snapshot::Reader reader{in};
        const auto header = reader.read_header();
        const auto registers = reader.read_registers();
        const auto metadata = reader.read_metadata();
        EXPECT_TRUE(header.has_value() && registers.has_value() && metadata.has_value());
        std::vector<snapshot::Region> regions;
        for (std::uint32_t i = 0; i < header->region_count; ++i) {
            auto region = reader.read_region();
            EXPECT_TRUE(region.has_value());
            regions.push_back(std::move(*region));
        }
        const auto push_crafted = [&](std::uint64_t base, std::uint64_t size,
                                      std::uint32_t protection, std::vector<std::uint8_t> content) {
            snapshot::Region crafted;
            crafted.header.base_address = base;
            crafted.header.size = size;
            crafted.header.protection = protection;
            crafted.header.type = region_type;
            crafted.header.content = snapshot::kContentPresent;
            crafted.content = std::move(content);
            regions.push_back(std::move(crafted));
        };
        push_crafted(kImageBase, 0x1000, 0x02, headers_page);
        push_crafted(kImageBase + 0x1000, 0x1000, 0x20, std::move(payload_rx));
        push_crafted(kImageBase + 0x2000, 0x1000, 0x40, std::move(payload_rwx));
        // canonical order is ascending by base (binary-searching readers)
        std::sort(regions.begin(), regions.end(),
                  [](const snapshot::Region& a, const snapshot::Region& b) {
                      return a.header.base_address < b.header.base_address;
                  });
        // rewrite with the capture's header facts; the writer seeds its
        // region count from the header and bumps it per write_region, so it
        // takes a zero count and finalize patches the real one
        const auto crafted_path = plain.parent_path() / name;
        std::ofstream out(crafted_path, std::ios::binary | std::ios::trunc);
        EXPECT_TRUE(out.good());
        {
            auto out_header = *header;
            out_header.region_count = 0;
            snapshot::Writer writer{out};
            EXPECT_TRUE(writer.write_header(out_header).has_value());
            EXPECT_TRUE(writer.write_registers(*registers).has_value());
            EXPECT_TRUE(writer.write_metadata(*metadata).has_value());
            for (const auto& region : regions) {
                const auto* content = region.header.content == snapshot::kContentPresent
                                          ? region.content.data()
                                          : nullptr;
                EXPECT_TRUE(writer.write_region(region.header, content).has_value());
            }
            EXPECT_TRUE(writer.finalize_region_count().has_value());
            // A capture rewritten at its own version: v3 carries the clock
            // block (the engine's pinned policy - the fixture's sample world
            // does not run long enough to read it, but the loader requires
            // it).
            if (out_header.version == snapshot::kVersionV3) {
                EXPECT_TRUE(writer.write_clock(snapshot::default_clock_policy()).has_value());
            }
        }
        return crafted_path;
    };
    {
        const auto crafted_path = craft("unknown_jump.craft.snap", 0x1000000); // MEM_IMAGE

        const auto probe = sheller::engine::detail::attribute_snapshot_modules(crafted_path);
        ASSERT_TRUE(probe.has_value())
            << "rebuild failed: " << sheller::engine::rebuild_error_message(probe.error().error);

        // The synthesis product: one unknown image, the Ldr set untouched.
        ASSERT_EQ(probe->unknown_images.size(), 1U);
        const auto& unknown = probe->unknown_images[0];
        EXPECT_TRUE(unknown.module.synthesized);
        EXPECT_EQ(unknown.module.base, kImageBase);
        EXPECT_EQ(unknown.module.size, kImageSize); // SizeOfImage == chain union
        EXPECT_STREQ(unknown.module.name.data(), "unknown-image-00007f5000000000");
        for (const auto& image : probe->images) {
            EXPECT_FALSE(image.module.synthesized);
        }

        // Names <-> map alignment: Ldr images then unknown images IS the
        // map's module order - the render builds its tables from exactly
        // this concatenation.
        std::vector<mem_region::ModuleImage> all_images(probe->images);
        all_images.insert(all_images.end(), probe->unknown_images.begin(),
                          probe->unknown_images.end());
        const mem_region::MemRegionMap map(all_images, probe->regions);
        ASSERT_EQ(map.module_count(), all_images.size());
        for (std::size_t i = 0; i < all_images.size(); ++i) {
            EXPECT_EQ(map.module(i).base, all_images[i].module.base) << "module index " << i;
        }
        const auto unknown_index = probe->images.size();

        // Timeline names mirror the map order with the wire-grid sections.
        sheller::TimelineNameTable names;
        for (const auto& image : all_images) {
            names.modules.emplace_back(image.module.name.data());
            auto& secs = names.sections.emplace_back();
            secs.emplace_back("headers");
            mem_region::ImageLayout layout;
            if (mem_region::parse_section_table(image.header_bytes.data(),
                                                image.header_bytes.size(),
                                                layout) == mem_region::PeParseError::kNone) {
                for (const auto& section : layout.sections) {
                    secs.emplace_back(section.name.data());
                }
            }
        }

        const auto run_once = [&](const fs::path& path, const bool fidelity) {
            sheller::behavior::EventLedger ledger;
            std::vector<std::uint8_t> sink;
            auto options = options_with(sink, ledger);
            options.timeout_ms = 30000;
            options.windows_fidelity_dispatch = fidelity;
            const auto stats = sheller::engine::run_snapshot_syscalls(path, options);
            return std::pair{std::move(ledger), std::move(stats)};
        };

        // Engine mode: every guest-side check must pass (any failure
        // terminates cleanly with its 0xDEADn code), then the in-image
        // fault stays unhandled - delivered, found handler-less, and
        // re-delivered once before the repeat-dispatch guard ends the run.
        auto [ledger, stats] = run_once(crafted_path, false);
        ASSERT_FALSE(stats.has_value()) << "guest check failed or dispatch diverged (exit "
                                        << (stats.has_value() ? stats->exit_code : 0) << ")";
        EXPECT_EQ(stats.error().error, sheller::engine::SyscallRunError::kUnhandledException);
        EXPECT_EQ(stats.error().stats.exceptions, 2U);
        EXPECT_EQ(count_exceptions(ledger, 0xC0000005U), 2U);

        // The xfer face under the narrowed edge rules: jumps between the
        // sample image and the synthesized unknown image are NOT sample
        // image section -> sample image section / sample-allocated-memory
        // edges, so the whole unknown-image execution (landing, in-image
        // section crossing, fault re-entry, return) stays xfer-silent - the
        // execution itself is still fully observed through block-exec and
        // the exception stream above.
        std::size_t total_xfer = 0;
        for (std::size_t i = 0; i < ledger.size(); ++i) {
            if (ledger.entry(i).type == sheller::EventTypeId::kXfer) {
                ++total_xfer;
            }
        }
        EXPECT_EQ(total_xfer, 0U);

        const auto full_stream = render_full_events(ledger, names);
        // the naming face: the synthesized module resolves in the render
        // tables (map order Ldr-then-unknown), even though the narrowed
        // xfer stream no longer carries its landings
        EXPECT_EQ(sheller::module_name_of(names, static_cast<std::uint16_t>(unknown_index)),
                  "unknown-image-00007f5000000000");

        // determinism: same crafted snapshot, byte-identical stream
        auto [ledger2, stats2] = run_once(crafted_path, false);
        EXPECT_FALSE(stats2.has_value());
        const auto full_stream2 = render_full_events(ledger2, names);
        EXPECT_EQ(full_stream, full_stream2);

        // Fidelity mode: the MII extent answer (the guest-side check) must
        // hold, and the in-image fault must resolve exactly the way the
        // same bytes resolve without a synthesis-able region - the real
        // ntdll's exception-table lookup must not break on the synthesized
        // image. The comparison runs the MEM_PRIVATE twin of the crafted
        // snapshot: same bytes, no chain, region-level answers.
        const auto private_path = craft("unknown_jump.private.snap", 0x20000); // MEM_PRIVATE
        auto [fidelity_ledger, fidelity_stats] = run_once(crafted_path, true);
        auto [plain_ledger, plain_stats] = run_once(private_path, true);
        if (fidelity_stats.has_value() != plain_stats.has_value()) {
            EXPECT_TRUE(false)
                << "fidelity dispatch diverged between the "
                   "synthesized and region-level worlds (image "
                << (fidelity_stats.has_value()
                        ? "exit " + std::to_string(fidelity_stats->exit_code)
                        : "error " + std::to_string(static_cast<int>(fidelity_stats.error().error)))
                << " vs private "
                << (plain_stats.has_value()
                        ? "exit " + std::to_string(plain_stats->exit_code)
                        : "error " + std::to_string(static_cast<int>(plain_stats.error().error)))
                << ")";
        } else if (fidelity_stats.has_value()) {
            EXPECT_EQ(fidelity_stats->exit_code, plain_stats->exit_code);
        } else {
            EXPECT_EQ(fidelity_stats.error().error, plain_stats.error().error);
            EXPECT_EQ(fidelity_stats.error().stats.exceptions,
                      plain_stats.error().stats.exceptions);
        }
        // the synthesized world still faults at the crafted pc, whatever the
        // shared resolution is
        EXPECT_EQ(count_exceptions(fidelity_ledger, 0xC0000005U),
                  count_exceptions(plain_ledger, 0xC0000005U));
        EXPECT_GT(count_exceptions(fidelity_ledger, 0xC0000005U), 0U);
    }
}

TEST(XferBudget, BlockBudgetDeterministicStop)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_SPIN_PATH, "xfer_budget.spin.snap");

    const auto run_once = [&snapshot] {
        sheller::engine::SyscallRunOptions options;
        options.max_blocks = 100;
        const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
        EXPECT_FALSE(stats.has_value());
        EXPECT_EQ(stats.error().error, sheller::engine::SyscallRunError::kBudgetExhausted);
        return stats.error().stats.blocks;
    };

    const auto blocks_a = run_once();
    const auto blocks_b = run_once();
    EXPECT_EQ(blocks_a, 100U);
    EXPECT_EQ(blocks_a, blocks_b); // deterministic stop point
}

// Dump pipeline: the four deterministic stop kinds export
// the dirty regions; a pure wall-clock timeout does not (non-deterministic,
// excluded from baselines).
TEST(DumpPipeline, NormalExitExportsOriginalBytes)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_XFER_PATH, "dump_exit.snap");
    const auto dir = std::filesystem::path(testing::TempDir()) / "dump_pipeline_exit";
    std::filesystem::remove_all(dir);

    sheller::engine::SyscallRunOptions options;
    options.dump_directory = dir;
    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
    ASSERT_TRUE(stats.has_value());

    // The guest's stack writes dirty at least one region: one raw .bin per
    // manifest line, named by the line's base field.
    std::ifstream manifest(dir / "manifest.txt");
    ASSERT_TRUE(manifest) << "manifest missing";
    auto line_count = std::size_t{0};
    std::string line;
    while (std::getline(manifest, line)) {
        if (line.empty()) {
            continue;
        }
        ++line_count;
        const auto bin_path = dir / (line.substr(0, 16) + ".bin");
        std::ifstream region_file(bin_path, std::ios::binary);
        EXPECT_TRUE(region_file.good()) << bin_path;
    }
    EXPECT_GE(line_count, 1U);
}

TEST(DumpPipeline, DeterministicAcrossReplays)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_XFER_PATH, "dump_replay.snap");
    const auto root = std::filesystem::path(testing::TempDir()) / "dump_pipeline_replay";
    std::filesystem::remove_all(root);

    const auto run_dump = [&snapshot](const std::filesystem::path& out) {
        sheller::engine::SyscallRunOptions options;
        options.dump_directory = out;
        EXPECT_TRUE(sheller::engine::run_snapshot_syscalls(snapshot, options).has_value());
    };
    run_dump(root / "a");
    run_dump(root / "b");

    // Same snapshot replayed twice: byte-identical dumps.
    for (std::filesystem::recursive_directory_iterator it_a(root / "a"), it_b(root / "b");
         it_a != std::filesystem::recursive_directory_iterator(); ++it_a, ++it_b) {
        ASSERT_EQ(it_a->path().filename(), it_b->path().filename());
        std::ifstream file_a(it_a->path(), std::ios::binary);
        std::ifstream file_b(it_b->path(), std::ios::binary);
        const std::string bytes_a((std::istreambuf_iterator<char>(file_a)), {});
        const std::string bytes_b((std::istreambuf_iterator<char>(file_b)), {});
        EXPECT_EQ(bytes_a, bytes_b) << it_a->path();
    }
}

TEST(DumpPipeline, BudgetExhaustionAlsoExports)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_SPIN_PATH, "dump_budget.snap");
    const auto dir = std::filesystem::path(testing::TempDir()) / "dump_pipeline_budget";
    std::filesystem::remove_all(dir);

    sheller::engine::SyscallRunOptions options;
    options.dump_directory = dir;
    options.max_blocks = 100; // block budget: deterministic stop, dump-eligible
    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
    ASSERT_FALSE(stats.has_value());
    EXPECT_EQ(stats.error().error, sheller::engine::SyscallRunError::kBudgetExhausted);
    EXPECT_TRUE(std::filesystem::exists(dir / "manifest.txt"));
}

TEST(DumpPipeline, TimeoutWritesNothing)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_SPIN_PATH, "dump_timeout.snap");
    const auto dir = std::filesystem::path(testing::TempDir()) / "dump_pipeline_timeout";
    std::filesystem::remove_all(dir);

    sheller::engine::SyscallRunOptions options;
    options.dump_directory = dir;
    options.max_instructions = 0; // unlimited: only the wall clock may stop it
    options.timeout_ms = 200;     // wall-clock stop: non-deterministic, excluded
    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
    ASSERT_FALSE(stats.has_value());
    EXPECT_EQ(stats.error().error, sheller::engine::SyscallRunError::kTimeout);
    EXPECT_FALSE(std::filesystem::exists(dir));
}

TEST(ExceptionDispatch, FastfailCrashesWithoutDispatch)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_SEH_FASTFAIL_PATH, "fastfail.snap");

    sheller::behavior::EventLedger ledger;
    std::vector<std::uint8_t> sink;
    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options_with(sink, ledger));
    ASSERT_FALSE(stats.has_value());
    EXPECT_EQ(stats.error().error, sheller::engine::SyscallRunError::kUnhandledException);

    // The exception is still a guest fact: it lands in the ledger even
    // though the delivery never reaches the dispatcher. __fastfail keeps
    // its real Windows code (STATUS_STACK_BUFFER_OVERRUN).
    EXPECT_EQ(stats.error().stats.exceptions, 1U);
    EXPECT_EQ(ledger.count_of(sheller::EventTypeId::kException), 1U);
    EXPECT_EQ(count_exceptions(ledger, 0xC0000409U), 1U);
}

TEST(ModuleAttribution, HelloSnapshotEnumeratesAndAttributes)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_HELLO_PATH, "attribution.snap");
    const auto probe = sheller::engine::detail::attribute_snapshot_modules(snapshot);
    ASSERT_TRUE(probe.has_value());

    // Full enumeration: the main module plus the system modules.
    ASSERT_GE(probe->images.size(), 3U);
    ASSERT_FALSE(probe->regions.empty());

    const mem_region::MemRegionMap map(probe->images, probe->regions);
    std::size_t ntdll_index = 0;
    std::size_t known_modules = 0;
    bool has_ntdll = false;
    for (std::size_t i = 0; i < map.module_count(); ++i) {
        const auto& name = map.module(i).name;
        if (std::string_view(name.data()) == "ntdll.dll") {
            has_ntdll = true;
            ntdll_index = i;
        }
        if (std::string_view(name.data()) == "kernel32.dll" ||
            std::string_view(name.data()) == "ntdll.dll" ||
            std::string_view(name.data()).find("capture_syscall_sample") !=
                std::string_view::npos) {
            ++known_modules;
        }
    }
    EXPECT_TRUE(has_ntdll);
    EXPECT_GE(known_modules, 3U);

    // An address inside the ntdll image attributes to the ntdll module.
    const auto& ntdll = map.module(ntdll_index);
    const auto inside = map.query(ntdll.base + 0x1000);
    ASSERT_TRUE(inside.has_value());
    EXPECT_EQ(inside->module_name, "ntdll.dll");
    EXPECT_TRUE(inside->kind == mem_region::AttributionKind::kImageSection ||
                inside->kind == mem_region::AttributionKind::kImageHeaders);

    // A private region attributes at region level with its captured facts.
    bool private_checked = false;
    for (std::size_t i = 0; i < probe->regions.size(); ++i) {
        const auto& region = probe->regions[i];
        if (region.type != 0x20000U || region.size < 0x10) { // MEM_PRIVATE
            continue;
        }
        const auto attributed = map.query(region.base + region.size / 2);
        ASSERT_TRUE(attributed.has_value());
        EXPECT_EQ(attributed->kind, mem_region::AttributionKind::kRegion);
        EXPECT_EQ(attributed->type, 0x20000U);
        EXPECT_EQ(attributed->region_index, i);
        private_checked = true;
        break;
    }
    EXPECT_TRUE(private_checked);

    // Far outside every region and module: no attribution.
    std::uint64_t max_end = 0;
    for (const auto& region : probe->regions) {
        max_end = (std::max)(max_end, region.base + region.size);
    }
    EXPECT_FALSE(map.query(max_end + 0x10000000ULL).has_value());

    // Real syscall numbers: the resolution map names the core Nt functions. Numbers are
    // build-specific, so only presence and non-zero-ness are asserted.
    std::size_t core_named = 0;
    for (const auto& entry : probe->syscall_numbers) {
        const auto name = std::string_view(entry.name.data());
        if (name == "NtTerminateProcess" || name == "NtProtectVirtualMemory") {
            ++core_named;
            EXPECT_NE(entry.number, 0U);
        }
    }
    EXPECT_GE(core_named, 2U);
}

TEST(ExceptionDispatch, CppEhThrowChainWalksRealHandlers)
{
    // Throw entry: the whole C++ EH chain runs as real guest
    // code (RtlRaiseException's user-mode fast path dispatches without a
    // syscall on no-debugger hosts) - the throw record, __CxxFrameHandler4,
    // the unwind second pass (destructor markers, inner first) and the catch
    // funclet all execute in the guest. Output "EDC", exit 0x5678.
    const auto snapshot = capture_to(SHELLER_SAMPLE_CPP_EH_PATH, "cpp_eh.snap");

    sheller::behavior::EventLedger ledger;
    std::vector<std::uint8_t> sink;
    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options_with(sink, ledger));
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error);

    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x5678U);
    EXPECT_EQ(std::string(sink.begin(), sink.end()), "EDC");
    // the dispatch itself is engine-invisible on no-debugger hosts:
    // RtlRaiseException takes the user-mode fast path (direct
    // RtlDispatchException, no NtRaiseException syscall), so the whole
    // raise-walk-unwind-catch cycle runs as guest code the engine only
    // executes - exactly the fidelity this corpus pins
    EXPECT_EQ(stats->exceptions, 0U);
    EXPECT_EQ(ledger.count_of(sheller::EventTypeId::kException), 0U);
}

TEST(ExceptionDispatch, CppEhEngineDispatchUnwindRunsDestructors)
{
    // Engine-dispatch entry: a hardware AV inside C++ code.
    // The engine walk classifies the __CxxFrameHandler4 frames (never reading
    // FuncInfo as a scope table) and stages the real handler with the winnt
    // DISPATCHER_CONTEXT. When the accepting handler drives RtlUnwindEx (the
    // C++ accept protocol), the engine retires the dispatch and re-delivers
    // the fault through the real guest dispatcher: the unwind machinery runs
    // the second pass as guest code - faulter's destructor funclet ("F") -
    // re-calls the accepting frame with the target-unwind record, the catch
    // body funclet destroys the try-block markers ("E","D"), runs the body
    // ("B") and returns the continuation ("C"). Output "FEDBC", 0x5678.
    const auto snapshot = capture_to(SHELLER_SAMPLE_CPP_EH_AV_PATH, "cpp_eh_av.snap");

    sheller::behavior::EventLedger ledger;
    std::vector<std::uint8_t> sink;
    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options_with(sink, ledger));
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error);

    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x5678U);
    EXPECT_EQ(std::string(sink.begin(), sink.end()), "FEDBC");
    EXPECT_GE(stats->exceptions, 1U);
    // the AV was delivered first-chance, and the one handler-dispatch fact is
    // the accepting __CxxFrameHandler4 search call the engine staged; the
    // unwind pass itself runs as real guest code (the re-delivered dispatch),
    // so it produces no per-callback engine facts - nobody declined the
    // exception either way
    EXPECT_GE(count_disposition(ledger, kDispositionFirstChance), 1U);
    EXPECT_EQ(count_disposition(ledger, kDispositionHandlerDispatch), 1U);
    EXPECT_EQ(count_disposition(ledger, kDispositionLastChance), 0U);
}

TEST(ExceptionDispatch, SehFinallyRunsInEngineUnwindPass)
{
    // SEH __finally: the faulting frame's termination
    // handler runs exactly once during the engine unwind pass, before the
    // accepting __except body. Output "FX", exit 0x5678.
    const auto snapshot = capture_to(SHELLER_SAMPLE_SEH_FINALLY_PATH, "seh_finally.snap");

    sheller::behavior::EventLedger ledger;
    std::vector<std::uint8_t> sink;
    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options_with(sink, ledger));
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error);

    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x5678U);
    EXPECT_EQ(std::string(sink.begin(), sink.end()), "FX");
    EXPECT_EQ(stats->exceptions, 1U);
    // the finally body is one staged guest callback; the accepting
    // __except uses a constant filter (MSVC folds the one-line filter), so
    // only the finally stages
    EXPECT_GE(count_disposition(ledger, kDispositionHandlerDispatch), 1U);
    EXPECT_EQ(count_disposition(ledger, kDispositionLastChance), 0U);
}

#endif // _WIN32
