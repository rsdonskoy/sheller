// The unpack_sample entry point: capture (Windows) / construct a v1 container
// (other hosts) -> run that container with dump -> engine-native IAT repair ->
// target-region selection -> the requested artifacts. Both platforms share the
// same executed container, repair and region selection: the constructed
// container carries the sample's Ldr entry and the synthetic module pages, so
// the repair verdict matches the capture route and the behavior tier is
// populated. Work directories are process-unique when generated, and cleanup
// only ever touches a directory this call created.

#include "wiring.h"

#include "../engine/craft.h"
#include <sheller/capture.h>
#include <sheller/peloader.h>
#include <sheller/rebuild.h>
#include <sheller/snapshot.h>
#include <sheller/syscallrun.h>
#include <sheller/unpack.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <spanstream>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <process.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif

namespace sheller {

namespace {

#ifdef _WIN32

std::uint32_t current_pid()
{
    return static_cast<std::uint32_t>(_getpid());
}

#else

std::uint32_t current_pid()
{
    return static_cast<std::uint32_t>(getpid());
}

#endif

AnalysisFailure make_failure(const AnalysisFailure::Kind kind, std::string message,
                             AnalysisArtifacts artifacts,
                             std::optional<engine::SyscallRunFailure> run = std::nullopt)
{
    AnalysisFailure failure;
    failure.kind = kind;
    failure.message = std::move(message);
    failure.artifacts = std::move(artifacts);
    failure.run = std::move(run);
    return failure;
}

std::string hex16(const std::uint64_t value)
{
    char buf[17] = {};
    std::snprintf(buf, sizeof buf, "%016llx", static_cast<unsigned long long>(value));
    return std::string{buf};
}

// Process-unique staging root: pid + call counter, never a fixed shared
// directory two concurrent calls could delete out from under each other.
std::filesystem::path generate_work_dir(std::error_code& ec)
{
    static std::atomic<std::uint64_t> counter{0};
    const auto temp = std::filesystem::temp_directory_path(ec);
    if (ec) {
        return {};
    }
    auto dir = temp / ("sheller_unpack_" + std::to_string(current_pid()) + "_" +
                       std::to_string(counter.fetch_add(1)));
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        return {};
    }
    return dir;
}

} // namespace

namespace api::detail {

const unpack::RegionRepairReport*
select_unpack_region(const std::span<const unpack::RegionRepairReport> regions,
                     const std::uint64_t image_base_for_selection, const bool require_cover)
{
    const unpack::RegionRepairReport* best = nullptr;
    bool best_covers = false;
    for (const auto& region : regions) {
        if (region.verdict != unpack::RepairVerdict::kComplete &&
            region.verdict != unpack::RepairVerdict::kPartial) {
            continue;
        }
        const bool region_covers = image_base_for_selection >= region.base &&
                                   image_base_for_selection < region.base + region.size;
        // A covering candidate outranks any non-covering one outright -
        // a later incidental complete system image must never displace the
        // sample's own (possibly partial) region. Within the same coverage
        // class, complete wins over partial.
        if (best == nullptr) {
            best = &region;
            best_covers = region_covers;
            continue;
        }
        if (region_covers && !best_covers) {
            best = &region;
            best_covers = true;
            continue;
        }
        if (region_covers == best_covers && best->verdict == unpack::RepairVerdict::kPartial &&
            region.verdict == unpack::RepairVerdict::kComplete) {
            best = &region;
        }
    }
    return require_cover && !best_covers ? nullptr : best;
}

// The one-shot unpack entry under its internal name: the public
// sheller::unpack_sample signature is defined once, in src/shared/api.cpp, and
// forwards here.
UnpackOutcome unpack_sample_impl(const std::filesystem::path& sample, const UnpackOptions& options)
{
    UnpackOutcome outcome;
    namespace fs = std::filesystem;

    if (options.output.empty()) {
        // Fail before any work: an empty output path would otherwise surface
        // as a cryptic copy_file error at the very end of the pipeline.
        outcome.failure = make_failure(AnalysisFailure::Kind::kCapture,
                                       "unpack output path is required", AnalysisArtifacts{});
        outcome.failure->capture_status = capture::Status::kCaptureFailed;
        return outcome;
    }

    std::error_code ec;
    fs::path work = options.work_dir;
    const bool self_created = work.empty();
    if (self_created) {
        work = generate_work_dir(ec);
        if (ec) {
            outcome.failure =
                make_failure(AnalysisFailure::Kind::kCapture,
                             "cannot create the unpack work directory (" + ec.message() + ")",
                             AnalysisArtifacts{});
            outcome.failure->capture_status = capture::Status::kCaptureFailed;
            return outcome;
        }
    } else {
        fs::create_directories(work, ec);
        if (ec) {
            outcome.failure = make_failure(AnalysisFailure::Kind::kCapture,
                                           "cannot use the requested work directory " +
                                               work.string() + " (" + ec.message() + ")",
                                           AnalysisArtifacts{});
            outcome.failure->capture_status = capture::Status::kCaptureFailed;
            return outcome;
        }
    }
    outcome.work_dir = work;
    const auto dump = work / "dump";
    const auto out_dir = work / "out";

    auto fail = [&](const AnalysisFailure::Kind kind, std::string message,
                    AnalysisArtifacts artifacts,
                    std::optional<engine::SyscallRunFailure> run = std::nullopt,
                    std::optional<capture::Status> capture_status = std::nullopt) {
        // Both artifact shapes are filled: the failure carries what the
        // pipeline produced, and so does the outcome - a host reading either
        // shape sees the same artifacts.
        outcome.artifacts = artifacts;
        outcome.failure =
            make_failure(kind, std::move(message), std::move(artifacts), std::move(run));
        if (capture_status.has_value()) {
            outcome.failure->capture_status = *capture_status;
        }
        // A generated staging directory does not outlive a failed call -
        // batch hosts fail constantly and a leaked directory per failure
        // grows without bound; hosts that want the dump for diagnostics pass
        // an explicit work_dir (never touched by cleanup).
        if (self_created) {
            std::error_code cleanup_ec;
            fs::remove_all(work, cleanup_ec);
        }
        return outcome;
    };

    // The snapshot bytes the run consumes: the capture's output on Windows,
    // the PE-derived craft on the loader route. Repair sources its clean
    // pages from the same bytes.
    std::vector<std::uint8_t> snapshot;
    api::detail::Wiring wiring;
    const bool directory_mode = !options.system_modules_dir.empty();
#ifdef _WIN32
    if (!directory_mode) {
        capture::Options capture_options;
        capture_options.sample_path = sample;
        capture_options.shellcode = options.shellcode;
        const auto captured = capture::run_to_buffer(capture_options, snapshot);
        if (captured.status != capture::Status::kOk) {
            AnalysisArtifacts artifacts;
            artifacts.instrumented = false;
            return fail(AnalysisFailure::Kind::kCapture, captured.detail, std::move(artifacts));
        }
    } else
#endif
    {
        if (!directory_mode && options.synthetic_module_dir.empty()) {
            AnalysisArtifacts artifacts;
            artifacts.instrumented = false;
            return fail(AnalysisFailure::Kind::kCapture,
                        std::string{api::detail::kMissingSyntheticModules}, std::move(artifacts),
                        std::nullopt, capture::Status::kCaptureFailed);
        }
        if (const auto magic = api::detail::peek_pe_magic(sample);
            magic.has_value() && magic.value() == 0x10B) {
            // A host-domain boundary, distinct from the missing-directory
            // failure in wording and status.
            AnalysisArtifacts artifacts;
            artifacts.instrumented = false;
            return fail(AnalysisFailure::Kind::kCapture,
                        std::string{api::detail::kX86SampleUnsupported}, std::move(artifacts),
                        std::nullopt, capture::Status::kNotX64Pe);
        }
        auto container = engine::craft_sample_container(sample, false, options.synthetic_module_dir,
                                                        options.system_modules_dir,
                                                        options.system_modules_fallback);
        if (!container) {
            AnalysisArtifacts artifacts;
            artifacts.instrumented = false;
            return fail(
                AnalysisFailure::Kind::kCapture,
                "sample container construction failed: " +
                    (container.error().detail.empty()
                         ? std::string{engine::rebuild_error_message(container.error().error)}
                         : container.error().detail),
                std::move(artifacts), std::nullopt, capture::Status::kCaptureFailed);
        }
        snapshot = std::move(*container);
        // The container is the analysis subject: the probe (and therefore the
        // behavior tier) now sees the sample and its synthetic module set.
    }
    wiring = api::detail::wire_behavior(snapshot);

    if (!options.save_snapshot.empty()) {
        std::ofstream out(options.save_snapshot, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(snapshot.data()),
                  static_cast<std::streamsize>(snapshot.size()));
        if (!out) {
            AnalysisArtifacts artifacts;
            artifacts.instrumented = false;
            return fail(AnalysisFailure::Kind::kCapture,
                        "snapshot could not be written to " + options.save_snapshot.string(),
                        std::move(artifacts));
        }
    }

    const bool instrumented = wiring.rules != nullptr;
    auto names = instrumented ? api::detail::build_timeline_names(wiring) : TimelineNameTable{};
    api::detail::SemanticCollector collector(names);
    behavior::EventTally tally;
    std::unique_ptr<behavior::EventLedger> ledger;
    if (options.timeline) {
        ledger = std::make_unique<behavior::EventLedger>();
    }

    engine::SyscallRunOptions run;
    // Host-controlled bounds; the defaults keep the UPX-class shape
    // (unbounded instructions, generous wall clock - the dump only fires on
    // a deterministic stop).
    run.max_instructions = options.max_instructions;
    run.xfer_number = options.xfer_number;
    run.esp_stop_goal = options.esp_stop_goal;
    run.timeout_ms = options.timeout_ms;
    run.dump_directory = dump;
#ifndef _WIN32
    run.synthetic_system_modules = true;
    run.synthetic_module_dir = options.synthetic_module_dir;
#endif
    run.system_modules_dir = options.system_modules_dir;
    run.system_modules_fallback = options.system_modules_fallback;
    std::vector<AnalysisModuleSource> module_sources;
    run.module_source_sink = [&module_sources](const std::string_view module,
                                               const std::string_view source) {
        module_sources.push_back({std::string(module), std::string(source)});
    };
    api::detail::EventStream stream(wiring.rules.get(), tally, collector, ledger.get(), {}, 0);
    const engine::FactChannel facts =
        api::detail::install_behavior_sinks(run, stream, instrumented ? &names : nullptr);

    // One execution entry on every host: the container the capture produced
    // or the construction serialized.
    const auto result = engine::detail::run_snapshot_syscalls_with_facts(snapshot, run, facts);
    std::string timeline_error;
    AnalysisArtifacts artifacts = api::detail::assemble_artifacts(
        tally, collector, names, ledger.get(), instrumented,
        instrumented ? std::string{}
                     : "no behavior instrumentation on this route; artifacts are counts only",
        result.has_value() ? std::optional{result.value()} : std::optional{result.error().stats},
        timeline_error);
    artifacts.module_sources = std::move(module_sources);

    // A failed run with a dump still unpacks (the deterministic stops write
    // the dump; the packed payload's post-OEP crash on the synthetic stubs is
    // the documented shape of this corpus). Only a run without a dump is a
    // dead end - the repair stage never starts.
    if (!result.has_value()) {
        const auto& run_failure = result.error();
        if (!fs::exists(dump / "manifest.txt", ec)) {
            return fail(AnalysisFailure::Kind::kRun,
                        std::string{engine::syscall_run_error_message(run_failure.error)} +
                            " (syscalls=" + std::to_string(run_failure.stats.syscalls) +
                            " blocks=" + std::to_string(run_failure.stats.blocks) + ")",
                        std::move(artifacts), run_failure);
        }
        artifacts.note += artifacts.note.empty() ? "" : " ";
        artifacts.note += "run stopped: ";
        artifacts.note += engine::syscall_run_error_message(run_failure.error);
    } else if (!fs::exists(dump / "manifest.txt", ec)) {
        return fail(AnalysisFailure::Kind::kRun, "the run produced no dump to repair",
                    std::move(artifacts));
    }

    // OEP candidates in first-occurrence order from the judgment stream.
    const auto& oep_candidates = artifacts.oep_candidates;
    const auto summary = unpack::repair_dump(snapshot, dump, out_dir, oep_candidates);
    if (!summary.has_value()) {
        return fail(AnalysisFailure::Kind::kRun,
                    "repair failed (" + std::to_string(static_cast<int>(summary.error())) + ")",
                    std::move(artifacts));
    }
    outcome.oep_found = summary->oep_found;
    outcome.oep_va = summary->oep_va;
    outcome.oep_rva = summary->oep_rva;

    // The repair target covers the sample's own image; other written spans
    // (e.g. a fully dumped ntdll) are incidental. Metadata read straight
    // from the executed container's bytes - the repair and the run describe
    // one world. DLL-input containers (v2): the main image is the runner
    // and the sample is the synthesized module - the run stats carry its
    // runtime base, and that anchors the selection instead.
    std::ispanstream snapshot_in(std::span<char>{
        reinterpret_cast<char*>(const_cast<std::uint8_t*>(snapshot.data())), snapshot.size()});
    snapshot::Reader snapshot_reader{snapshot_in};
    const auto metadata = snapshot_reader.read_metadata();
    if (!metadata.has_value()) {
        return fail(AnalysisFailure::Kind::kRun, "snapshot metadata unreadable",
                    std::move(artifacts));
    }
    auto image_base_for_selection = metadata->image_base;
    const auto sample_base_for_selection =
        result.has_value() ? result->sample_module_base : result.error().stats.sample_module_base;
    if (sample_base_for_selection != 0) {
        image_base_for_selection = sample_base_for_selection;
    }

    const auto* best = select_unpack_region(summary->regions, image_base_for_selection,
                                            sample_base_for_selection != 0);
    if (best == nullptr) {
        // DLL route: a synthesized sample that produced no repairable region
        // is a distinct, honest failure - an incidental system image must
        // not stand in for it.
        if (sample_base_for_selection != 0) {
            return fail(AnalysisFailure::Kind::kRun,
                        "the sample image produced no repairable region in the dump",
                        std::move(artifacts));
        }
        return fail(AnalysisFailure::Kind::kRun, "no repairable image region in the dump",
                    std::move(artifacts));
    }

    const auto repaired = out_dir / ("repaired_" + hex16(best->base) + ".exe");
    // The verdicts are machine-readable in the outcome; no report file is
    // written. Carried even if the output copy below fails.
    outcome.repair = std::move(*summary);
    fs::copy_file(repaired, options.output, fs::copy_options::overwrite_existing, ec);
    if (ec) {
        return fail(AnalysisFailure::Kind::kRun,
                    "cannot write the unpacked image to " + options.output.string() + " (" +
                        ec.message() + ")",
                    std::move(artifacts));
    }
    outcome.output = options.output;

    if (self_created) {
        fs::remove_all(work, ec);
    }
    outcome.artifacts = std::move(artifacts);
    return outcome;
}

} // namespace api::detail

} // namespace sheller
