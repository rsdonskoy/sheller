// The analyze entry points: magic-routed input handling (snapshot replay /
// Windows capture pass-through / loader route), the facade-owned sink
// wiring, and the three-kind failure surface. Filesystem work uses the
// error_code overloads and maps into the failure structure - the facade
// never throws at a host.

#include "wiring.h"

#include "../engine/craft.h"
#include <sheller/capture.h>
#include <sheller/peloader.h>
#include <sheller/rebuild.h>
#include <sheller/snapshot.h>
#include <sheller/syscallrun.h>

#include <array>
#include <cstring>
#include <fstream>
#include <optional>
#include <spanstream>
#include <string>
#include <utility>
#include <vector>

namespace sheller {

namespace {

constexpr std::array<std::uint8_t, 8> kSnapshotMagic = {'S', 'H', 'E', 'L', 'L', 'S', 'N', 'P'};

bool has_snapshot_magic(const std::vector<std::uint8_t>& bytes)
{
    return bytes.size() >= kSnapshotMagic.size() &&
           std::memcmp(bytes.data(), kSnapshotMagic.data(), kSnapshotMagic.size()) == 0;
}

AnalysisFailure capture_failure(const capture::Status status, std::string message,
                                AnalysisArtifacts artifacts = {})
{
    AnalysisFailure failure;
    failure.kind = AnalysisFailure::Kind::kCapture;
    failure.capture_status = status;
    failure.message = std::move(message);
    failure.artifacts = std::move(artifacts);
    return failure;
}

AnalysisFailure snapshot_io_failure(std::string message, AnalysisArtifacts artifacts = {})
{
    AnalysisFailure failure;
    failure.kind = AnalysisFailure::Kind::kSnapshotIo;
    failure.message = std::move(message);
    failure.artifacts = std::move(artifacts);
    return failure;
}

// Peeks the magic of a file input for the auto routing. An unopenable or
// short file reports nullopt and the caller falls through to the sample
// route, whose capture/loader stage names the precise error.
std::optional<bool> peek_is_snapshot(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    std::array<char, 8> head{};
    in.read(head.data(), static_cast<std::streamsize>(head.size()));
    if (!in) {
        return false; // readable but shorter than the magic: not a snapshot
    }
    return std::memcmp(head.data(), kSnapshotMagic.data(), kSnapshotMagic.size()) == 0;
}

std::string probe_failed_note()
{
    return "module attribution probe failed; the run proceeded un-instrumented";
}

std::string behavior_disabled_note()
{
    return "behavior report disabled by the host; the run proceeded un-instrumented";
}

// Wraps assembled artifacts into the failure variants: a timeline codec
// error maps into a kRun failure (never a truncated success artifact); a
// rebuild-stage engine error maps into kSnapshotIo with no run statistics;
// everything else is a kRun failure carrying the raw code and partial stats.
std::expected<AnalysisArtifacts, AnalysisFailure>
finish_run(const engine::SyscallRunFailure* engine_failure, AnalysisArtifacts artifacts,
           std::string timeline_error)
{
    if (!timeline_error.empty()) {
        AnalysisFailure out;
        out.kind = AnalysisFailure::Kind::kRun;
        out.message = timeline_error;
        out.artifacts = std::move(artifacts);
        return std::unexpected(std::move(out));
    }
    if (engine_failure == nullptr) {
        return artifacts;
    }
    switch (engine_failure->error) {
    // The rebuild-stage errors (unreadable / bad format / bitness /
    // inconsistent / unaligned) are snapshot IO failures no matter which
    // entry delivered the bytes - listed explicitly so a future
    // snapshot-class error added to the enum cannot silently masquerade as
    // a run failure.
    case engine::SyscallRunError::kIoFailure:
    case engine::SyscallRunError::kBadSnapshot:
    case engine::SyscallRunError::kBitnessUnsupported:
    case engine::SyscallRunError::kInconsistent:
    case engine::SyscallRunError::kUnalignedRegion: {
        artifacts.run_stats = std::nullopt; // the run never started
        // The engine's named rejection detail (module!reason wording) leads
        // the message when it exists; the enum spelling alone names nothing.
        std::string message = "snapshot rejected: ";
        message += engine::syscall_run_error_message(engine_failure->error);
        if (!engine_failure->detail.empty()) {
            message += ": ";
            message += engine_failure->detail;
        }
        return std::unexpected(snapshot_io_failure(std::move(message), std::move(artifacts)));
    }
    // The container carries synthetic module pages but the replay was given
    // no directory: a capture-class failure, never a silent un-instrumented
    // run.
    case engine::SyscallRunError::kSyntheticModulesMissing:
        artifacts.run_stats = std::nullopt;
        return std::unexpected(capture_failure(capture::Status::kCaptureFailed,
                                               std::string{api::detail::kMissingSyntheticModules},
                                               std::move(artifacts)));
    default:
        break;
    }
    AnalysisFailure out;
    out.kind = AnalysisFailure::Kind::kRun;
    out.run = *engine_failure;
    // The boundary-trap stop carries its named diagnosis in the failure's
    // detail; it leads the message so the report names module!export and
    // the call site, not a bare enum spelling.
    if (!engine_failure->detail.empty()) {
        out.message = engine_failure->detail + " (";
    } else {
        out.message = std::string{engine::syscall_run_error_message(engine_failure->error)} + " (";
    }
    out.message += "syscalls=" + std::to_string(engine_failure->stats.syscalls) +
                   " rejects=" + std::to_string(engine_failure->stats.rejects) +
                   " blocks=" + std::to_string(engine_failure->stats.blocks) + ")";
    out.artifacts = std::move(artifacts);
    return std::unexpected(std::move(out));
}

// The shared snapshot-replay pipeline, generic over the snapshot source:
// a path streams through the engine's own reader (no whole-file buffer -
// the CLI's memory shape), bytes come from the bytes entry or the capture
// route. Behavior tier (probe, wiring, rules) only when the host requested
// it; the raw tiers (timeline, observer) ride either shape.
template <typename SnapshotT>
std::expected<AnalysisArtifacts, AnalysisFailure> run_snapshot(const SnapshotT& input,
                                                               const AnalysisOptions& options)
{
    api::detail::Wiring wiring;
    if (options.behavior_report) {
        wiring = api::detail::wire_behavior(input);
    }
    const bool instrumented = wiring.rules != nullptr;
    auto names = instrumented ? api::detail::build_timeline_names(wiring) : TimelineNameTable{};
    api::detail::SemanticCollector collector(names);
    behavior::EventTally tally;
    // Timeline tier: the raw wire tier works with or without the behavior
    // tier; only the name resolution needs the probe's modules.
    std::unique_ptr<behavior::EventLedger> ledger;
    if (options.timeline) {
        ledger = std::make_unique<behavior::EventLedger>();
    }

    engine::SyscallRunOptions run = options.run;
    // The module source table rides every run: capture rows here (chaining
    // any host-installed sink) and stamp the artifacts with them.
    std::vector<AnalysisModuleSource> module_sources;
    {
        auto host_sink = run.module_source_sink;
        run.module_source_sink = [&module_sources, host_sink](const std::string_view module,
                                                              const std::string_view source) {
            module_sources.push_back({std::string(module), std::string(source)});
            if (host_sink) {
                host_sink(module, source);
            }
        };
    }
    api::detail::EventStream stream(wiring.rules.get(), tally, collector, ledger.get(),
                                    options.event_observer, options.event_type_mask);
    const engine::FactChannel facts =
        api::detail::install_behavior_sinks(run, stream, instrumented ? &names : nullptr);

    std::string note;
    if (!instrumented) {
        note = options.behavior_report ? probe_failed_note() : behavior_disabled_note();
    }
    std::string timeline_error;
    const auto result = engine::detail::run_snapshot_syscalls_with_facts(input, run, facts);
    if (result.has_value()) {
        AnalysisArtifacts artifacts =
            api::detail::assemble_artifacts(tally, collector, names, ledger.get(), instrumented,
                                            std::move(note), result.value(), timeline_error);
        artifacts.module_sources = std::move(module_sources);
        return finish_run(nullptr, std::move(artifacts), std::move(timeline_error));
    }
    AnalysisArtifacts artifacts =
        api::detail::assemble_artifacts(tally, collector, names, ledger.get(), instrumented,
                                        std::move(note), result.error().stats, timeline_error);
    artifacts.module_sources = std::move(module_sources);
    return finish_run(&result.error(), std::move(artifacts), std::move(timeline_error));
}

// The non-Windows sample route: construct the v1 container from the PE and
// the synthetic module directory, then run the same snapshot pipeline the
// Windows capture route uses. The probe, wiring, names and artifacts now come
// from the container, so this route carries the full behavior tier instead of
// the retired zero-signal boundary.
std::expected<AnalysisArtifacts, AnalysisFailure>
run_crafted_sample(const std::filesystem::path& input, const AnalysisOptions& options)
{
    const bool directory_mode = !options.run.system_modules_dir.empty();
    if (!directory_mode && options.run.synthetic_module_dir.empty()) {
        return std::unexpected(capture_failure(capture::Status::kCaptureFailed,
                                               std::string{api::detail::kMissingSyntheticModules}));
    }
    if (const auto magic = api::detail::peek_pe_magic(input);
        magic.has_value() && magic.value() == 0x10B) {
        return std::unexpected(capture_failure(capture::Status::kNotX64Pe,
                                               std::string{api::detail::kX86SampleUnsupported}));
    }
    auto container = engine::craft_sample_container(
        input, options.run.windows_fidelity_dispatch, options.run.synthetic_module_dir,
        options.run.system_modules_dir, options.run.system_modules_fallback);
    if (!container) {
        const auto& failure = container.error();
        return std::unexpected(capture_failure(
            capture::Status::kCaptureFailed,
            "sample container construction failed: " +
                (failure.detail.empty() ? std::string{engine::rebuild_error_message(failure.error)}
                                        : failure.detail)));
    }
    if (!options.save_snapshot.empty()) {
        std::ofstream out(options.save_snapshot, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(container->data()),
                  static_cast<std::streamsize>(container->size()));
        if (!out) {
            return std::unexpected(capture_failure(
                capture::Status::kWriteFailed,
                "constructed container could not be written to " + options.save_snapshot.string()));
        }
    }
    return run_snapshot(*container, options);
}

// Sample route on a Windows host: capture into memory, optionally save the
// snapshot bytes, then the replay pipeline - no intermediate snapshot file
// unless the host asked for one.
#ifdef _WIN32
std::expected<AnalysisArtifacts, AnalysisFailure>
run_sample_windows(const std::filesystem::path& sample, const AnalysisOptions& options)
{
    capture::Options capture_options;
    capture_options.sample_path = sample;
    std::vector<std::uint8_t> snapshot;
    const auto captured = capture::run_to_buffer(capture_options, snapshot);
    if (captured.status != capture::Status::kOk) {
        return std::unexpected(capture_failure(captured.status, captured.detail));
    }
    if (!options.save_snapshot.empty()) {
        std::ofstream out(options.save_snapshot, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(snapshot.data()),
                  static_cast<std::streamsize>(snapshot.size()));
        if (!out) {
            return std::unexpected(capture_failure(capture::Status::kWriteFailed,
                                                   "captured snapshot could not be written to " +
                                                       options.save_snapshot.string()));
        }
    }
    return run_snapshot(snapshot, options);
}
#endif // _WIN32

} // namespace

namespace api::detail {

// The two analyze overloads under their internal names: the public
// sheller::analyze signatures are defined once, in src/shared/api.cpp, and
// forward here - so this library carries no symbol under a product name and a
// direct-link consumer cannot reach one.
std::expected<AnalysisArtifacts, AnalysisFailure>
analyze_path_impl(const std::filesystem::path& input, const AnalysisOptions& options)
{
    switch (options.input_kind) {
    case AnalysisInputKind::kSnapshot:
        // Path-native: the engine's reader streams the file - no whole-file
        // buffer; unreadable/bad files surface as snapshot-class failures.
        return run_snapshot(input, options);
    case AnalysisInputKind::kSample: {
        // Sample routing on snapshot input fails as a capture would: the input
        // is not a sample PE. The wording holds for a host that set the route
        // explicitly and for one that never chose at all.
        const auto magic = peek_is_snapshot(input);
        if (magic.has_value() && magic.value()) {
            return std::unexpected(capture_failure(
                capture::Status::kNotX64Pe,
                "input carries the snapshot magic but sample routing was selected: " +
                    input.string()));
        }
        // Directory-mode system modules construct the world on every host
        // (the capture route cannot express a user-supplied system world).
        if (!options.run.system_modules_dir.empty()) {
            return run_crafted_sample(input, options);
        }
#ifdef _WIN32
        return run_sample_windows(input, options);
#else
        return run_crafted_sample(input, options);
#endif
    }
    case AnalysisInputKind::kAuto:
    default: {
        const auto magic = peek_is_snapshot(input);
        if (magic.has_value() && magic.value()) {
            return run_snapshot(input, options); // streamed, like kSnapshot
        }
        // Not (provably) a snapshot: the sample route names the precise
        // error for unreadable or non-PE inputs. Directory-mode system
        // modules construct the world on every host.
        if (!options.run.system_modules_dir.empty()) {
            return run_crafted_sample(input, options);
        }
#ifdef _WIN32
        return run_sample_windows(input, options);
#else
        return run_crafted_sample(input, options);
#endif
    }
    }
}

std::expected<AnalysisArtifacts, AnalysisFailure>
analyze_bytes_impl(const std::vector<std::uint8_t>& input, const AnalysisOptions& options)
{
    const auto snapshot_magic = has_snapshot_magic(input);
    switch (options.input_kind) {
    case AnalysisInputKind::kSnapshot:
        break; // replay route regardless of magic: the reader validates
    case AnalysisInputKind::kSample:
        return std::unexpected(capture_failure(
            capture::Status::kNotX64Pe,
            snapshot_magic ? "input carries the snapshot magic but sample routing was selected"
                           : "sample bytes are not accepted by this batch (the bytes entry "
                             "takes snapshot bytes only; capture and the loader take paths)"));
    case AnalysisInputKind::kAuto:
    default:
        if (!snapshot_magic) {
            return std::unexpected(capture_failure(
                capture::Status::kCaptureFailed,
                "sample bytes are not accepted by this batch (the bytes entry takes snapshot "
                "bytes only; capture and the loader take paths)"));
        }
        break;
    }
    return run_snapshot(input, options);
}

} // namespace api::detail

} // namespace sheller
