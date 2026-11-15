// sheller public analysis facade header - the combined entry points for
// hosts that need one call to run capture -> execution -> behavior analysis
// (or the unpack pipeline) and consume structured artifacts. The facade owns
// the behavior wiring the CLI used to assemble host-side: attribution probe,
// rules, event ledger, name resolution. Artifacts are structured data - the
// library renders no report formats, formatting belongs to the host.
//
// Input routing: the SHELLSNP magic selects snapshot replay vs sample
// analysis. P1 boundaries: the bytes entry accepts snapshot bytes only
// (sample bytes return a capture-class failure - capture and the loader
// take file paths). unpack_sample runs on both hosts, through different
// first steps: capture on Windows, the loader route elsewhere - see its own
// comment.

#ifndef SHELLER_ANALYSIS_H
#define SHELLER_ANALYSIS_H

#include <sheller/capture.h>
#include <sheller/events.h>
#include <sheller/export.h>
#include <sheller/syscallrun.h>
#include <sheller/unpack.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sheller {

// The event-type table every public count array is indexed by: position i is
// EventTypeId value i (kInvalid..kKusdAccess).
inline constexpr std::size_t kAnalysisEventTypeCount = kEventTypeCount;

// One decoded parameter record of a syscall / API-call semantic event. Names
// resolve in-library from the description tables (positional argN past their
// end). Stack-slot records are shallow-stack snapshot values above the
// caller's return address - attribution-only; their name is empty.
struct SemanticParam {
    std::string name{};
    ParamKind kind{};
    bool truncated{};
    std::uint64_t integer{};           // u32 / u64 / ptr / bool / stack-slot value
    std::string text{};                // strA; strW (already UTF-8 at capture)
    std::vector<std::uint8_t> bytes{}; // buf raw bytes; empty otherwise
};

// One semantic event record, in arrival order. The semantic tier covers the
// seven low-volume event types (syscall, apicall, exception, thread-create,
// cpuid, rdtsc, xfer), the default-column forwarded facts (mem-read/mem-write
// produced by sample code accessing a system module) and the low-frequency
// judgment events; window-side types (block-exec, sample-code, smc-execute)
// surface through the ledger window and the host subscription only. Only the
// fields of `type` are populated. Payload budgets follow the engine's 256-byte
// slot budget: a cut payload keeps its record and carries truncated=true
// (never silently dropped).
struct SemanticEvent {
    EventTypeId type{};
    std::uint64_t seq{}; // facade-assigned arrival order, 1-based, gapless
    // The record's ordinal in the whole-run event stream (every event type
    // counted, 1-based) - the join key into the ledger window and the seq
    // every report entry carries. Gapless only by accident; semantic records
    // skip the numbers the window-side events consumed.
    std::uint64_t wire_seq{};
    std::uint32_t tid{};
    std::uint64_t pc{};
    std::uint8_t flags{}; // raw wire flags byte (kEventFlag* bits)
    bool truncated{};     // payload cut at capture (flags bit 2)
    // kSyscall: number + resolved mnemonic; kApiCall: in-band name + module
    std::uint32_t syscall_number{};
    std::string syscall_name{}; // empty when unresolved
    std::string api_name{};
    std::string api_module{}; // resolved module name; empty when unresolved
    // kSyscall / kApiCall call facts
    std::uint32_t status{}; // kSyscall NTSTATUS
    bool success{};         // kSyscall: not rejected; kApiCall: flags bit 0
    std::uint64_t caller_retaddr{};
    std::uint64_t retval{}; // kApiCall
    // kXfer: resolved module!section names of the transfer endpoints
    std::string from_module{};
    std::string from_section{};
    std::string to_module{};
    std::string to_section{};
    // kException
    std::uint32_t exception_code{};
    // kThreadCreate
    std::uint32_t new_tid{};
    std::uint64_t start_routine{};
    // kMemRead / kMemWrite: the forwarded fact's address, width and (read
    // only) value; the judgment types use address/aux/subtype/annotation.
    std::uint64_t address{};
    std::uint32_t access_size{};
    std::uint64_t value{};
    std::uint64_t aux{};
    std::uint32_t subtype{};
    std::string judgment_api{}; // "module!function" annotation, empty when unresolved
    // kSyscall / kApiCall parameter records (stack slots included,
    // kind-tagged); empty for every other type
    std::vector<SemanticParam> params{};
};

// Name tables for the timeline tier's TLV stream: the wire carries module /
// section indexes and syscall numbers; these tables resolve them host-side
// exactly as the in-library renders do. Module indexes in [0xFF00, 0xFFFF]
// are the region-class sentinel segment (private-exec / private-data /
// mapped ride their class, 0xFF00 and 0xFFFF spell "runtime"); out-of-range
// indexes render as "runtime" too.
struct TimelineNameTable {
    std::vector<std::string> modules;               // by module index
    std::vector<std::vector<std::string>> sections; // [module][section]; index 0 is
                                                    // the headers pseudo-section
    std::map<std::uint32_t, std::string> syscalls;  // number -> mnemonic
    // Parameter-name tables keyed "NtCreateFile" (syscall, second hop) and
    // "kernel32!LoadLibraryA" (apicall, module!name). Missing or short
    // entries degrade to positional argN names.
    std::map<std::string, std::vector<std::string>> apicall_params;
    // [base, end) ranges parallel to modules (caller-attribution facts).
    std::vector<std::pair<std::uint64_t, std::uint64_t>> module_ranges;
    // The sample image's own range (base, end). (0, 0) = absent.
    std::pair<std::uint64_t, std::uint64_t> sample_image_range{0, 0};

    static constexpr std::uint16_t kRegionSentinelBase = 0xFF00;
    static constexpr std::uint16_t kRuntimeIndex = 0xFFFF;
};

// Region-class spelling of a sentinel-segment index, by its low nibble
// (1 = private-exec, 2 = private-data, 3 = mapped). The snapshot tier
// (0xFF0x) and the runtime tier (0xFF1x) render the same name - only the
// engine's runtime-registered flag tells the tiers apart. Anything else in the
// segment (unclassified 0xFF00, the legacy 0xFFFF) falls back to "runtime".
inline std::string_view region_class_name(const std::uint16_t index)
{
    switch (index & 0x0Fu) {
    case 0x1:
        return "private-exec";
    case 0x2:
        return "private-data";
    case 0x3:
        return "mapped";
    default:
        return "runtime";
    }
}

// Attribution over a name table: the single implementation behind both the
// artifacts the library fills (SemanticEvent::from_module / to_module /
// api_module, StubCall::module_name) and whatever a host renders from the
// timeline tier, so the two tiers cannot name the same event differently.
// Indexes below the sentinel segment resolve against the module table;
// 0xFFFF and out-of-range indexes mean "no module owner" and spell "runtime"
// (the region unpacked payloads land in). A resolved index returns the table's
// own entry verbatim, so the spelling is empty only if the table carries an
// empty module name.
inline std::string module_name_of(const TimelineNameTable& names, const std::uint16_t index)
{
    if (index >= TimelineNameTable::kRegionSentinelBase) {
        return std::string{region_class_name(index)};
    }
    if (index != TimelineNameTable::kRuntimeIndex && index < names.modules.size()) {
        return names.modules[index];
    }
    return "runtime";
}

// The `module!section` composite of an xfer endpoint. A sentinel-segment
// module renders bare - the region class is the whole attribution, whatever
// the section slot carries. Index 0 of the section list is the headers
// pseudo-section; an unresolvable section spells "runtime".
inline std::string section_name_of(const TimelineNameTable& names, const std::uint16_t module_index,
                                   const std::uint16_t section_index)
{
    if (module_index >= TimelineNameTable::kRegionSentinelBase) {
        return std::string{region_class_name(module_index)};
    }
    if (module_index == TimelineNameTable::kRuntimeIndex || module_index >= names.modules.size()) {
        return "runtime";
    }
    std::string name = names.modules[module_index];
    name += "!";
    if (section_index != TimelineNameTable::kRuntimeIndex && module_index < names.sections.size() &&
        section_index < names.sections[module_index].size()) {
        name += names.sections[module_index][section_index];
    } else {
        name += "runtime";
    }
    return name;
}

// One entry of the stub-call side table (deterministic-stub export calls).
struct StubCall {
    std::uint16_t module{}; // module index as carried on the side table
    // Resolved through the run's name table and never empty: a region
    // sentinel spells its class (private-exec / private-data / mapped) and an
    // out-of-range index spells "runtime" - the same spellings the timeline
    // and report renders use, so the report's "module!name" keys stay shaped.
    std::string module_name{};
    std::string name{};
    std::uint64_t count{};
};

// One row of the module source table: where a
// resident system module's bytes came from. Empty on routes that never
// build a loader world.
struct AnalysisModuleSource {
    std::string module{}; // folded name with extension
    // "directory-derived" (boundary pair under the committed manifest),
    // "directory-real-bytes" (the directory DLL's own bytes),
    // "fallback-synthetic" (directory mode + fallback closure member),
    // "synthetic" (the synthetic route), "host-system" (host System32).
    std::string source{};
};

// Analysis artifacts: the same structure rides success and failure (a failed
// run still carries what it produced). Counts are whole-run exact values -
// they accumulate outside the timeline's ring, so a lossy (evicted) timeline
// never distorts them.
struct AnalysisArtifacts {
    // Whether the instrumentation actually installed this run. An
    // attribution-probe failure keeps the run going but everything stays
    // empty; hosts MUST read "clean sample" only when this is true.
    bool instrumented{};
    // Human-readable condition notes (e.g. the un-instrumented explanation
    // on a probe failure); empty on a fully instrumented run.
    std::string note{};
    // Run statistics, including the xfer count and the xfer-stop flag;
    // nullopt when the run never started (capture / snapshot-IO failures),
    // partial values ride run failures.
    std::optional<engine::SyscallRunStats> run_stats{};
    // Semantic tier: seq-ordered records, no count cap (never evicted).
    std::vector<SemanticEvent> semantic_events{};
    // Semantic-type events whose payload failed to decode: dropped from the
    // records and counted here (symmetric with timeline_dropped), so the
    // gap against the whole-run event_counts stays observable.
    std::uint64_t semantic_dropped{};
    // OEP candidates in first-occurrence order (guest VAs), taken from the
    // oep-candidate judgment events in the semantic stream.
    std::vector<std::uint64_t> oep_candidates{};
    // Whole-run per-type counts, exact regardless of ledger eviction.
    std::array<std::uint64_t, kAnalysisEventTypeCount> event_counts{};
    // Stub-call side-table snapshot.
    std::vector<StubCall> stub_calls{};
    // The module source table: one row per resident system module,
    // delivered before the first instruction executes (present even on a
    // run that later failed).
    std::vector<AnalysisModuleSource> module_sources{};
    // Window tier (only with AnalysisOptions::timeline): the ledger's
    // retention window re-encoded as concatenated TLV events (the guest
    // contract wire format). Lossy: the ledger is a fixed-capacity ring, so
    // events beyond the window are gone - dropped/truncated below make the
    // loss observable. Empty unless the tier was requested (the raw wire
    // tier works with or without the behavior report; the name tables only
    // resolve when the behavior tier probed modules).
    std::vector<std::uint8_t> timeline_tlv{};
    TimelineNameTable timeline_names{};
    std::uint64_t timeline_dropped{};   // events evicted by the full ring
    std::uint64_t timeline_truncated{}; // events cut by the slot cap
};

// Tagged analysis failure. Capture-class failures carry the capture state
// code (and no run statistics); run-class failures carry the raw engine
// failure with its partial statistics; artifacts ride either way.
struct AnalysisFailure {
    enum class Kind : std::uint8_t {
        kCapture,    // the sample never became a snapshot (or the bytes
                     // entry got non-snapshot bytes, or a forced routing
                     // contradicted the input)
        kSnapshotIo, // a snapshot file could not be read, or the bytes did
                     // not validate as a snapshot container
        kRun,        // execution (or post-run artifact production) failed
    };
    Kind kind{};
    // kCapture: the capture stage's state code (kCaptureFailed for the
    // synthetic capture-class refusals: sample bytes on P1, forced routing
    // mismatch, non-Windows unpack).
    capture::Status capture_status{};
    // kRun: the engine's failure - raw error code plus partial statistics.
    std::optional<engine::SyscallRunFailure> run{};
    // Pre-rendered human-readable explanation.
    std::string message{};
    // What the pipeline produced before failing - the success structure.
    AnalysisArtifacts artifacts{};
};

// Input routing override: kAuto routes on the SHELLSNP magic, kSnapshot
// forces the replay route, kSample forces capture (Windows) / the loader
// route (other hosts). A forced sample routing on snapshot input fails with
// a capture-class error rather than being second-guessed.
enum class AnalysisInputKind : std::uint8_t {
    kAuto = 0,
    kSnapshot,
    kSample,
};

struct AnalysisOptions {
    // Engine run options passed through: budgets, the xfer stop ordinal,
    // timeout, dump directory, reject overrides, fidelity dispatch, synthetic
    // module directory, diagnostics, thread slicing. Two public slots are
    // facade-owned and host settings on them are ignored: event_sink and
    // stub_sink complete the internal wiring (rules, tally, ledger, semantic
    // tier). The engine-to-rules
    // fact channel rides beside the options as an internal type
    // (src/engine/behavior_fact.h), so it has no public slot at all; host event
    // subscription goes through event_observer below.
    engine::SyscallRunOptions run{};
    // Behavior report tier: the attribution probe, the rules layer and the
    // whole-run counts. On by default - the structured judgment stream is the
    // facade's product. Off = a deliberately un-instrumented cheap run: no
    // probe, no monitored windows, empty semantic events / counts
    // (instrumented=false, with a note saying the host opted out); the
    // window tier and the host observer stay available.
    bool behavior_report{true};
    // Window tier (lossy ledger window as TLV + name tables + loss
    // counters), lit only by the full event level. Off by default; when off,
    // no event ledger is built.
    bool timeline{false};
    // Input routing, see AnalysisInputKind.
    AnalysisInputKind input_kind{AnalysisInputKind::kAuto};
    // Explicit snapshot save path: sample pass-through writes the captured
    // snapshot here (the capture's exact bytes). Empty = nothing lands on
    // disk the host did not ask for.
    std::filesystem::path save_snapshot;
    // Host subscription mask: bit i selects EventTypeId value i; events of
    // types whose bit is clear never invoke the callback (zero crossings),
    // and event types beyond bit 63 cannot be addressed (their bits are
    // ignored). 0 selects nothing.
    std::uint64_t event_type_mask{};
    // Host event observer, teed with the facade's internal wiring (the two
    // never displace each other). Runs on the engine's hook hot path: do not
    // allocate, do no IO, do not block, do not throw - the facade catches a
    // throwing callback so a violated contract cannot change the run's verdict
    // or unwind into the host's own frame, but the run pays for that catch only
    // when a throw actually happens. The engine's frames carry unwind info (the
    // no-throw rule there is a source-level gate, not -fno-exceptions), so the
    // catch is what keeps the throw from reaching the host's call site.
    std::function<void(EventTypeId type, const EventPreamble& preamble,
                       std::span<const std::uint8_t> type_fields)>
        event_observer;
};

// Combined analysis of a snapshot or sample file. Snapshot input replays;
// sample input captures (Windows) or loader-runs (other hosts). Guest output
// (NtWriteFile bytes) is discarded unless the host sets run.write_sink: the
// library writes no host standard stream at any level, so a host that wants the
// guest's bytes on stdout has to forward them itself - which is what the CLI's
// --guest-stdout does.
SHELLER_API std::expected<AnalysisArtifacts, AnalysisFailure>
analyze(const std::filesystem::path& input, const AnalysisOptions& options);

// Same analysis from memory: snapshot bytes only - non-snapshot bytes
// return a capture-class failure (sample bytes need a capture/loader bytes
// entry, which this entry does not provide).
SHELLER_API std::expected<AnalysisArtifacts, AnalysisFailure>
analyze(const std::vector<std::uint8_t>& input, const AnalysisOptions& options);

struct UnpackOptions {
    // Where the unpacked image lands (required; the only file the pipeline
    // writes outside the work directory).
    std::filesystem::path output;
    // Working directory for the dump/repair intermediates. Empty = the
    // library generates a process-unique directory, returns it in
    // UnpackOutcome::work_dir, and removes it when the call ends (success
    // or failure - pass an explicit directory to keep failure diagnostics;
    // host-supplied directories are never removed).
    std::filesystem::path work_dir;
    // Treat the input as a bare shellcode blob (wrapped into a minimal PE
    // before the standard capture route).
    bool shellcode{false};
    // Instruction budget for the unpack run. The UPX-class default is
    // unlimited: the stubs decompress several million blocks, and a budget
    // stop mid-decompression leaves a useless dump. 0 = unlimited.
    std::uint64_t max_instructions{0};
    // Execution-transfer stop (1-based; 0 = off). On a hit the run stops
    // before the landing block executes and dump/repair continue as a
    // successful stop. Not an event-stream seq.
    std::uint64_t xfer_number{0};
    // ESP-law stop target (--stop esp / --stop esp+xfer), same family as
    // xfer_number: a hit is a successful stop and dump/repair continue; a
    // sample that never restores its entry stack is a silent miss.
    engine::EspStopGoal esp_stop_goal{engine::EspStopGoal::kNone};
    // Wall-clock bound for the unpack run, in milliseconds. A timeout expiry
    // writes no dump, which surfaces as a run failure naming the timeout
    // (the dump fires on the deterministic stops only). 0 = unbounded.
    std::uint32_t timeout_ms{600000};
    // Window tier for the underlying run: the ledger's retention window as
    // TLV plus loss counters in the outcome artifacts. Off by default; the
    // CLI lights it for the full event level (window-side types join the
    // report detail). The field name is historical and implies no companion
    // files.
    bool timeline{false};
    // Explicit snapshot save path (Windows capture route): the captured
    // snapshot bytes are written here, exactly the bytes the run consumed.
    // Empty = no intermediate snapshot file exists.
    std::filesystem::path save_snapshot;
    // Synthetic system module directory for the non-Windows loader route
    // (the deterministic DLLs generated by tools/gen_synth_modules.py).
    // Required for loader-route unpacks - the run maps them instead of the
    // host's real system DLLs; ignored on the Windows capture route.
    std::filesystem::path synthetic_module_dir;
    // Directory-mode system modules: the
    // resident set comes strictly from this directory (boundary pair
    // derived, everything else real bytes); the synthetic directory serves
    // only the explicit fallback. On every host, directory-mode unpacks
    // construct their world instead of capturing a native process.
    std::filesystem::path system_modules_dir;
    bool system_modules_fallback{false};
};

struct UnpackOutcome {
    // The directory used: the echoed UnpackOptions::work_dir, or the
    // generated unique one (removed when the call ends if it was generated).
    std::filesystem::path work_dir;
    // The written unpacked image; empty when the pipeline failed earlier.
    std::filesystem::path output;
    // OEP stamped into the written image (first OEP candidate inside the
    // selected repair region).
    bool oep_found{};
    std::uint64_t oep_va{};
    std::uint32_t oep_rva{};
    // Behavior artifacts from the underlying run - the same structure the
    // failure carries; both are filled (a host reading either shape sees
    // the produced artifacts).
    AnalysisArtifacts artifacts{};
    // Structured repair verdicts (per-region three-state conclusion, thunk
    // lists, OEP application). The machine-readable truth - no report file
    // exists. nullopt when the pipeline never reached the repair stage.
    std::optional<unpack::RepairSummary> repair{};
    // Failure of the pipeline; nullopt on success.
    std::optional<AnalysisFailure> failure{};
};

// One-shot unpack: capture -> run with dump -> engine-native IAT repair ->
// target-region selection -> write the requested artifacts.
// Only explicitly requested paths are written. The first step is host-specific:
// a Windows host captures the running sample, while other hosts take the loader
// route over the PE file itself (run_pe_file, with synthetic system modules
// mapped for the run). The loader route's fidelity boundary is the repair, and
// its cause is the crafted snapshot rather than those modules: the snapshot the
// repair reads carries no loader module list, so the module images its export
// resolution walks are not there - thunks stay uncovered and the verdict comes
// back partial. Same entry, same artifacts, two routes; the returned
// `repair` field says which one ran.
SHELLER_API UnpackOutcome unpack_sample(const std::filesystem::path& sample,
                                        const UnpackOptions& options);

} // namespace sheller

#endif // SHELLER_ANALYSIS_H
