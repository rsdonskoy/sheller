// Internal shared wiring for the analysis facade.
// Builds attribution-probe output into behavior rules and timeline names.
// Provides the semantic-tier collector as an independent event_sink tap
// that does not pass through the ledger ring.
// Re-encodes the ledger retention window as TLV and installs the
// facade-owned sink tee.
// Internal on purpose: the shipped surface is the public entries defined in
// src/shared/api.cpp. The only includers outside src/api are test binaries
// that link the static core directly, which is also why the internal names
// below carry no product names.

#ifndef SHELLER_API_WIRING_H
#define SHELLER_API_WIRING_H

#include <sheller/analysis.h>
#include <sheller/events.h>
#include <sheller/unpack.h>

#include "../behavior/api_descriptions.h"
#include "../behavior/behavior_rules.h"
#include "../behavior/event_ledger.h"
#include "../behavior/report_events.h"
#include "../engine/behavior_fact.h"
#include "../engine/mem_region_map.h"
#include "../engine/rebuild_probe.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sheller::api::detail {

// DLL outputs must cover the runtime sample base; EXE keeps its fallback.
const unpack::RegionRepairReport*
select_unpack_region(std::span<const unpack::RegionRepairReport> regions, std::uint64_t image_base,
                     bool require_cover);

// Non-Windows sample route (construct container + replay) shared failure
// text: the two conditions are distinct on purpose, in wording and in
// capture status.
inline constexpr std::string_view kMissingSyntheticModules =
    "synthetic system modules not found (looked next to the executable); build with "
    "synth_modules enabled";
inline constexpr std::string_view kX86SampleUnsupported =
    "this host does not support 32-bit sample input (PE32); 32-bit container "
    "replay is not supported in this build";

// Optional-header magic (0x10B PE32 / 0x20B PE32+) of a readable PE file;
// nullopt for unreadable or non-PE input (the construction stage names the
// precise error then).
std::optional<std::uint16_t> peek_pe_magic(const std::filesystem::path& path);

// The three facade entries under their internal names: the public
// analyze()/unpack_sample() signatures are defined only by the shared
// interface library in src/shared/api.cpp, which forwards here. A consumer
// that links the static core directly - the facade test suites - calls
// these instead of the product names.
std::expected<AnalysisArtifacts, AnalysisFailure>
analyze_path_impl(const std::filesystem::path& input, const AnalysisOptions& options);

std::expected<AnalysisArtifacts, AnalysisFailure>
analyze_bytes_impl(const std::vector<std::uint8_t>& input, const AnalysisOptions& options);

UnpackOutcome unpack_sample_impl(const std::filesystem::path& sample, const UnpackOptions& options);

// Probe -> params/rules. Null rules means the attribution probe failed;
// the run proceeds un-instrumented (the facade reports success with empty
// artifacts and instrumented=false).
struct Wiring {
    behavior::BehaviorRulesParams params;
    std::unique_ptr<behavior::BehaviorRules> rules;
    std::vector<engine::mem_region::ModuleImage> images;
    std::vector<engine::mem_region::ModuleImage> unknown_images;
    std::vector<syscalls::SyscallNumberEntry> syscall_numbers;
};

// Probe -> params/rules. Resolves per SnapshotT against
// attribute_snapshot_modules' path and bytes overloads, so file inputs
// stream through the engine instead of materializing the whole snapshot in
// memory. Null rules means the attribution probe failed; the run proceeds
// un-instrumented (the facade reports success with empty artifacts and
// instrumented=false).
template <typename SnapshotT> Wiring wire_behavior(const SnapshotT& snapshot)
{
    Wiring wiring;
    const auto probe = engine::detail::attribute_snapshot_modules(snapshot);
    if (!probe.has_value()) {
        return wiring; // rules stay null: the run proceeds un-instrumented
    }
    auto& params = wiring.params;
    params.teb_address = probe->teb_address;
    params.peb_address = probe->peb_address;
    params.sample_image_base = probe->image_base;
    params.sample_image_size = probe->image_size;
    wiring.images = probe->images;
    wiring.unknown_images = probe->unknown_images;
    wiring.syscall_numbers = probe->syscall_numbers;
    for (const auto& image : probe->images) {
        params.modules.push_back(image.module);
        if (std::string_view(image.module.name.data()) == "ntdll.dll") {
            params.ntdll_base = image.module.base;
        }
    }
    for (const auto& entry : probe->syscall_numbers) {
        if (std::string_view(entry.name.data()) == "NtQueryInformationProcess") {
            params.query_process_number = entry.number;
        }
    }
    // ntdll stub entries: Nt-prefixed export function addresses.
    for (const auto& slot : probe->export_slots) {
        if (slot.module_base != params.ntdll_base) {
            continue;
        }
        if (std::string_view(slot.name.data()).starts_with("Nt")) {
            params.syscall_entries.push_back(slot.function_va);
        }
    }
    std::ranges::sort(params.syscall_entries);
    // Debugger-probe API entries: a block-exec landing on one directly after
    // a sample-image xfer is the sample calling the probe itself. Probes
    // reached through system machinery (CRT internals, WER crash reporting)
    // enter from system-side transfers and stay silent.
    for (const auto& slot : probe->export_slots) {
        const std::string_view name{slot.name.data()};
        if (name == "CheckRemoteDebuggerPresent" || name == "IsDebuggerPresent" ||
            name == "NtQueryInformationProcess" || name == "RtlQueryProcessDebugInformation") {
            params.probe_api_entries.push_back(slot.function_va);
        }
    }
    std::ranges::sort(params.probe_api_entries);
    params.probe_api_entries.erase(
        std::unique(params.probe_api_entries.begin(), params.probe_api_entries.end()),
        params.probe_api_entries.end());
    // Exception-registration API entries: the same xfer-arm attribution as
    // the probe list - an entry reached straight from a sample-side xfer is
    // the sample installing its own handler; CRT/WER machinery stays silent.
    for (const auto& slot : probe->export_slots) {
        const std::string_view name{slot.name.data()};
        if (name == "RtlAddVectoredExceptionHandler" || name == "RtlAddVectoredContinueHandler" ||
            name == "SetUnhandledExceptionFilter" || name == "RtlAddFunctionTable" ||
            name == "RtlInstallFunctionTableCallback") {
            params.exception_handler_api_entries.push_back(slot.function_va);
        }
    }
    std::ranges::sort(params.exception_handler_api_entries);
    params.exception_handler_api_entries.erase(
        std::unique(params.exception_handler_api_entries.begin(),
                    params.exception_handler_api_entries.end()),
        params.exception_handler_api_entries.end());
    // export-walk slots with the folded "module!function" annotation.
    const auto module_name = [&](const std::uint64_t base) -> std::string_view {
        for (const auto& module : params.modules) {
            if (module.base == base) {
                return std::string_view(module.name.data());
            }
        }
        return {};
    };
    for (const auto& slot : probe->export_slots) {
        behavior::BehaviorRulesParams::ExportSlot entry;
        entry.slot_va = slot.slot_va;
        std::string annotation{module_name(slot.module_base)};
        annotation += '!';
        annotation += std::string_view(slot.name.data());
        annotation.resize(std::min(annotation.size(), entry.annotation.size() - 1));
        std::ranges::copy(annotation, entry.annotation.begin());
        wiring.params.export_slots.push_back(entry);
        // the same annotation keyed by the function's own entry address for
        // the entry-arrival signals (probe-api call, exception-handler
        // install, staged exception handler)
        behavior::BehaviorRulesParams::ExportSlot function_entry;
        function_entry.slot_va = slot.function_va;
        std::ranges::copy(annotation, function_entry.annotation.begin());
        wiring.params.function_entries.push_back(function_entry);
    }
    std::ranges::sort(wiring.params.export_slots, std::ranges::less{},
                      &behavior::BehaviorRulesParams::ExportSlot::slot_va);
    std::ranges::sort(wiring.params.function_entries, std::ranges::less{},
                      &behavior::BehaviorRulesParams::ExportSlot::slot_va);
    wiring.rules = std::make_unique<behavior::BehaviorRules>(wiring.params);
    return wiring;
}

// Module/section/syscall/parameter name tables for the renders and the
// semantic resolution.
TimelineNameTable build_timeline_names(const Wiring& wiring);
void register_module_names(TimelineNameTable& names, std::size_t module_index,
                           const engine::mem_region::ModuleImage& image);

// Semantic-tier collector: a straight event_sink tap into
// std::vector<SemanticEvent> - no count cap, the ledger ring is never
// involved. It accepts the default-column types (the seven semantic types,
// mem-read/mem-write and the low-frequency judgments); window-side types
// (block-exec, sample-code, smc-execute) are skipped here and belong to the
// ledger window and the host subscription only. A semantic-type event whose
// payload fails to decode is dropped and counted in dropped().
class SemanticCollector {
  public:
    explicit SemanticCollector(const TimelineNameTable& names) : names_(names)
    {
    }

    void on_event(EventTypeId type, const EventPreamble& preamble,
                  std::span<const std::uint8_t> fields);

    std::vector<SemanticEvent> take()
    {
        return std::move(events_);
    }

    // Semantic-type events whose payload failed to decode: dropped from the
    // records and counted here, symmetric with the ledger's dropped() -
    // the counts tier stays whole-run exact, so the gap stays observable.
    std::uint64_t dropped() const
    {
        return dropped_;
    }

  private:
    // A default-detail mem access entry is the sample touching a system
    // module: the target must lie inside a loaded module other than the sample
    // image. For mem-write the payload's writer flag must also mark sample
    // code (the sample image or a private-executable region); mem-read facts
    // already cross the seam only for sample-side readers. Sample/stack/heap/
    // private-exec targets stay counts-only.
    [[nodiscard]] bool is_system_module_address(std::uint64_t address) const;

    // Names outlive the collector by construction (both are run-scope
    // locals of the callers, names declared first).
    const TimelineNameTable& names_;
    std::vector<SemanticEvent> events_;
    std::uint64_t next_seq_{1};
    std::uint64_t dropped_{};
};

// Timeline tier: the ledger's retention window re-encoded in memory
// with the public encode_event (the wire's single source of truth). The
// ledger gains no memory-export API - this walks entry(i) like any reader.
std::expected<std::vector<std::uint8_t>, std::string>
encode_timeline_tlv(const behavior::EventLedger& ledger);

// The facade-owned event stream tee: one whole-run cursor, one dispatch
// order. Every engine event takes its number here, reaches rules -> tally ->
// semantic collector -> ledger -> host observer, and the judgments the rules
// emitted during that dispatch then drain into the same tiers. The drain never
// re-enters rules->on_event (forwarding and judgments are not rule inputs).
//
// Window facts forward through a dedicated path: the fact's own event
// (mem-read / mem-write / sample-code) takes its number and reaches
// tally/collector/ledger/observer without entering the rules layer. The event
// precedes the judgments the same fact triggers, so a judgment is always
// numbered after its cause.
class EventStream {
  public:
    EventStream(
        behavior::BehaviorRules* rules, behavior::EventTally& tally, SemanticCollector& collector,
        behavior::EventLedger* ledger,
        std::function<void(EventTypeId, const EventPreamble&, std::span<const std::uint8_t>)>
            observer,
        std::uint64_t event_type_mask);

    // Engine event sink: numbers the event, runs the rules (which may queue
    // judgments), delivers the event, then drains the queue in emit order.
    void on_engine_event(EventTypeId type, const EventPreamble& preamble,
                         std::span<const std::uint8_t> fields);

    // Behavior fact sink: forwards the window fact as its event, lets the
    // rules consume the fact, then drains the judgments it emitted.
    void on_behavior_fact(const engine::BehaviorFact& fact);

    // Stub-call side table (run-end drain from the engine).
    void on_stub_call(std::uint16_t module, std::string_view name, std::uint64_t count);

    [[nodiscard]] bool has_rules() const
    {
        return rules_ != nullptr;
    }
    // No rules, no ledger, no observer: nothing would record, the engine
    // registers no hooks.
    [[nodiscard]] bool active() const
    {
        return rules_ != nullptr || ledger_ != nullptr || static_cast<bool>(observer_);
    }

  private:
    struct PendingEvent {
        EventTypeId type{};
        EventPreamble preamble{};
        std::array<std::uint8_t, behavior::kMaxEventFields> fields{};
        std::uint16_t field_count{};
    };

    void deliver(EventTypeId type, const EventPreamble& preamble,
                 std::span<const std::uint8_t> fields);
    void queue_judgment(EventTypeId type, const EventPreamble& preamble,
                        std::span<const std::uint8_t> fields);
    void drain();
    void forward_mem_fact(const engine::BehaviorFact& fact, EventTypeId type);
    void forward_code_fact(const engine::BehaviorFact& fact);

    behavior::BehaviorRules* rules_;
    behavior::EventTally& tally_;
    SemanticCollector& collector_;
    behavior::EventLedger* ledger_;
    std::function<void(EventTypeId, const EventPreamble&, std::span<const std::uint8_t>)> observer_;
    std::uint64_t event_type_mask_;
    // The one whole-run sequence cursor: engine events, forwarded facts and
    // judgment events consume it in arrival order.
    std::uint64_t next_seq_{1};
    // Judgments emitted during the current dispatch, numbered at emit time
    // and delivered after it. Drained every crossing; the vector keeps its
    // capacity (the queue is empty or short between dispatches).
    std::vector<PendingEvent> pending_;
};

// Installs the stream's callbacks on the run's two public sink slots (event,
// stub) and returns the fact channel to hand to the engine beside the
// options: the fact seam deliberately has no public slot, so the channel is
// the only way in, and only this wiring builds it. An empty return = the
// engine registers no fact hooks. The host observer rides along behind its
// type mask and throw guard; an un-instrumented run suppresses the internal
// tiers but never the host subscription.
engine::FactChannel install_behavior_sinks(engine::SyscallRunOptions& run, EventStream& stream,
                                           TimelineNameTable* names = nullptr);

// Assembles the artifacts block shared by the success and failure paths
// (failure still carries artifacts). A timeline codec error is reported
// through the out-param and leaves timeline_tlv empty - the caller maps it
// into a kRun failure; a truncated byte stream is never delivered as a
// success artifact.
AnalysisArtifacts assemble_artifacts(behavior::EventTally& tally, SemanticCollector& collector,
                                     const TimelineNameTable& names,
                                     const behavior::EventLedger* ledger, bool instrumented,
                                     std::string note,
                                     std::optional<engine::SyscallRunStats> run_stats,
                                     std::string& timeline_error);

} // namespace sheller::api::detail

#endif // SHELLER_API_WIRING_H
