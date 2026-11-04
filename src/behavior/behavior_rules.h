// Behavior rules: turns the pure-data facts and events crossing the engine
// seam into judgment events. The layer never touches unicorn - facts arrive
// as fixed-size values - and the synthesis is a deterministic function of the
// fact/event order, so the same snapshot replays the same judgment stream.
// Judgments are events now: every pattern hit is emitted through the installed
// emitter, one event per hit, no dedupe and no capacity cap (the ledger ring
// is the only window, and it never carries the low-frequency judgments).

#ifndef SHELLER_BEHAVIOR_BEHAVIOR_RULES_H
#define SHELLER_BEHAVIOR_BEHAVIOR_RULES_H

#include <sheller/events.h>

#include "../engine/behavior_fact.h"  // BehaviorFact: the internal fact seam
#include "../engine/mem_region_map.h" // mem_region::ModuleRecord (read-only)

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sheller::behavior {

// The engine's attribution map lives under sheller::engine::mem_region; the
// alias keeps the parameter spellings short without dragging unicorn in.
namespace mem_region = sheller::engine::mem_region;
namespace engine = sheller::engine;

struct BehaviorRulesParams {
    std::uint64_t teb_address{};
    std::uint64_t peb_address{};
    std::uint64_t sample_image_base{};
    std::uint64_t sample_image_size{};
    std::uint64_t ntdll_base{};
    // Resolved NtQueryInformationProcess number (number resolution);
    // 0 disables the query sub-type.
    std::uint32_t query_process_number{};
    // Module records in MemRegionMap index order - the xfer payload's module
    // indexes are indexes into this same order.
    std::vector<mem_region::ModuleRecord> modules;
    // ntdll syscall stub entry addresses, sorted ascending.
    std::vector<std::uint64_t> syscall_entries;
    // Export functions-array slots across all modules, sorted ascending;
    // annotation prebuilt as "module!function".
    struct ExportSlot {
        std::uint64_t slot_va{};
        std::array<char, 96> annotation{};
    };
    std::vector<ExportSlot> export_slots;
    // Exact function-entry annotations ("module!function"), sorted ascending
    // by function_va: the attribution table for entry-arrival signals (the
    // probe-api call, the exception-handler install, the staged exception
    // handler all land on a function's first byte, not on an export-table
    // slot).
    std::vector<ExportSlot> function_entries;
    // Debugger-probe API entry addresses (CheckRemoteDebuggerPresent,
    // IsDebuggerPresent, NtQueryInformationProcess, ...), resolved by the
    // CLI from export names, sorted ascending. A block-exec landing on one
    // directly after a transfer out of sample territory - the sample image
    // or a runtime-registered payload region (xfer from-sentinel 0xFF1x) -
    // is the sample calling the probe itself; probes reached through system
    // machinery (CRT internals, WER crash reporting) enter from system-side
    // xfers and stay silent.
    std::vector<std::uint64_t> probe_api_entries;
    // Exception-registration API entry addresses (RtlAddVectoredExceptionHandler,
    // RtlAddVectoredContinueHandler, SetUnhandledExceptionFilter,
    // RtlAddFunctionTable, RtlInstallFunctionTableCallback), resolved and
    // sorted the same way. The same xfer-arm attribution: a registration
    // entered straight from sample territory (sample image or runtime-
    // registered region) is the sample installing its own handler;
    // system-machinery registrations stay silent.
    std::vector<std::uint64_t> exception_handler_api_entries;
    // rdtsc-burst window (blocks) and threshold (events); overridable for tests.
    std::uint64_t rdtsc_window_blocks{100000};
    std::uint32_t rdtsc_burst_threshold{64};
};

class BehaviorRules {
  public:
    // Emits one judgment event: the type, its preamble (pc/tid; seq is filled
    // by the wiring cursor at emit time) and the judgment wire payload.
    using EventEmitter =
        std::function<void(EventTypeId, const EventPreamble&, std::span<const std::uint8_t>)>;

    explicit BehaviorRules(BehaviorRulesParams params);

    // The wiring installs the emitter after the final move of its owner; a
    // rule set without one records nothing (direct-construction tests install
    // a collector).
    void set_event_emitter(EventEmitter emitter);

    // Seam inputs, called from the engine hooks and the event sink path.
    void on_fact(const engine::BehaviorFact& fact);
    void on_event(EventTypeId type, const EventPreamble& preamble,
                  std::span<const std::uint8_t> fields);

  private:
    // Builds the judgment payload and hands it to the emitter. tid is the
    // triggering event's thread, or 0 when the trigger is a fact (the fact
    // seam carries no tid).
    void emit(EventTypeId type, std::uint64_t pc, std::uint64_t address, std::uint64_t aux,
              std::uint32_t subtype, std::string_view api, std::uint32_t tid);
    void on_mem_read(const engine::BehaviorFact& fact);
    void on_mem_write(const engine::BehaviorFact& fact);
    void on_code(const engine::BehaviorFact& fact);
    void on_protect(const engine::BehaviorFact& fact);

    BehaviorRulesParams params_{};
    EventEmitter emitter_;
    // OEP: target pages already reported as OEP candidates.
    std::set<std::uint64_t> oep_pages_;

    // PEB walk: armed by the TEB self-pointer read, fired by the PEB Ldr read.
    bool peb_armed_{};
    // GetPC: armed by `call $+5` / `fnstenv`, fired by the matching follower.
    std::uint64_t callpop_pc_{}; // 0 = disarmed; holds the call's rip
    std::uint64_t fnstenv_countdown_{};
    // rdtsc burst window.
    std::uint64_t window_blocks_{};
    std::uint32_t window_rdtsc_{};
    // entry-arrival arming (probe-api call, exception-handler install): the previous
    // block-exec's territory - a landing on a probe/handler API entry right
    // after a sample-side block (sample image or a sample-side execution
    // window) is the sample calling the API. Read from the block stream
    // directly: the narrowed xfer edge rules no longer fire for
    // sample->system-module calls.
    bool last_block_sample_{};
    std::uint32_t last_block_tid_{};
    bool last_block_valid_{};
    // SMC: pages first-touched this run -> first write pc.
    std::map<std::uint64_t, std::uint64_t> new_dirty_pages_;
    // W+X sequence tracking: page base -> last requested protection.
    std::map<std::uint64_t, std::uint32_t> page_protection_;
    // Runtime execution windows (base -> end): RWX allocations and pages
    // flipped W->X this run. Syscall pcs landing inside one classify as the
    // shellcode's own direct syscalls.
    std::map<std::uint64_t, std::uint64_t> exec_windows_;
};

} // namespace sheller::behavior

#endif // SHELLER_BEHAVIOR_BEHAVIOR_RULES_H
