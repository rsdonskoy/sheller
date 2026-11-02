// sheller public engine-run header - syscall-enabled snapshot execution: the
// engine rebuilds a v1 snapshot and runs it with the syscall skeleton
// attached (policy table, default deny, three minimal handlers). Standard
// library only: no unicorn or Windows headers may leak in here; the Unicorn
// instance lives and dies inside the engine.

#ifndef SHELLER_SYSCALLRUN_H
#define SHELLER_SYSCALLRUN_H

#include <sheller/events.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sheller::engine {

using SyscallNumber = std::uint32_t;
using NtStatus = std::uint32_t;

// ESP-law stop goal, the esp members of the stop-target family (--stop esp /
// --stop esp+xfer). kStopAtRestore stops at the confirmed entry-stack-restore
// read; kArmThenNextXfer arms on that read and stops at the next execution
// transfer (the xfer stop face, dump included). The confirmation criteria and
// the window they read in are the engine's (static entry save extent + decode
// + RSP completion check); a sample that never restores its entry stack is a
// silent miss, not an error.
enum class EspStopGoal {
    kNone = 0,
    kStopAtRestore,
    kArmThenNextXfer,
};

struct SyscallRunOptions {
    // Bounded run: either budget exhaustion stops the guest, or a
    // NtTerminateProcess handler does.
    std::uint64_t max_instructions{1000000};
    // Block-count budget: stop deterministically once this
    // many basic blocks executed. 0 = unlimited (existing semantics).
    std::uint64_t max_blocks{0};
    // Execution-transfer stop: stop before the landing block of the
    // 1-based xfer ordinal executes (the xfer event itself is still
    // emitted). 0 = off. This is not an event-stream seq, and it is not
    // guaranteed to be the Nth kXfer event in a report either: transfers
    // speculatively executed by a burn-loop probe emit events but are never
    // counted.
    std::uint64_t xfer_number{0};
    // ESP-law stop target, same family as xfer_number above (the formal
    // spellings are --stop esp / --stop esp+xfer). Never armed inside a
    // burn-loop probe's speculative chunks. kNone = not requested; the
    // default run pays nothing for it.
    EspStopGoal esp_stop_goal{EspStopGoal::kNone};
    std::uint32_t timeout_ms{10000};
    // Per-number rejection-code overrides (rejection
    // codes are data, overridable per number).
    std::map<SyscallNumber, NtStatus> reject_overrides;
    // Exit-time region dump directory: when set, the
    // five deterministic stop kinds write the dirty regions here. Empty =
    // no dump.
    std::filesystem::path dump_directory;
    // Fidelity dispatch mode: the engine-side SEH dispatcher is the default; a
    // true value routes exception dispatch through the real captured ntdll
    // (Windows fidelity mode). Fidelity mode keeps the version-pinned seams alive.
    bool windows_fidelity_dispatch{false};
    // Synthetic system modules: when the directory is set, the loader
    // route maps the generated synthetic system DLLs (deterministic stub
    // bodies + frozen export tables) instead of the host's real ones; the
    // engine's interception layer (heap family, LdrLoadDll) serves them.
    bool synthetic_system_modules{false};
    std::filesystem::path synthetic_module_dir;
    // Directory-mode system modules (change real-dll-module-dir): when set,
    // the resident set comes strictly from this directory - real DLL bytes
    // for every module except the boundary pair (ntdll, win32u), which
    // derives under the committed boundary manifest. The host system
    // directories are never read. With the fallback option on, a closure
    // member the directory lacks falls back to the synthetic directory and
    // is marked in the module source table; with it off, the missing module
    // is a named construction rejection.
    std::filesystem::path system_modules_dir;
    bool system_modules_fallback{false};
    // When a basic block STARTS
    // exactly on one of the watched addresses (e.g. ntdll heap-function
    // entries, or call return sites added mid-run by the harness),
    // diag_entry_hit fires with the pc and the opaque unicorn handle (void*
    // to keep this public header unicorn-free). The harness owns the vector
    // and may grow it (keep sorted - the engine binary-searches); null or
    // empty = zero cost; diagnostic-only, never consulted by engine
    // semantics.
    const std::vector<std::uint64_t>* diag_watch_entries{};
    std::function<void(std::uint64_t entry_pc, void* uc)> diag_entry_hit;
    // A range-scoped UC_HOOK_MEM_WRITE
    // over [diag_write_window_lo, diag_write_window_hi) fires diag_write_hit on
    // EVERY guest store landing in the window - the first-touch ledger hook
    // only sees the first store per page, so a later store stomping a live
    // heap structure is invisible to it. The engine reads the writer rip
    // inside the hook; value carries the stored data for narrow stores
    // (zero-extended; 0 for multi-byte bulk writes). lo == 0 or an empty
    // callback = disabled (no hook registered); diagnostic-only, never
    // consulted by engine semantics.
    std::uint64_t diag_write_window_lo{};
    std::uint64_t diag_write_window_hi{};
    std::function<void(std::uint64_t pc, std::uint64_t addr, std::uint32_t size,
                       std::uint64_t value)>
        diag_write_hit;
    // Diagnostic per-instruction code window: fires diag_code_hit for every
    // instruction executed inside [diag_code_window_lo, diag_code_window_hi)
    // (the engine reads the rip inside the hook). Range-scoped like the write
    // watch; lo == 0 or an empty callback = disabled. Diagnostic-only.
    std::uint64_t diag_code_window_lo{};
    std::uint64_t diag_code_window_hi{};
    std::function<void(std::uint64_t pc, void* uc)> diag_code_hit;
    // Host sink receiving NtWriteFile buffer bytes; empty = guest output is
    // discarded, zero cost at the call site. The engine writes guest output
    // nowhere else - never the host's stdout, never a file. The callback must not
    // throw; if it does, that one write is dropped and the run is otherwise
    // untouched (the writes after it still arrive here in guest order, the handler
    // still answers STATUS_SUCCESS, and the event stream and these statistics do
    // not notice), which is the same rule the log sink is given - see the
    // Callbacks block in include/sheller/export.h.
    std::function<void(const std::uint8_t*, std::size_t)> write_sink;
    // Engine-side event producer (the engine emits raw
    // events, the behavior ledger consumes). Empty = zero-overhead skip; the
    // callback runs on hook hot paths and must not allocate or do IO.
    std::function<void(EventTypeId, const EventPreamble&, std::span<const std::uint8_t>)>
        event_sink;
    // Stub-call side-table drain. The engine counts
    // deterministic-stub export calls (loader route) allocation-free during
    // the run and flushes (module, name, count) per entry once at run end -
    // never on the hook hot path. Empty = the engine registers no stub hook.
    std::function<void(std::uint16_t module, std::string_view name, std::uint64_t count)> stub_sink;
    // Module source table delivery (change real-dll-module-dir): the engine
    // calls this once per run, one row per resident system module, right
    // after the loader world is built - before the first instruction
    // executes, so a run that later fails still delivers its provenance.
    // Folded module name + source-class spelling ("directory-derived",
    // "directory-real-bytes", "fallback-synthetic", "synthetic",
    // "host-system"). Empty = no delivery, zero cost.
    std::function<void(std::string_view module, std::string_view source)> module_source_sink;
    // (The rules layer's fact seam is deliberately absent: facts cross the
    // engine boundary through an internal channel beside these options and
    // reach hosts only as forwarded events - see src/engine/behavior_fact.h.)
    // Cooperative scheduler: blocks a thread runs consecutively before
    // yielding to the next ready thread (once any thread exists beyond the
    // main one). 0 = default (10000).
    std::uint64_t thread_slice_blocks{0};
};

enum class SyscallRunError {
    kNone = 0,
    kIoFailure,
    kBadSnapshot,
    kBitnessUnsupported,
    kInconsistent,
    kUnalignedRegion,
    kUnicornFailure,
    kEmulationFailure,
    kBudgetExhausted,    // instruction budget expired without termination
    kTimeout,            // wall-clock timeout expired without termination
    kUnhandledException, // guest crashed: fastfail, repeated or unregistered exception
    // A container carrying the synthetic module pages was replayed without a
    // synthetic module directory: the synthetic-world tables cannot be
    // rebuilt, so the run is refused instead of silently losing behavior.
    kSyntheticModulesMissing,
    // Directory mode: the guest called a boundary export whose manifest
    // disposition is the unsupported trap. A deliberate, named stop -
    // distinct from crash fallback and budget expiry; the failure's detail
    // names module!export, the ordinal and the call site.
    kBoundaryTrap,
};

struct SyscallRunStats {
    bool terminated{}; // NtTerminateProcess handler stopped the run
    std::uint32_t exit_code{};
    std::uint64_t blocks{};     // guest blocks executed (block hook)
    std::uint64_t syscalls{};   // every intercepted syscall
    std::uint64_t rejects{};    // syscalls answered with a rejection code
    std::uint64_t exceptions{}; // guest exceptions routed into the dispatch
    // xfer events counted by the stop gate. Only accumulated while the
    // counting gate is active (an event_sink, a non-zero xfer_number, or the
    // esp+xfer stop goal, whose ordinal arming needs the tracked identity of
    // the transfer's source block) and outside burn-loop probe speculation,
    // so 0 does NOT mean the run executed no transfers.
    std::uint64_t xfers{};
    // The xfer target stopped the run before its landing block executed. This
    // is a successful stop: terminated stays false and the dump is eligible.
    bool xfer_stop{};
    // The esp target stopped the run: kStopAtRestore at the confirmed
    // restore read, kArmThenNextXfer armed on it and the xfer machinery took
    // the stop (xfer_stop is then true too, and xfers carries the hit
    // ordinal). Same successful-stop contract as xfer_stop.
    bool esp_stop{};
    // DLL-input route: the synthesized sample module's base in the executed
    // world (0 when no pending module loaded). The unpack pipeline's repair
    // target selection anchors on this instead of the container's main-image
    // base (which is the runner here).
    std::uint64_t sample_module_base{};
};

struct SyscallRunFailure {
    SyscallRunError error{};
    // Raw unicorn error code; meaningful when error is kUnicornFailure or
    // kEmulationFailure.
    std::uint32_t unicorn_code{};
    // Partial statistics - filled when the bounded run did execute.
    SyscallRunStats stats{};
    // Named diagnosis text (kBoundaryTrap: "boundary-trap: module!export
    // (ordinal N) at 0x... called from 0x..."); empty for the other kinds.
    std::string detail;
};

std::string_view syscall_run_error_message(SyscallRunError error);

std::expected<SyscallRunStats, SyscallRunFailure>
run_snapshot_syscalls(const std::filesystem::path& snapshot_path, const SyscallRunOptions& options);

// Same run from in-memory snapshot bytes (the one-shot unpack flow keeps the
// capture out of the filesystem).
std::expected<SyscallRunStats, SyscallRunFailure>
run_snapshot_syscalls(const std::vector<std::uint8_t>& snapshot, const SyscallRunOptions& options);

} // namespace sheller::engine

#endif // SHELLER_SYSCALLRUN_H
