// The run's pure decision core: every table and verdict the syscall run's
// state assembly needs, computed from the guest's construction tables alone.
// build_run_plan takes const references and never touches unicorn, the run
// state, or guest memory - that is the point of the split: the rules below
// (intercept registration, alias adjudication, stub counting, boundary-trap
// filtering, deterministic cursor layout) become table-driven unit tests
// instead of behavior that only end-to-end replays can observe.
//
// RunPlan is transient: it exists on the assembly stack and is NEVER stored in
// SyscallRunState (the hook callbacks' user_data, whose layout is an implicit
// contract with the hook code).

#ifndef SHELLER_ENGINE_RUN_PLAN_H
#define SHELLER_ENGINE_RUN_PLAN_H

#include "../syscalls/syscall_policy.h"

#include <sheller/syscallrun.h>

#include <cstdint>
#include <expected>
#include <map>
#include <string>
#include <vector>

namespace sheller::engine {

struct PreparedGuest;
struct GuestFacts;

// One stub-counting row: the owning region-map module index and the export
// spelling. The call count starts at zero and lives in the run state.
struct RunStubEntry {
    std::uint16_t module{};
    std::string name;
};

struct RunPlan {
    // The policy table the apply stage hands to the environment pass (empty by
    // design: the built-in semantics are seeded from the mapped ntdll after
    // assembly, not decided here).
    syscalls::PolicyTable policy;
    // Intercepted API entry addresses with their parallel handler ids: the
    // declared set (guest intercepts) plus the heap/Ldr families registered at
    // the mapped ntdll's export entries, plus the DLL-input continuation slot.
    std::vector<std::uint64_t> intercept_vas;
    std::vector<std::uint32_t> intercept_ids;
    // Resolved intercept identity for event emission (export spelling from the
    // loader export table; owning region-map module index, 0xFFFF when none).
    std::vector<std::string> intercept_names;
    std::vector<std::uint16_t> intercept_modules;
    // The stub counting table: directory mode counts the explicit whitelist
    // (alias-sharing VAs collapse to the first row), the synthetic mode counts
    // every non-intercepted loader export.
    std::vector<RunStubEntry> stub_entries;
    std::map<std::uint64_t, std::uint32_t> stub_slots; // export VA -> stub_entries slot
    // Boundary-trap VAs with the intercepted ones already removed: an
    // intercept registration on the same VA supersedes the trap.
    std::vector<std::uint64_t> boundary_trap_vas;
    // Engine-dispatch trampoline page and the deterministic allocator cursors
    // (per-guest-mode layout constants, precomputed so the apply stage only
    // maps and writes).
    std::uint64_t seh_trampoline{};
    std::uint64_t seh_scratch{};
    std::uint64_t valloc_cursor{};
    std::uint64_t heap_cursor{};
    bool directory_mode{false};
    // The DLL-input route: a pending module arms the continuation-slot
    // intercept (the apply stage also maps the heap band and the slot page).
    bool arm_resume_slot{false};
    // options.stub_sink is set and the counting table is non-empty.
    bool needs_stub_hooks{false};
};

// Pure: reads the guest's construction tables and writes nothing. The facts
// parameter is reserved for the apply split's decision inputs (this core needs
// none of them yet), so it is deliberately unused. The decision core is total
// today (every rule has a defined answer), so the failure channel carries no
// producer yet - it is the signature the apply split (later slice) continues
// with.
std::expected<RunPlan, SyscallRunFailure> build_run_plan(const PreparedGuest& guest,
                                                         const GuestFacts& facts,
                                                         const SyscallRunOptions& options);

} // namespace sheller::engine

#endif // SHELLER_ENGINE_RUN_PLAN_H
