#include "run_apply.h"

#include "diag_trace.h"
#include "dll_loader.h"
#include "engine_hooks.h"
#include "intercept.h"

#include <unicorn/unicorn.h>

namespace sheller::engine {

std::expected<void, SyscallRunFailure>
apply_run_plan(PreparedGuest& guest, const SyscallRunOptions& options, const FactChannel& facts,
               const GuestFacts& guest_facts, const RunPlan& plan, SyscallRunState& state)
{
    // The syscall run executes the sample's real code, so the entry spin the
    // capture path wrote must go: restore the original bytes from the
    // snapshot metadata before the guest starts.
    const uc_err restore_error = uc_mem_write(guest.unicorn.get(), guest.metadata.entry_address,
                                              guest.metadata.original_entry_bytes.data(),
                                              guest.metadata.original_entry_bytes.size());
    if (restore_error != UC_ERR_OK) {
        return std::unexpected(SyscallRunFailure{
            SyscallRunError::kUnicornFailure, static_cast<std::uint32_t>(restore_error), {}, {}});
    }

    state.policy = plan.policy;
    // Guest output is the host's decision, not the engine's: an empty sink
    // means the bytes are dropped, and sink_trampoline's existing null check is
    // what makes that cost nothing at the call site - the same shape as every
    // other optional callback in SyscallRunOptions.
    state.sink = options.write_sink;
    state.event_sink = options.event_sink;
    state.behavior_sink = facts.behavior_sink;
    state.module_sink = facts.module_sink;
    state.region_map = &guest.map;
    // The PEB-derived current directory is a read-only fact now
    // (snapshot_guest_facts): it carries the captured process's own directory
    // when that derivation succeeds and the guest's own base otherwise, so
    // this is already the resolved value.
    state.relative_base = guest_facts.relative_base;
    // The sample module's region-map record is a fact too; the write ledger and
    // the behavior code window consume the same values through run_syscalls.
    state.sample_module_known = guest_facts.sample_module_known;
    state.sample_module_index = guest_facts.sample_module_index;
    state.max_blocks = options.max_blocks;
    state.xfer_number = options.xfer_number;
    state.esp_stop_goal = options.esp_stop_goal;
    state.uc = guest.unicorn.get();
    state.guest_mode = guest.guest_mode;
    state.teb_base = guest.metadata.teb_address;
    state.loader_modules = guest.loader_modules;
    state.ldr_entry_vas = guest.ldr_entry_vas;
    state.loader_route = guest.loader_route;
    state.loader_exports = guest.loader_exports;
    state.diag_watch_entries = options.diag_watch_entries;
    state.diag_entry_hit = options.diag_entry_hit;
    state.diag_write_hit = options.diag_write_hit;
    state.diag_code_hit = options.diag_code_hit;
    // SHELLER_LOOP_GATE_TRACE: per-window loop-gate verdict detail plus the run-end
    // verdict distribution, both as kDebug records. Default off - nothing is rendered
    // and the event stream stays byte-identical; the verdict counters accumulate
    // either way (see SyscallRunState::loop_gate_counts). It is copied into the state
    // because the hook path reads it per probe window.
    state.loop_gate_trace = diag::loop_gate_on();
    // DLL-input route: the pending module travels into the run state and the
    // continuation-slot intercept arms (no-op without a pending block -
    // EXE/shellcode runs pay nothing). The arming maps the heap band and the
    // slot page and appends the continuation slot to the state lists; the
    // plan's assignment below replaces them with the identical final contents.
    if (plan.arm_resume_slot) {
        state.pending_module = &*guest.pending;
        state.loaded_modules = &guest.loaded_modules;
        arm_dll_resume_slot(state, guest.unicorn.get());
    }
    state.intercept_vas = plan.intercept_vas;
    state.intercept_ids = plan.intercept_ids;

    // Heap/Ldr family interception, the intercept identity tables, the stub
    // counting table and the boundary-trap adjudication are decided by
    // build_run_plan; the state only receives their result from here on.
    state.fidelity_dispatch = options.windows_fidelity_dispatch;
    // The stub-call side table: the counting hooks bump a slot counter and the
    // run end drains the slots once into this sink, off the hot path.
    state.stub_sink = options.stub_sink;
    // Number <-> Nt name were resolved once as read-only facts
    // (snapshot_guest_facts): real ntdll stubs only, so synthetic 0x1000+
    // numbers never collide, and both maps are copies of that result - off the
    // hook hot path.
    state.syscall_numbers_by_name = guest_facts.syscall_numbers_by_name;
    state.syscall_names = guest_facts.syscall_names;
    state.intercept_names = plan.intercept_names;
    state.intercept_modules = plan.intercept_modules;
    state.stub_slots = plan.stub_slots;
    state.stub_entries.clear();
    for (const auto& entry : plan.stub_entries) {
        state.stub_entries.push_back({entry.module, entry.name, 0});
    }
    if (plan.directory_mode) {
        state.boundary_trap_vas = plan.boundary_trap_vas;
        state.boundary_trap_names = guest.boundary_trap_names;
        state.directory_mode = true;
        state.api_set_ctx.mode = loader::ApiSetContext::Mode::kDirectoryMap;
        state.api_set_ctx.directory_map = &guest.api_set_map;
        // One range-bound code hook per surviving trap VA (the plan already
        // dropped the VAs an intercept supersedes).
        for (const auto va : plan.boundary_trap_vas) {
            uc_hook trap_hook = 0;
            const uc_err trap_error =
                uc_hook_add(guest.unicorn.get(), &trap_hook, UC_HOOK_CODE,
                            reinterpret_cast<void*>(on_boundary_trap), &state, va, va);
            if (trap_error != UC_ERR_OK) {
                return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure,
                                                         static_cast<std::uint32_t>(trap_error),
                                                         {},
                                                         {}});
            }
        }
    }
    if (plan.needs_stub_hooks) {
        for (const auto& mod : state.loader_modules) {
            uc_hook stub_hook = 0;
            const uc_err stub_error = uc_hook_add(guest.unicorn.get(), &stub_hook, UC_HOOK_CODE,
                                                  reinterpret_cast<void*>(on_stub_code), &state,
                                                  mod.base, mod.base + mod.size);
            if (stub_error != UC_ERR_OK) {
                return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure,
                                                         static_cast<std::uint32_t>(stub_error),
                                                         {},
                                                         {}});
            }
        }
    }
    // Engine dispatch: the trampoline page (int3 marker the callback return
    // address points at), per-layer scratch for the guest
    // EXCEPTION_RECORD/CONTEXT/DISPATCHER_CONTEXT structs, and per-layer
    // callback stacks. Reserved from the front of the deterministic alloc
    // bump range; both dispatch modes map it (only the engine mode consumes
    // it). The callback stacks deliberately do NOT ride the guest stack: a
    // captured snapshot's committed stack may not extend below the faulting
    // rsp, and a silent staging write to unmapped memory would zero the
    // handler's return address.
    const auto seh_trampoline = plan.seh_trampoline;
    const uc_err trampoline_error =
        uc_mem_map(guest.unicorn.get(), seh_trampoline, 0x21000, UC_PROT_ALL);
    if (trampoline_error != UC_ERR_OK) {
        return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure,
                                                 static_cast<std::uint32_t>(trampoline_error),
                                                 {},
                                                 {}});
    }
    const std::uint8_t trampoline_marker = 0xCC; // int3: the INTR hook keys on the rip
    uc_mem_write(guest.unicorn.get(), seh_trampoline, &trampoline_marker, 1);
    state.seh.trampoline = plan.seh_trampoline;
    state.seh.scratch = plan.seh_scratch;
    state.valloc_cursor = plan.valloc_cursor;
    state.heap_cursor = plan.heap_cursor;
    return {};
}

} // namespace sheller::engine
