// Engine hook callbacks and their applies: the write-prot ledger hook, the
// syscall-run block hook (counters, xfer attribution, diagnostics), the
// behavior monitored-window facts, CPUID/RDTSC masking, and the
// cooperative-thread applies. The run loop registers these as unicorn hooks;
// the syscall dispatch applies the thread ones.

#ifndef SHELLER_ENGINE_ENGINE_HOOKS_H
#define SHELLER_ENGINE_ENGINE_HOOKS_H

#include "rebuild_state.h"

namespace sheller::engine {

bool on_mem_write_prot_callback(uc_engine* const uc, const uc_mem_type, const std::uint64_t address,
                                const std::uint32_t size, const std::int64_t,
                                void* const user_data);

// Block hook of the syscall run: bumps the block counter and, when an event
// sink is attached, emits block-exec with the block start address (the hook
// address is the block start). Hot path: no allocation, no IO.
// Directory-mode boundary trap: an
// exact-entry code hook over each (c)-class trap VA. Fills the named
// diagnosis, marks the deliberate stop and halts - the ud2 body and every
// instruction after the call never execute, and the caller is answered by
// nothing.
void on_boundary_trap(uc_engine* uc, const std::uint64_t address, const std::uint32_t,
                      void* user_data);

void on_syscall_run_block(uc_engine* uc, const std::uint64_t address, const std::uint32_t,
                          void* const user_data);

// Issuer attribution of one allocation/protect syscall (direct-issuance):
// the bounded stack scan looks for a return address in sample territory -
// the sample image or an already-registered sample region; system-issued
// actions are event-silent infrastructure.
bool stack_carries_sample_frame(uc_engine* const uc, std::uint64_t rsp, bool x64,
                                const mem_region::MemRegionMap* region_map,
                                const SyscallRunState& state);

bool allocation_sample_issued(uc_engine* const uc, const syscalls::SyscallFrame& frame,
                              const mem_region::MemRegionMap* region_map,
                              const SyscallRunState& state);

// Applies one guest allocation: unicorn mapping, ledger region, and the
// attribution-map registration when a map is attached. The issuer flag
// (see allocation_sample_issued) decides sample territory vs event-silent
// infrastructure.
void apply_guest_allocation(uc_engine* const uc, const syscalls::SyscallFrame& frame,
                            syscalls::SyscallOutcome& outcome, SyscallRunState& state,
                            bool sample_issued);

// Behavior monitored-window callbacks: pure-data facts out of the
// engine hooks. Registered only when a behavior consumer is attached.
void on_behavior_mem_read(uc_engine* const uc, const uc_mem_type, const std::uint64_t address,
                          const std::uint32_t size, const std::int64_t, void* const user_data);
void on_behavior_code(uc_engine* const uc, const std::uint64_t address, const std::uint32_t size,
                      void* const user_data);

void on_diag_write_window(uc_engine* const uc, const uc_mem_type, const std::uint64_t address,
                          const std::uint32_t size, const std::int64_t value,
                          void* const user_data);
void on_diag_code_window(uc_engine* const uc, const std::uint64_t address, const std::uint32_t,
                         void* const user_data);

bool on_rdtsc_callback(uc_engine* const uc, void* const user_data);

bool on_rdtscp_callback(uc_engine* const uc, void* const user_data);

// Burn-loop fast-forward: called between legs when the cycle detector
// fired. Emulates one cycle under a full write journal - a cycle with any
// guest-visible write is real computation (re-arm and continue); a
// zero-write cycle is a pure-counter delay, force-exited by setting each
// changed GPR to its loop-exit value and letting the branch fall through
// naturally (decoder-free). Emits the kLoopSkip behavior fact on success.
// The same window produces the loop-native-gate verdict (static closed-CFG
// scan + the cycle's dynamic evidence): ledger-only, printed
// per window under SHELLER_LOOP_GATE_TRACE.
void run_loop_probe(SyscallRunState& state, uc_engine* uc);

bool on_cpuid_callback(uc_engine* const uc, void* const user_data);

// TEB switch: x64 rewrites GS_BASE; x86 swaps the live FS descriptor
// base on the pinned GDT page and reloads the selector.
void apply_teb_switch(uc_engine* const uc, const GuestMode mode, const std::uint64_t teb_base);

// Thread creation (NtCreateThreadEx engine side).
void apply_thread_creation(SyscallRunState* state, uc_engine* const uc,
                           const syscalls::SyscallFrame& frame, syscalls::SyscallOutcome& outcome,
                           const std::uint64_t resume_rip);

// Thread exit: end the calling thread.
void scheduler_thread_exit(SyscallRunState* state, const std::uint32_t exit_code);

} // namespace sheller::engine

#endif // SHELLER_ENGINE_ENGINE_HOOKS_H
