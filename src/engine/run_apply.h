// The apply stage of the syscall-run state assembly: the write half of the
// split. It consumes a RunPlan (already decided, pure) plus the run options and
// the read-only facts, and performs every guest write, hook registration and
// state fill in the order the pre-split assemble_run_state used. That order is
// load-bearing - arm_dll_resume_slot's map timing is coupled to the hook
// registration order, and the state pointer assignments must precede the hooks
// that read them - so keep it when editing.

#ifndef SHELLER_ENGINE_RUN_APPLY_H
#define SHELLER_ENGINE_RUN_APPLY_H

#include "behavior_fact.h"
#include "rebuild_state.h"
#include "run_facts.h"
#include "run_plan.h"

#include <expected>

namespace sheller::engine {

// Writes the plan into the guest and the run state; returns the first failing
// unicorn call's error untouched.
std::expected<void, SyscallRunFailure>
apply_run_plan(PreparedGuest& guest, const SyscallRunOptions& options, const FactChannel& facts,
               const GuestFacts& guest_facts, const RunPlan& plan, SyscallRunState& state);

} // namespace sheller::engine

#endif // SHELLER_ENGINE_RUN_APPLY_H
