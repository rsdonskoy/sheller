// Guest syscall interception state: what the policy
// handler sees when the engine intercepts a guest syscall, plus the result
// field the handler writes back. tid is the thread-model reservation: the seams never assume
// single-thread, and the scheduler adds the multi-thread model.

#ifndef SHELLER_SYSCALL_CTX_H
#define SHELLER_SYSCALL_CTX_H

#include <cstdint>

namespace sheller {

struct SyscallCtx {
    std::uint32_t number{}; // eax at the interception point
    std::uint64_t r10{};    // argument 1 (Windows x64 syscall ABI)
    std::uint64_t rdx{};    // argument 2
    std::uint64_t r8{};     // argument 3
    std::uint64_t r9{};     // argument 4
    std::uint64_t rip{};    // interception-point address of the syscall
    std::uint64_t rsp{};
    std::uint32_t tid{};   // thread-model reservation (scheduler)
    std::int64_t result{}; // handler writes the NTSTATUS / handler result back
};

// Contract type for policy-side handlers: consume the frame, write the
// result; the engine synthesizes the syscall instruction's effects
// (rcx/r11/rax/rip) from ctx.result per the interception-point findings.
using SyscallHandler = std::int64_t (*)(SyscallCtx* ctx);

} // namespace sheller

#endif // SHELLER_SYSCALL_CTX_H
