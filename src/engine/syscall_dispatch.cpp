#include "syscall_dispatch.h"

#include "../syscalls/syscall_arity.h"
#include "../syscalls/syscall_number_map.h"
#include "engine_hooks.h"
#include "exception_pipeline.h"
#include "guest_objects.h"

#include <cstring>
#include <optional>

namespace sheller::engine {
namespace {

// Gate-idiom encodings: ntdll's string family loads its cached CPU-feature
// byte with a rip-relative byte mov and branches on a single-bit test.
constexpr std::uint8_t kGateLoadOpcode = 0x8A;     // mov r8, rip-relative memory
constexpr std::uint8_t kGateLoadModrmRipAl = 0x05; // mod=00 reg=al rm=101 (rip-rel)
constexpr std::size_t kGateLoadLength = 6;         // opcode + modrm + rel32
constexpr std::uint8_t kGateTestOpcode = 0xA8;     // test al, imm8
constexpr std::size_t kGateTestLength = 2;         // opcode + imm8
constexpr std::size_t kGateTestWindow = 32;        // load->test gap in bytes
constexpr std::size_t kGateScanWindow = 512;       // prologue bytes inspected per export

// The QPC face of the virtual clock: the counter is the policy's base plus
// the per-block delta at the current block position, the frequency the
// policy's pinned value - both pure functions of the block count. Fail-soft
// like the retired zero answer: an unwritable counter pointer rejects the
// call, a null counter pointer keeps the default success (frequency-only
// callers still get their frequency).
void apply_query_performance_counter(SyscallRunState* state, uc_engine* const uc,
                                     syscalls::SyscallOutcome& outcome)
{
    if (outcome.qpc_counter_ptr != 0) {
        const std::uint64_t counter =
            state->clock.base_qpc + state->clock.qpc_per_block * state->blocks;
        if (uc_mem_write(uc, outcome.qpc_counter_ptr, &counter, sizeof counter) != UC_ERR_OK) {
            outcome.status = syscalls::kStatusAccessViolation;
            return;
        }
    }
    if (outcome.qpc_frequency_ptr != 0) {
        const std::uint64_t frequency = state->clock.qpc_frequency;
        static_cast<void>(
            uc_mem_write(uc, outcome.qpc_frequency_ptr, &frequency, sizeof frequency));
    }
}

} // namespace

// Shared syscall dispatch: event, policy answer, allocation/protect side
// effects, counters. The caller synthesizes the instruction-specific ABI
// (x64 syscall vs x86 int 2e) and handles termination.
syscalls::SyscallOutcome dispatch_one_syscall(SyscallRunState* state, uc_engine* const uc,
                                              const syscalls::SyscallFrame& frame)
{
    const syscalls::WriteSink sink{&state->sink, &sink_trampoline};
    auto outcome = syscalls::dispatch_syscall(state->policy, uc, frame, sink);
    if (outcome.query_performance) {
        apply_query_performance_counter(state, uc, outcome);
    }
    if (outcome.open_section) {
        apply_open_section(*state, uc, frame, outcome);
    }
    if (outcome.create_section) {
        apply_create_section(*state, uc, frame, outcome);
    }
    if (outcome.map_view) {
        apply_map_view_of_section(*state, uc, frame, outcome);
    }
    if (outcome.create_file) {
        apply_create_file(*state, uc, frame, outcome);
    }
    if (outcome.read_file) {
        apply_read_file(*state, uc, frame, outcome);
    }
    if (outcome.query_file) {
        apply_query_file(*state, uc, frame, outcome);
    }
    if (outcome.query_attributes) {
        apply_query_attributes(*state, uc, frame, outcome);
    }
    if (outcome.query_virtual) {
        apply_query_virtual_memory(state, uc, frame, outcome);
    }
    if (outcome.map_size != 0) {
        // Issuer attribution (direct-issuance): sample-issued allocations
        // are sample territory and carry the full behavior surface; system-
        // issued ones (CRT/CLR JIT machinery) map and answer event-silently.
        const bool sample_issued = allocation_sample_issued(uc, frame, state->region_map, *state);
        apply_guest_allocation(uc, frame, outcome, *state, sample_issued);
        // Behavior: the allocation range joins the monitored code windows
        // (shellcode lands and executes here), and an allocation that
        // already requests executable-write protection is an RWX signal.
        // Infrastructure allocations stay outside the behavior surface.
        if (state->behavior_sink && sample_issued) {
            uc_hook code_window = 0;
            if (uc_hook_add(uc, &code_window, UC_HOOK_CODE,
                            reinterpret_cast<void*>(on_behavior_code), state, outcome.map_base,
                            outcome.map_base + outcome.map_size) == UC_ERR_OK) {
                // hook lives until uc_close; no handle bookkeeping needed
            }
            if (outcome.alloc_protection != 0) {
                BehaviorFact fact;
                fact.kind = BehaviorFact::Kind::kProtect;
                fact.pc = frame.rip;
                fact.addr = outcome.map_base;
                fact.aux = outcome.map_size;
                fact.size = outcome.alloc_protection;
                state->behavior_sink(fact);
            }
        }
    }
    if (outcome.protect_size != 0) {
        // Protection requests flip the ledger region writable: the fault
        // hook then re-grants unicorn write permission per page on the
        // guest's first write (the stub's own header-restore writes).
        state->write_ledger->set_writable(outcome.protect_base, outcome.protect_size);
        // The attribution map carves the covered interval at page
        // granularity: xfer identities and MBI answers see the new
        // protection from here on.
        if (state->region_map != nullptr) {
            state->region_map->apply_protection(outcome.protect_base, outcome.protect_size,
                                                outcome.protect_protection);
        }
        // An execute-carrying request (the classic RW-then-protect-to-RWX
        // shellcode pattern) must reach the unicorn mapping too - a fetch
        // fault has no handler to grant it. Write stays ungranted so the
        // dirty tracking keeps seeing first writes.
        static_cast<void>(
            uc_mem_protect(uc, outcome.protect_base, outcome.protect_size,
                           protection_to_perms(outcome.protect_protection) & ~UC_PROT_WRITE));
        // The behavior fact rides the issuer (direct-issuance): a system
        // module protecting its own memory (CLR flipping JIT pages) is
        // infrastructure and stays event-silent.
        if (state->behavior_sink &&
            allocation_sample_issued(uc, frame, state->region_map, *state)) {
            BehaviorFact fact;
            fact.kind = BehaviorFact::Kind::kProtect;
            fact.pc = frame.rip;
            fact.addr = outcome.protect_base;
            fact.aux = outcome.protect_size;
            fact.size = outcome.protect_protection;
            state->behavior_sink(fact);
        }
    }
    // thread outcomes are applied by the callers: the resume rip differs
    // per abi (x64 syscall is pre-instruction, x86 int 2e is post)
    // Syscall event = completed-call fact: emitted
    // after dispatch and its side effects - rejects and handlers alike
    // produce it, with the handler's status and OUT values in hand. Timing
    // note pinned by design: handler uc_mem_write side effects never emit
    // events (the only write hook is the read-only-page WRITE_PROT), so this
    // position cannot interleave with other ledger events. Parameters ride
    // the raw register shape (flags bit1) until the Nt description table
    // join promotes individual numbers to decoded records.
    if (state->event_sink) {
        std::uint64_t return_address = 0;
        static_cast<void>(uc_mem_read(uc, frame.rsp, &return_address, sizeof return_address));
        const auto success = (outcome.status & 0x80000000u) == 0;
        std::array<std::uint8_t, kSyscallFixedBytes + 11 * 11 + 3 * 11> fields{};
        SyscallFields head{
            .number = frame.number,
            .flags = static_cast<std::uint8_t>(kEventFlagRaw | (success ? kEventFlagSuccess : 0u)),
            .status = static_cast<std::uint32_t>(outcome.status),
            .caller_retaddr = return_address};
        auto head_end = encode_syscall_head(fields, head);
        std::size_t cursor = head_end.value_or(kSyscallFixedBytes);
        // The decoded tier emits ALL positional form
        // parameters when the number resolves to a known Nt signature -
        // four register values plus stack slots at [rsp+0x28+8k] (the
        // same slots the policy handlers read). Unreadable slots record 0.
        const auto arity = [&state, number = frame.number]() -> std::optional<std::uint32_t> {
            const auto named = state->syscall_names.find(number);
            if (named == state->syscall_names.end()) {
                return std::nullopt;
            }
            return syscalls::nt_arg_count(named->second);
        }();
        if (arity.has_value() && *arity >= 4) {
            head.flags = static_cast<std::uint8_t>(head.flags & ~kEventFlagRaw); // decoded tier
            static_cast<void>(encode_syscall_head(fields, head));
            const std::uint64_t regs[4] = {frame.rcx, frame.rdx, frame.r8, frame.r9};
            for (std::uint32_t i = 0; i < *arity; ++i) {
                std::uint64_t value = 0;
                if (i < 4) {
                    value = regs[i];
                } else {
                    // arg5+ rides the caller's stack above the shadow zone
                    static_cast<void>(
                        uc_mem_read(uc, frame.rsp + 0x28 + 8 * (i - 4), &value, sizeof value));
                }
                std::array<std::uint8_t, 8> bytes{};
                le::store_le64(bytes.data(), value);
                static_cast<void>(append_param_record(fields, cursor, ParamKind::kU64, bytes));
            }
        } else {
            for (const std::uint64_t reg : {frame.rcx, frame.rdx, frame.r8, frame.r9}) {
                std::array<std::uint8_t, 8> value{};
                le::store_le64(value.data(), reg);
                static_cast<void>(append_param_record(fields, cursor, ParamKind::kU64, value));
            }
        }
        // Shallow-stack snapshot: three raw
        // slots above the caller's return address - saved registers and
        // grandparent return addresses. Attribution-only facts; unreadable
        // slots record 0 deterministically.
        for (const std::uint64_t slot :
             {std::uint64_t{8}, std::uint64_t{0x10}, std::uint64_t{0x18}}) {
            std::uint64_t value = 0;
            static_cast<void>(uc_mem_read(uc, frame.rsp + slot, &value, sizeof value));
            std::array<std::uint8_t, 8> bytes{};
            le::store_le64(bytes.data(), value);
            static_cast<void>(append_param_record(fields, cursor, ParamKind::kStackSlot, bytes));
        }
        const EventPreamble preamble{.seq = 0, .tid = state->current_tid, .pc = frame.rip};
        state->event_sink(EventTypeId::kSyscall, preamble,
                          std::span<const std::uint8_t>{fields.data(), cursor});
    }
    ++state->syscalls;
    if (outcome.rejected) {
        ++state->rejects;
    }
    // A syscall is a guest-visible side effect: whatever block cycle was
    // spinning is real behavior's neighbourhood, not a burn loop.
    state->hot_run = 0;
    return outcome;
}

void on_syscall_callback(uc_engine* const uc, void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);

    syscalls::SyscallFrame frame{};
    std::uint64_t rax = 0;
    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    frame.number = static_cast<std::uint32_t>(rax);
    frame.tid = state->current_tid;
    uc_reg_read(uc, UC_X86_REG_RIP, &frame.rip);
    uc_reg_read(uc, UC_X86_REG_RCX, &frame.rcx);
    uc_reg_read(uc, UC_X86_REG_R10, &frame.r10);
    uc_reg_read(uc, UC_X86_REG_RDX, &frame.rdx);
    uc_reg_read(uc, UC_X86_REG_R8, &frame.r8);
    uc_reg_read(uc, UC_X86_REG_R9, &frame.r9);
    uc_reg_read(uc, UC_X86_REG_RSP, &frame.rsp);
    uc_reg_read(uc, UC_X86_REG_RSP, &frame.rsp);

    auto outcome = dispatch_one_syscall(state, uc, frame);
    if (outcome.thread_create) {
        // the syscall hook is pre-instruction: the calling thread resumes
        // past the two-byte syscall
        apply_thread_creation(state, uc, frame, outcome, frame.rip + 2);
    }

    // Synthesize the syscall instruction's own effects: rcx = return
    // address, r11 = rflags, rax = result, execution continues after the
    // two-byte syscall. At the interception point none of that has happened
    // yet (a zeroed guest rcx once sent execution to address 0).
    std::uint64_t next_rip = frame.rip + 2;
    std::uint64_t rflags = 0;
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &rflags);
    uc_reg_write(uc, UC_X86_REG_RCX, &next_rip);
    uc_reg_write(uc, UC_X86_REG_R11, &rflags);
    uc_reg_write(uc, UC_X86_REG_RAX, &outcome.status);

    // kRaiseException: adopt the raised context (over the synthesis above)
    // and stop; the run loop re-dispatches or lands the crash fallback.
    if (outcome.raise) {
        apply_raise_exception(state, uc, frame);
        uc_emu_stop(uc);
        return;
    }

    // thread outcomes: the syscall hook is pre-instruction, so a blocking
    // or exiting thread resumes past the two-byte syscall
    if (outcome.blocking && state->scheduler.enabled) {
        state->scheduler.blocked = true;
        state->scheduler.cur().rip_resume = frame.rip + 2;
        uc_emu_stop(uc);
    }
    if (outcome.terminate_thread) {
        scheduler_thread_exit(state, outcome.exit_code);
    }
    if (outcome.terminate) {
        state->terminated = true;
        state->exit_code = outcome.exit_code;
        uc_emu_stop(uc);
    }
}

// ISA-consistency sweep. The CPUID hook reports a no-AVX
// baseline, but system modules baked their CPU-feature caches at capture
// time on the real machine - ntdll's string family gates its 256-bit paths
// on a cached feature byte, so the emulated guest ends up executing AVX2
// through the single-instruction shim although the reported CPU cannot.
// Sweep the string-family exports for the gate idiom - mov al,[rip+rel32]
// followed by test al,imm8 with a single-bit mask - and clear the baked
// bits, restoring a world where the reported CPU and the cached feature
// state agree. Offsets are discovered per capture; a build without the
// idiom leaves the pass a no-op. Clearing a gate selects the scalar path,
// which computes identical results (it is the pre-SIMD implementation).
void normalize_isa_feature_gates(uc_engine* const uc, const mem_region::MemRegionMap& map)
{
    static constexpr std::array<std::string_view, 9> kStringExports{
        "wcslen", "strlen", "wcschr",  "wcsrchr", "memchr",
        "memcmp", "strcmp", "strncmp", "wcsncmp"};
    for (std::size_t i = 0; i < map.module_count(); ++i) {
        if (map.module(i).synthesized) {
            continue; // synthesized unknown images: this sweep never rewrites them
        }
        const auto module_base = map.module(i).base;
        for (const auto& export_name : kStringExports) {
            const auto function_va = syscalls::resolve_export(uc, module_base, export_name);
            if (!function_va.has_value()) {
                continue;
            }
            std::array<std::uint8_t, kGateScanWindow> code{};
            if (uc_mem_read(uc, *function_va, code.data(), code.size()) != UC_ERR_OK) {
                continue;
            }
            for (std::size_t at = 0;
                 at + kGateLoadLength + kGateTestWindow + kGateTestLength <= code.size(); ++at) {
                if (code[at] != kGateLoadOpcode || code[at + 1] != kGateLoadModrmRipAl) {
                    continue;
                }
                std::uint32_t rel32 = 0;
                std::memcpy(&rel32, code.data() + at + 2, sizeof rel32);
                const std::uint64_t rip_after_load = *function_va + at + kGateLoadLength;
                for (std::size_t j = at + kGateLoadLength;
                     j <= at + kGateLoadLength + kGateTestWindow; ++j) {
                    if (code[j] != kGateTestOpcode) {
                        continue;
                    }
                    const auto mask = code[j + 1];
                    if (mask == 0 || (mask & (mask - 1)) != 0) {
                        break; // only single-bit gates are feature selectors
                    }
                    const std::uint64_t gate_va =
                        rip_after_load +
                        static_cast<std::uint64_t>(static_cast<std::int32_t>(rel32));
                    std::uint8_t gate = 0;
                    if (uc_mem_read(uc, gate_va, &gate, sizeof gate) == UC_ERR_OK &&
                        (gate & mask) != 0) {
                        gate = static_cast<std::uint8_t>(gate & ~mask);
                        static_cast<void>(uc_mem_write(uc, gate_va, &gate, sizeof gate));
                    }
                    break;
                }
            }
        }
    }
}

// The SCP (shadow-stack-compatible CFG dispatch)
// registration gate inside LdrpProcessMappedModule. Native truth (packed
// corpus host, Win11 24H2, 2026-10-02): the gate is two `bt + setae` pairs
// over the LDR-entry flags and the load-context flags - when either input
// has its bit set the loader skips RtlpInsertOrRemoveScpCfgFunctionTable
// entirely, which is the shape EVERY Windows 10 process runs in (the SCP
// dispatch mode and this call site do not exist in Win10 ntdll). The replay
// has no CFG bitmap machinery to back a successful registration, and a
// failed one fails the load into the WER report path. Flip the gate's short
// jump to unconditional so the replayed loader takes the skip branch for
// every module - the Win10 semantics, with no guest logic rewritten and no
// host state involved. Version-pinned byte scan: a build without the idiom
// leaves the pass a no-op (the pre-fix failure shape returns, nothing else
// changes).
void normalize_scp_cfg_gate(uc_engine* const uc, const std::uint64_t ntdll_base,
                            const std::uint64_t ntdll_size)
{
    static constexpr std::array<std::uint8_t, 18> kScpGatePattern{
        0x0F, 0xBA, 0xE2, 0x15,       // bt edx, 15h        (LDR entry flags)
        0x0F, 0x93, 0xC1,             // setae cl
        0x41, 0x0F, 0xBA, 0xE5, 0x17, // bt r13d, 17h       (load-context flags)
        0x0F, 0x93, 0xC0,             // setae al
        0x84, 0xC8,                   // test al, cl
        0x74};                        // je short  <- the byte flipped to jmp (0xEB)
    if (ntdll_base == 0 || ntdll_size < kScpGatePattern.size() || ntdll_size > kMaxSectionBytes) {
        return;
    }
    std::vector<std::uint8_t> code(static_cast<std::size_t>(ntdll_size));
    if (uc_mem_read(uc, ntdll_base, code.data(), code.size()) != UC_ERR_OK) {
        return;
    }
    for (std::size_t i = 0; i + kScpGatePattern.size() <= code.size(); ++i) {
        if (std::memcmp(code.data() + i, kScpGatePattern.data(), kScpGatePattern.size()) != 0) {
            continue;
        }
        const std::uint8_t unconditional = 0xEB; // jmp short (the je's displacement)
        static_cast<void>(uc_mem_write(uc, ntdll_base + i + kScpGatePattern.size() - 1,
                                       &unconditional, sizeof unconditional));
        return;
    }
}

// Syscall run: rebuild, attach the policy, execute until the guest
// terminates or the budget/timeout expires.

} // namespace sheller::engine
