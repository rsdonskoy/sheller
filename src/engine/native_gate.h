// Loop-candidate native-execution evaluation gate: a closed-CFG static scan
// over the cycle detector's hot blocks, deciding whether the bytes could ever
// be handed to the host CPU. Admission here is bookkeeping only - the
// executor itself is not implemented.
//
// Soundness posture: false rejects are acceptable, false accepts are not.
// The closure proof (closed CFG + no privileged/sensitive bytes) is what
// upgrades "syscall-free within the observation window" to "syscall-free
// for every iteration", so anything the scan cannot fully follow is a
// structured reject, never a guess. The scanned bytes must also stay
// immutable for the proof to hold - a store resolving into the loop's own
// byte range is therefore a reject (self-modification), and the probe's
// write journal covers the register-indirect stores static analysis cannot
// resolve (see run_loop_probe).
//
// The module is decoder-cadence (called once per probe window, not per
// block): no heap allocation, no global state, fully reentrant - every
// buffer is caller-independent stack storage and guest bytes arrive through
// the caller's read callback.

#ifndef SHELLER_ENGINE_NATIVE_GATE_H
#define SHELLER_ENGINE_NATIVE_GATE_H

#include <cstddef>
#include <cstdint>

namespace sheller::engine::native_gate {

// Exit-target slot budget: the window executor pins loop exits
// with the four hardware debug registers DR0-3, so a loop with more than
// four distinct fall-outs has no executor-side stop set - reject.
inline constexpr std::size_t kMaxExitTargets = 4;
// Scan budget per window (all blocks together). The probe window this gate
// evaluates is the 8-slot cycle ring; 512 instructions is the shape bound
// the executor is sized for.
inline constexpr std::size_t kMaxLoopBlocks = 64;
inline constexpr std::size_t kMaxScanInstructions = 512;

// Guest addressing mode for the decoder: the engine is x64-first; x86
// guests decode in compat mode (their universal fs-prefix TEB access is
// rejected by the attribute blacklist, which is the scoped outcome - x86 is
// a native-execution non-goal).
enum class MachineMode : std::uint8_t { kX64, kX86 };

// Ledger categories. A window lands in exactly one; scan() fills the
// provisional admitted_zero_write on a clean static pass and the probe
// upgrades it to admitted_compute when its write journal saw guest writes.
enum class Verdict : std::uint8_t {
    kAdmitZeroWrite,
    kAdmitCompute,
    kReject,
};

// Structured reject classes - the ledger and the SHELLER_LOOP_GATE_TRACE
// detail lines spell them via reject_reason_name(). Order is ledger ABI:
// verdict_slot() maps them to state counters by value, so only append.
enum class RejectReason : std::uint8_t {
    kNone = 0,
    kSyscall,            // syscall/sysenter and the return side
    kSoftInterrupt,      // int n / int1 / int3 / into / ud family
    kClockRead,          // rdtsc / rdtscp / rdpmc
    kFeatureQuery,       // cpuid
    kPortIo,             // in / ins / out / outs
    kHalt,               // hlt and the system-instruction catch-all (MSR /
                         // CR / DR / system-table writes, VMX/SVM/SGX,
                         // monitor-mwait family)
    kCallRet,            // call/ret pairs - callees are outside the set
    kIndirectBranch,     // reg/mem/far transfer: closure unprovable
    kX87Transcendental,  // microarch-variant results break cross-host
                         // determinism even with FCW/MXCSR synced
    kSegmentPrefix,      // fs/gs: TEB-relative addressing
    kLockPrefix,         // lock / xacquire / xrelease
    kVectorEncoding,     // VEX/EVEX: TCG shim territory
    kNondeterministic,   // rdrand/rdseed/TSX: results are not a function of
                         // the entry state - breaks the equivalence contract
    kClosureEscape,      // engine-side cross-check only: a probe-observed
                         // fall-out is not in the static exit set (scan()
                         // itself never returns it)
    kExitTargetOverflow, // more than kMaxExitTargets fall-outs (DR0-3)
    kSelfWrite,          // store resolving into the scanned byte range:
                         // self-modification voids the closure proof
    kClockSensitiveRead, // dynamic: KUSER_SHARED_DATA read in the probe
                         // cycle
    kHookSensitiveInsn,  // dynamic: rdtsc/rdtscp/cpuid hook fired in the
                         // probe cycle
    kDecodeFailure,      // unreadable/malformed/truncated bytes or a scan
                         // over budget - never a false accept
};

struct GateVerdict {
    Verdict category{Verdict::kReject};
    RejectReason reason{RejectReason::kNone};
    std::uint64_t exit_targets[kMaxExitTargets]{};
    std::size_t exit_target_count{};
    // Scanned byte ranges per block ([start, end)), what a self-write check
    // and the probe's write-journal cross-check compare against.
    struct Extent {
        std::uint64_t start{};
        std::uint64_t end{};
    };
    Extent extents[kMaxLoopBlocks]{};
    std::size_t extent_count{};
};

[[nodiscard]] inline bool rejected(const GateVerdict& verdict)
{
    return verdict.category == Verdict::kReject;
}

// Byte reader over the loop's code range: fills at most `size` bytes at
// guest virtual address `va` and returns how many were filled (0 = none
// available - the scan answers kDecodeFailure, an unreadable loop is never
// admitted). Fewer bytes than requested are fine: the request may straddle
// a mapped-region end and the loop's terminator may still sit inside what
// came back. Plain function pointer + context: std::function may allocate.
using ReadBytes = std::size_t (*)(void* context, std::uint64_t va, std::uint8_t* out,
                                  std::size_t size);

// Closed-CFG scan over the loop's blocks: per block, linear-decode from the
// block start to its terminator; classify every instruction against the
// blacklist; require every direct transfer target to land in the block set
// or the (bounded) exit set; resolve every statically-resolvable store and
// reject if it targets the scanned range. First structural hit wins as the
// reject reason.
[[nodiscard]] GateVerdict scan(const std::uint64_t* block_vas, std::size_t block_count,
                               MachineMode mode, ReadBytes read, void* context);

// Ledger slot layout for SyscallRunState.loop_gate_counts: one slot per
// window verdict, unconditionally accumulated, printed only under the
// SHELLER_LOOP_GATE_TRACE switch.
inline constexpr std::size_t kAdmitZeroWriteSlot = 0;
inline constexpr std::size_t kAdmitComputeSlot = 1;
inline constexpr std::size_t kRejectSlotBase = 2;
inline constexpr std::size_t kVerdictSlotCount =
    kRejectSlotBase + 19; // one per RejectReason value past kNone

inline std::size_t verdict_slot(const GateVerdict& verdict)
{
    if (verdict.category == Verdict::kAdmitCompute) {
        return kAdmitComputeSlot;
    }
    if (verdict.category == Verdict::kAdmitZeroWrite) {
        return kAdmitZeroWriteSlot;
    }
    return kRejectSlotBase + (static_cast<std::size_t>(verdict.reason) - 1);
}

inline RejectReason reason_for_slot(const std::size_t slot)
{
    return static_cast<RejectReason>(slot - kRejectSlotBase + 1);
}

// Stable spellings for the trace output and the run-end distribution.
const char* verdict_name(Verdict verdict);
const char* reject_reason_name(RejectReason reason);

} // namespace sheller::engine::native_gate

#endif // SHELLER_ENGINE_NATIVE_GATE_H
