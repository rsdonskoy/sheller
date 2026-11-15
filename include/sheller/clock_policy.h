// The engine's default deterministic-clock policy - the single definition
// point for the numeric constants behind every guest-visible clock source.
// snapshot.h carries the ClockPolicy format type; this header carries its
// values. Producers that pin a policy into a v3 container (capture, craft)
// and the replay path that answers from a container without a clock block
// both read the same constants here, so a container written today replays
// with today's clock even after the engine default moves on.
//
// Rate self-consistency (the contract the constants encode):
//   TSC face:      tsc_per_block * 16,000 blocks/s = 150,000 * 16,000 = 2.4 GHz
//   CPUID 0x16:    base frequency 2400 MHz = the TSC face
//   CPUID 0x15:    crystal 24 MHz * (EBX/EAX = 100) = 2.4 GHz
//   QPC face:      qpc_per_block * 16,000 blocks/s = 625 * 16,000 = 10 MHz
//     (= qpc_frequency, the invariant Windows TSC-backed QPC rate)

#ifndef SHELLER_CLOCK_POLICY_H
#define SHELLER_CLOCK_POLICY_H

#include <sheller/snapshot.h>

namespace sheller::snapshot {

// The clock block's policy version: the layout of the fields a policy block
// carries. A reader that does not know the version rejects the block
// (kBadClock) instead of guessing at shifted fields.
inline constexpr std::uint32_t kClockPolicyVersion = 1;

// The engine default, an offline calibration (no host measurement ever
// enters it):
//   * tsc_per_block 150,000 = 2.4 GHz / 16,000 blocks/s - a ~native-scale
//     virtual TSC at the engine's block rate, so delay loops sized for real
//     hardware complete in bounded emulation time.
//   * blocks_per_tick 16 = one guest millisecond - the same compression
//     order as the retired instruction-count clock (128 insns/ms at ~8
//     insns/block).
//   * base_tsc / base_qpc: fixed nonzero boot-shaped starting points (60s
//     since boot in each face's own units) - real machines never read zero,
//     and constants carry no entropy.
//   * CPUID 0x15/0x16 shape the same 2.4 GHz (0x16 in MHz; 0x15 as the
//     crystal/ratio pair the SDM formula folds into frequency). Ratio
//     closure with the measured TSC face wins over silicon archaeology -
//     real Haswell parts often omit 0x15 entirely.
inline constexpr ClockPolicy kDefaultClockPolicy{
    .policy_version = kClockPolicyVersion,
    .base_tsc = 0x218711A700ULL, // 60s at 2.4 GHz
    .tsc_per_block = 150000,
    .blocks_per_tick = 16,
    .qpc_frequency = 10000000,        // Windows invariant TSC QPC rate
    .base_qpc = 600000000ULL,         // 60s at 10 MHz
    .qpc_per_block = 625,             // 10 MHz / 16,000 blocks/s
    .cpuid_0x15 = {1, 100, 24000000}, // EAX denom, EBX numer, crystal Hz
    .cpuid_0x16 = {2400, 2400, 100},  // base MHz, max MHz, bus MHz
};

inline ClockPolicy default_clock_policy()
{
    return kDefaultClockPolicy;
}

} // namespace sheller::snapshot

#endif // SHELLER_CLOCK_POLICY_H
