// The deterministic virtual clock's pins: the block-count pure functions on
// the run state, the KUSER_SHARED_DATA threshold publication, the derived
// QPC syscall answer, the CPUID time leaves, the rate-ratio closure across
// the clock faces, the container-less default policy (a v1 fixture carries
// no clock block), and the leg-layout independence pin - the same container
// run under different leg partitions answers identically at the same block
// position.
//
// The rdtsc answer trace (SHELLER_RDTSC_TRACE) is this binary's observation
// channel for the leg-layout pin; main() sets it before anything can cache
// the switch. Trace-off silence is engine_trace_test's contract, not this
// file's.

#ifdef _WIN32
#define _CRT_NONSTDC_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "engine_hooks.h"
#include "loader_route.h"
#include "log_detail.h"
#include "rebuild_state.h"
#include "snapshot_fixture.h"
#include "syscall_dispatch.h"

#include <sheller/clock_policy.h>
#include <sheller/log.h>
#include <sheller/snapshot.h>
#include <sheller/syscallrun.h>

#include <gtest/gtest.h>
#include <unicorn/unicorn.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace snapshot = sheller::snapshot;
namespace engine = sheller::engine;
namespace syscalls = sheller::syscalls;
namespace fixture = sheller_test;

constexpr std::uint64_t kKUser = 0x7FFE0000;
constexpr std::uint64_t kTickLow = kKUser + 0x320;
constexpr std::uint64_t kWorkBase = 0x7FF900000000;

// The three same-value TickCount fields (0x7FFE0004/0x320/0x324 - the
// engine's long-standing contract).
constexpr std::array<std::uint64_t, 3> kTickFields{kKUser + 4, kKUser + 0x320, kKUser + 0x324};

uc_engine*& uc_handle()
{
    static uc_engine* handle = nullptr;
    return handle;
}

std::uint32_t read_tick_field(uc_engine* uc, const std::uint64_t address)
{
    std::uint32_t value = 0;
    EXPECT_EQ(uc_mem_read(uc, address, &value, sizeof value), UC_ERR_OK);
    return value;
}

// A run state answering from the engine default policy.
engine::SyscallRunState default_clock_state()
{
    engine::SyscallRunState state;
    state.clock = snapshot::default_clock_policy();
    return state;
}

// ---- unit pins: the pure functions and the threshold publication ----------

TEST(VirtualClock, TickCountIsQuantizedBlocksPerTick)
{
    auto state = default_clock_state();
    EXPECT_EQ(state.virtual_ticks(), 0U);
    state.blocks = 15;
    EXPECT_EQ(state.virtual_ticks(), 0U);
    state.blocks = 16;
    EXPECT_EQ(state.virtual_ticks(), 1U);
    state.blocks = 31;
    EXPECT_EQ(state.virtual_ticks(), 1U);
    state.blocks = 32;
    EXPECT_EQ(state.virtual_ticks(), 2U);
}

TEST(VirtualClock, TscIsBasePlusPerBlockTimesBlocks)
{
    auto state = default_clock_state();
    const auto& policy = snapshot::kDefaultClockPolicy;
    EXPECT_EQ(state.virtual_tsc(), policy.base_tsc);
    state.blocks = 1000;
    EXPECT_EQ(state.virtual_tsc(), policy.base_tsc + policy.tsc_per_block * 1000ULL);
}

TEST(VirtualClock, KusdPublishesOnlyOnThresholdCrossing)
{
    ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &uc_handle()), UC_ERR_OK);
    auto page = engine::allocate_kuser_page();
    ASSERT_NE(page, nullptr);
    ASSERT_EQ(uc_mem_map_ptr(uc_handle(), kKUser, 0x1000, UC_PROT_READ, page.get()), UC_ERR_OK);
    // The seed-leak detector: a nonzero tick in the mapped page.
    const std::uint32_t seed = 0x10000000;
    std::memcpy(page.get() + 0x320, &seed, sizeof seed);
    std::memcpy(page.get() + 0x004, &seed, sizeof seed);
    std::memcpy(page.get() + 0x324, &seed, sizeof seed);

    auto state = default_clock_state();
    state.kuser_host_page = page.get();
    // Below the first threshold nothing is written - the run start's forced
    // publication is what overwrites the seed, not the block hook.
    state.blocks = 15;
    engine::publish_kusd_ticks(state, false);
    EXPECT_EQ(read_tick_field(uc_handle(), kTickLow), 0x10000000U);
    // Crossing publishes the quantized value to all three fields.
    state.blocks = 16;
    engine::publish_kusd_ticks(state, false);
    for (const std::uint64_t field : kTickFields) {
        EXPECT_EQ(read_tick_field(uc_handle(), field), 1U) << std::hex << field;
    }
    // Between crossings: one compare, no store.
    state.blocks = 17;
    engine::publish_kusd_ticks(state, false);
    EXPECT_EQ(read_tick_field(uc_handle(), kTickLow), 1U);
    state.blocks = 48;
    engine::publish_kusd_ticks(state, false);
    EXPECT_EQ(read_tick_field(uc_handle(), kTickLow), 3U);
    uc_close(uc_handle());
    uc_handle() = nullptr;
}

TEST(VirtualClock, DispatchQpcAnswersDerivedCounterAndPolicyFrequency)
{
    ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &uc_handle()), UC_ERR_OK);
    ASSERT_EQ(uc_mem_map(uc_handle(), kWorkBase, 0x10000, UC_PROT_ALL), UC_ERR_OK);
    constexpr std::uint64_t kCounterPtr = kWorkBase + 0x800;
    constexpr std::uint64_t kFreqPtr = kWorkBase + 0x810;

    auto state = default_clock_state();
    state.policy.set_builtin(0x1234, syscalls::BuiltinHandler::kQueryPerformanceCounter);
    syscalls::SyscallFrame frame{};
    frame.number = 0x1234;
    frame.rcx = kCounterPtr;
    frame.rdx = kFreqPtr;
    const auto outcome = engine::dispatch_one_syscall(&state, uc_handle(), frame);
    ASSERT_EQ(outcome.status, syscalls::kStatusSuccess);
    const auto& policy = snapshot::kDefaultClockPolicy;
    std::uint64_t value = 0;
    ASSERT_EQ(uc_mem_read(uc_handle(), kCounterPtr, &value, sizeof value), UC_ERR_OK);
    EXPECT_EQ(value, policy.base_qpc); // blocks = 0: the base alone
    ASSERT_EQ(uc_mem_read(uc_handle(), kFreqPtr, &value, sizeof value), UC_ERR_OK);
    EXPECT_EQ(value, policy.qpc_frequency);
    EXPECT_NE(value, 0U);

    // The counter moves with the block position: the same pure function.
    state.blocks = 100;
    const auto later = engine::dispatch_one_syscall(&state, uc_handle(), frame);
    ASSERT_EQ(later.status, syscalls::kStatusSuccess);
    ASSERT_EQ(uc_mem_read(uc_handle(), kCounterPtr, &value, sizeof value), UC_ERR_OK);
    EXPECT_EQ(value, policy.base_qpc + policy.qpc_per_block * 100ULL);

    // Fail-soft: an unwritable counter pointer rejects the call.
    syscalls::SyscallFrame bad = frame;
    bad.rcx = 0x5FF900000000; // unmapped
    bad.rdx = 0;
    const auto refused = engine::dispatch_one_syscall(&state, uc_handle(), bad);
    EXPECT_EQ(refused.status, syscalls::kStatusAccessViolation);
    uc_close(uc_handle());
    uc_handle() = nullptr;
}

TEST(VirtualClock, CpuidTimeLeavesAnswerThePolicy)
{
    ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &uc_handle()), UC_ERR_OK);
    auto state = default_clock_state();
    const auto& policy = snapshot::kDefaultClockPolicy;
    // The enumerate-then-query shape: leaf 0 advertises a limit that names
    // the time leaves, so a guest walking leaves 0..max reaches them.
    {
        std::uint64_t rax = 0;
        std::uint64_t rcx = 0;
        ASSERT_EQ(uc_reg_write(uc_handle(), UC_X86_REG_RAX, &rax), UC_ERR_OK);
        ASSERT_EQ(uc_reg_write(uc_handle(), UC_X86_REG_RCX, &rcx), UC_ERR_OK);
        ASSERT_TRUE(engine::on_cpuid_callback(uc_handle(), &state));
        std::uint64_t max_leaf = 0;
        ASSERT_EQ(uc_reg_read(uc_handle(), UC_X86_REG_EAX, &max_leaf), UC_ERR_OK);
        EXPECT_EQ(max_leaf, 0x16U);
    }
    for (const std::uint32_t leaf : {0x15U, 0x16U}) {
        std::uint64_t rax = leaf;
        std::uint64_t rcx = 0;
        ASSERT_EQ(uc_reg_write(uc_handle(), UC_X86_REG_RAX, &rax), UC_ERR_OK);
        ASSERT_EQ(uc_reg_write(uc_handle(), UC_X86_REG_RCX, &rcx), UC_ERR_OK);
        ASSERT_TRUE(engine::on_cpuid_callback(uc_handle(), &state));
        const auto& answers = leaf == 0x15 ? policy.cpuid_0x15 : policy.cpuid_0x16;
        std::uint64_t got = 0;
        ASSERT_EQ(uc_reg_read(uc_handle(), UC_X86_REG_EAX, &got), UC_ERR_OK);
        EXPECT_EQ(got, answers[0]) << "leaf " << std::hex << leaf;
        ASSERT_EQ(uc_reg_read(uc_handle(), UC_X86_REG_EBX, &got), UC_ERR_OK);
        EXPECT_EQ(got, answers[1]) << "leaf " << std::hex << leaf;
        ASSERT_EQ(uc_reg_read(uc_handle(), UC_X86_REG_ECX, &got), UC_ERR_OK);
        EXPECT_EQ(got, answers[2]) << "leaf " << std::hex << leaf;
    }
    uc_close(uc_handle());
    uc_handle() = nullptr;
}

TEST(VirtualClock, DefaultPolicyRatesCloseAcrossFaces)
{
    // 16,000 blocks/s is the blocks_per_tick anchor (16 blocks per guest ms):
    // every face folded to a frequency must land on the same 2.4 GHz TSC
    // face and the same 10 MHz QPC face.
    const auto& policy = snapshot::kDefaultClockPolicy;
    constexpr std::uint64_t kBlocksPerSecond = 16000;
    EXPECT_EQ(policy.tsc_per_block * kBlocksPerSecond, 2400000000ULL);
    EXPECT_EQ(policy.qpc_per_block * kBlocksPerSecond, policy.qpc_frequency);
    EXPECT_EQ(policy.qpc_frequency, 10000000ULL);
    // CPUID 0x15: crystal (ECX) * EBX / EAX = the TSC face.
    EXPECT_EQ(policy.cpuid_0x15[2] * policy.cpuid_0x15[1] / policy.cpuid_0x15[0], 2400000000ULL);
    // CPUID 0x16: the base frequency (EAX, MHz) is the TSC face.
    EXPECT_EQ(policy.cpuid_0x16[0], 2400U);
}

// ---- the fixture world with a KUSER page -----------------------------------
//
// snapshot_fixture's crafted container has no KUSER page; the clock tests
// need one, seeded with a nonzero tick so a leaked seed is visible.
// Everything else mirrors craft_snapshot (one RWX code page, stack, TEB).

constexpr std::uint64_t kClockStackRegionBase = 0x07F00000;
constexpr std::uint64_t kClockStackVa = kClockStackRegionBase + 0x800;

std::vector<std::uint8_t> craft_clock_snapshot(const std::vector<std::uint8_t>& code)
{
    std::vector<std::uint8_t> page(0x1000, std::uint8_t{0});
    std::copy(code.begin(), code.end(), page.begin());
    std::vector<std::uint8_t> stack(0x1000, std::uint8_t{0x5A});
    std::vector<std::uint8_t> teb(0x1000, std::uint8_t{0});
    std::vector<std::uint8_t> kuser(0x1000, std::uint8_t{0});
    constexpr std::uint32_t kSeedTick = 0x10000000;
    std::memcpy(kuser.data() + 0x320, &kSeedTick, sizeof kSeedTick);

    snapshot::Metadata metadata{};
    metadata.teb_address = 0x07F10100;
    metadata.image_base = fixture::kImageBase;
    metadata.entry_address = fixture::kImageBase;
    std::copy_n(page.begin(), metadata.original_entry_bytes.size(),
                metadata.original_entry_bytes.begin());

    snapshot::Registers registers{};
    registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRsp)] = kClockStackVa;
    registers.rip = fixture::kImageBase;
    registers.rflags = fixture::kFixtureRflags;

    std::ostringstream out;
    snapshot::Writer writer{out};
    if (!writer.write_header(
            snapshot::Header{.version = snapshot::kVersion, .bitness = snapshot::kBitness64}) ||
        !writer.write_registers(registers) || !writer.write_metadata(metadata) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = fixture::kImageBase,
                                                    .size = 0x1000,
                                                    .protection = fixture::kPageExecuteReadwrite,
                                                    .type = fixture::kMemImage,
                                                    .content = snapshot::kContentPresent},
                             page.data()) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = kClockStackRegionBase,
                                                    .size = 0x1000,
                                                    .protection = fixture::kPageReadwrite,
                                                    .type = fixture::kMemPrivate,
                                                    .content = snapshot::kContentPresent},
                             stack.data()) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = kKUser,
                                                    .size = 0x1000,
                                                    .protection = fixture::kPageReadwrite,
                                                    .type = fixture::kMemPrivate,
                                                    .content = snapshot::kContentPresent},
                             kuser.data()) ||
        !writer.finalize_region_count()) {
        ADD_FAILURE() << "clock snapshot serialization failed";
    }
    const auto str = out.str();
    return {str.begin(), str.end()};
}

// mov eax, dword [0x7FFE0320] (absolute moffs form).
constexpr std::array<std::uint8_t, 7> kReadTickLow{0x8B, 0x04, 0x25, 0x20, 0x03, 0xFE, 0x7F};
// mov r8d, dword [0x7FFE0320].
constexpr std::array<std::uint8_t, 8> kReadTickLowR8{0x44, 0x8B, 0x04, 0x25,
                                                     0x20, 0x03, 0xFE, 0x7F};

TEST(VirtualClock, ContainerWithoutClockBlockStartsAtTickZero)
{
    // The default-policy acceptance: the fixture is a v1 container - no
    // clock block - and the engine answers from the engine default. The
    // guest proves the forced first publication: a nonzero seed still in
    // the TickCount field takes the ud2 branch (an unhandled crash), the
    // published tick(0) = 0 takes the spin (a deterministic block-budget
    // stop).
    std::vector<std::uint8_t> code;
    code.insert(code.end(), kReadTickLow.begin(), kReadTickLow.end()); // eax = [0x7FFE0320]
    code.insert(code.end(), {0x85, 0xC0});                             // test eax, eax
    code.insert(code.end(), {0x74, 0x02});                             // je spin
    code.insert(code.end(), {0x0F, 0x0B});                             // ud2
    code.insert(code.end(), {0xEB, 0xFE});                             // spin: jmp spin

    engine::SyscallRunOptions options;
    options.max_blocks = 200;
    const auto run = engine::run_snapshot_syscalls(craft_clock_snapshot(code), options);
    ASSERT_FALSE(run.has_value());
    // The budget stop, not the crash: the seed did not leak through.
    EXPECT_EQ(run.error().error, engine::SyscallRunError::kBudgetExhausted);
    EXPECT_EQ(run.error().stats.blocks, 200U);
}

TEST(VirtualClock, KusdBusyWaitExitsOnTheVirtualTickAdvance)
{
    // r8d = [0x7FFE0320]; loop while eax == r8d; ud2 on change. The initial
    // publication answers 0; the block hook publishes 1 at block 16 - so
    // the busy-wait exits in a handful of blocks without any host wall
    // clock. A dead clock would spin to the block budget instead.
    std::vector<std::uint8_t> code;
    code.insert(code.end(), kReadTickLowR8.begin(), kReadTickLowR8.end());
    code.insert(code.end(), kReadTickLow.begin(), kReadTickLow.end()); // loop: eax = field
    code.insert(code.end(), {0x41, 0x39, 0xC0});                       // cmp eax, r8d
    code.insert(code.end(), {0x74, 0xF4});                             // je loop (0x08)
    code.insert(code.end(), {0x0F, 0x0B});                             // ud2 on change

    engine::SyscallRunOptions options;
    options.max_blocks = 200;
    const auto run = engine::run_snapshot_syscalls(craft_clock_snapshot(code), options);
    ASSERT_FALSE(run.has_value()) << "the busy-wait never saw a tick advance";
    EXPECT_EQ(run.error().error, engine::SyscallRunError::kUnhandledException);
    EXPECT_LT(run.error().stats.blocks, 100U);
}

// ---- the leg-layout pin -----------------------------------------------------

std::vector<std::string>& rdtsc_lines()
{
    static auto* const held = new std::vector<std::string>();
    return *held;
}

void install_rdtsc_sink()
{
    sheller::log::detail::set_sink_impl(
        [](const sheller::log::level, const std::string_view message) {
            if (message.find("[rdtsc]") != std::string_view::npos) {
                rdtsc_lines().emplace_back(message);
            }
        },
        sheller::log::level::kDebug);
}

// Ten two-instruction stubs rotate through the burn detector's eight slots.
// S0 reads TSC; S6 reads TickCount; S9 decrements the counter and loops.
// The partition harness observes S6's result at its jump, after the load.
std::vector<std::uint8_t> clock_loop_code()
{
    return {0x0F, 0x31,                               // S0 @0x00: rdtsc
            0xEB, 0x00,                               //       jmp S1
            0x90,                                     // S1 @0x04: nop
            0xEB, 0x00,                               //       jmp S2
            0x90,                                     // S2 @0x07: nop
            0xEB, 0x00,                               //       jmp S3
            0x90,                                     // S3 @0x0A: nop
            0xEB, 0x00,                               //       jmp S4
            0x90,                                     // S4 @0x0D: nop
            0xEB, 0x00,                               //       jmp S5
            0x90,                                     // S5 @0x10: nop
            0xEB, 0x00,                               //       jmp S6
            0x8B, 0x04, 0x25, 0x20, 0x03,             // S6 @0x13: mov eax,[0x7FFE0320]
            0xFE, 0x7F,                               //          (absolute moffs, 7 bytes)
            0xEB, 0x00,                               //       jmp S7
            0x90,                                     // S7 @0x1C: nop
            0xEB, 0x00,                               //       jmp S8
            0x90,                                     // S8 @0x1F: nop
            0xEB, 0x00,                               //       jmp S9
            0xFF, 0xCB,                               // S9 @0x22: dec ebx
            0x75, 0xDA,                               //       jnz S0 (0x22+4=0x26 -> 0x00 = -38)
            0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, // mov rcx, -1
            0x48, 0xC7, 0xC2, 0x34, 0x12, 0x00, 0x00, // mov rdx, 0x1234
            0xB8, 0x02, 0x10, 0x00, 0x00,             // mov eax, 0x1002
            0x0F, 0x05};                              // syscall
}

using ClockReads = std::array<std::uint64_t, 7>; // blocks, guest tick, 3 fields, QPC, Hz

struct ClockReadProbe {
    engine::SyscallRunState* state{};
    std::vector<ClockReads> reads;
};

void observe_clock_reads(uc_engine* uc, const std::uint64_t address, const std::uint32_t,
                         void* user_data)
{
    if ((address - fixture::kImageBase) % 0x26 != 0x1A) {
        return;
    }
    auto& probe = *static_cast<ClockReadProbe*>(user_data);
    auto& state = *probe.state;
    ClockReads values{state.blocks};
    EXPECT_EQ(uc_reg_read(uc, UC_X86_REG_RAX, &values[1]), UC_ERR_OK);
    for (std::size_t i = 0; i < kTickFields.size(); ++i) {
        values[2 + i] = read_tick_field(uc, kTickFields[i]);
    }
    // Exercise the engine's QPC dispatch at this same block position. The
    // fixture has no ntdll number table, so register a test-only number.
    syscalls::SyscallFrame frame{};
    frame.number = 0x1234;
    frame.rcx = kClockStackRegionBase + 0x800;
    frame.rdx = kClockStackRegionBase + 0x810;
    EXPECT_EQ(engine::dispatch_one_syscall(&state, uc, frame).status, syscalls::kStatusSuccess);
    EXPECT_EQ(uc_mem_read(uc, frame.rcx, &values[5], sizeof values[5]), UC_ERR_OK);
    EXPECT_EQ(uc_mem_read(uc, frame.rdx, &values[6], sizeof values[6]), UC_ERR_OK);
    probe.reads.push_back(values);
}

void run_clock_partition(const std::size_t iterations_per_leg, std::vector<std::string>& trace,
                         std::vector<ClockReads>& reads)
{
    // Unroll the ten-stub iteration into a finite chain: distinct addresses
    // let each address stop apply without reusing a TB translated for an old
    // until address. Each copy falls through to the next instead of looping.
    auto iteration = clock_loop_code();
    iteration.resize(0x26);
    iteration[0x24] = 0xEB;
    iteration[0x25] = 0;
    std::vector<std::uint8_t> code;
    for (std::size_t i = 0; i < 60; ++i) {
        code.insert(code.end(), iteration.begin(), iteration.end());
    }
    const auto container = craft_clock_snapshot(code);
    std::istringstream in(std::string(container.begin(), container.end()));
    auto guest = engine::prepare_guest_stream(in);
    ASSERT_TRUE(guest.has_value());
    auto* uc = guest->unicorn.get();
    auto state = default_clock_state();
    state.kuser_host_page = guest->kuser_host_page.get();
    state.rdtsc_trace = true;
    state.policy.set_builtin(0x1234, syscalls::BuiltinHandler::kQueryPerformanceCounter);
    ClockReadProbe probe{&state, {}};
    uc_hook block_hook = 0, tsc_hook = 0, read_hook = 0;
    ASSERT_EQ(uc_hook_add(uc, &block_hook, UC_HOOK_BLOCK,
                          reinterpret_cast<void*>(engine::on_syscall_run_block), &state, 1, 0),
              UC_ERR_OK);
    ASSERT_EQ(uc_hook_add(uc, &tsc_hook, UC_HOOK_INSN,
                          reinterpret_cast<void*>(engine::on_rdtsc_callback), &state, 1, 0,
                          UC_X86_INS_RDTSC),
              UC_ERR_OK);
    ASSERT_EQ(uc_hook_add(uc, &read_hook, UC_HOOK_CODE,
                          reinterpret_cast<void*>(observe_clock_reads), &probe, fixture::kImageBase,
                          fixture::kImageBase + code.size() - 1),
              UC_ERR_OK);
    engine::publish_kusd_ticks(state, true);
    rdtsc_lines().clear();
    // Address stops occur before the next block's hook. Instruction-count
    // stops enter an extra unexecuted block in Unicorn; that existing budget
    // behavior is excluded here. A stops after every two copies, B every
    // three; both execute the same complete chain with different boundaries.
    std::uint64_t begin = fixture::kImageBase;
    for (std::size_t i = iterations_per_leg; i <= 60; i += iterations_per_leg) {
        const auto until = fixture::kImageBase + i * iteration.size();
        ASSERT_EQ(uc_emu_start(uc, begin, until, 0, 0), UC_ERR_OK);
        ASSERT_EQ(uc_reg_read(uc, UC_X86_REG_RIP, &begin), UC_ERR_OK);
        ASSERT_EQ(begin, until);
        ASSERT_FALSE(state.loop_probe_pending);
    }
    EXPECT_EQ(state.blocks, 600U);
    trace = rdtsc_lines();
    reads = std::move(probe.reads);
}

TEST(VirtualClock, AnswersDoNotDependOnTheLegLayout)
{
    install_rdtsc_sink();
    std::vector<std::string> first_lines, second_lines;
    std::vector<ClockReads> first_reads, second_reads;
    // Drive the production block, instruction and QPC hooks over the same
    // rebuilt container with different early-stop boundaries in every iteration.
    // Compare every read in the entire run, including reads after unequal stops.
    run_clock_partition(2, first_lines, first_reads);
    run_clock_partition(3, second_lines, second_reads);
    ASSERT_EQ(first_lines.size(), 60U);
    ASSERT_EQ(second_lines.size(), first_lines.size());
    ASSERT_EQ(first_reads.size(), 60U);
    ASSERT_EQ(second_reads, first_reads);
    const auto& policy = snapshot::kDefaultClockPolicy;
    for (const auto& values : first_reads) {
        for (std::size_t i = 1; i <= 4; ++i) {
            EXPECT_EQ(values[i], values[0] / policy.blocks_per_tick);
        }
        EXPECT_EQ(values[5], policy.base_qpc + policy.qpc_per_block * values[0]);
        EXPECT_EQ(values[6], policy.qpc_frequency);
    }
    constexpr std::size_t kBlocksPrefix = 15; // "[rdtsc] blocks="
    for (std::size_t i = 0; i < first_lines.size(); ++i) {
        ASSERT_EQ(first_lines[i], second_lines[i]) << "line " << i;
        const std::uint64_t blocks =
            std::strtoull(first_lines[i].c_str() + kBlocksPrefix, nullptr, 10);
        const auto tsc_at = first_lines[i].find("tsc=0x");
        ASSERT_NE(tsc_at, std::string::npos) << first_lines[i];
        const std::uint64_t tsc = std::strtoull(first_lines[i].c_str() + tsc_at + 6, nullptr, 16);
        EXPECT_EQ(tsc, policy.base_tsc + policy.tsc_per_block * blocks) << first_lines[i];
    }
}

} // namespace

int main(int argc, char** argv)
{
    // Before anything can cache the switch: this binary observes the clock
    // through the rdtsc answer trace.
#ifdef _WIN32
    _putenv_s("SHELLER_RDTSC_TRACE", "1");
#else
    setenv("SHELLER_RDTSC_TRACE", "1", 1);
#endif
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
