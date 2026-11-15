// on_intercept's two branches against a live engine: a miss (a non-entry
// instruction inside a registered span) is a side-effect-free return - the
// common case since the spans registered - and a hit dispatches through the
// original row and the handler completes against real guest memory.

#include "../src/engine/intercept.h"
#include "../src/engine/intercept_span_dispatch.h"
#include "../src/engine/rebuild_state.h"

#include <gtest/gtest.h>

#include <unicorn/unicorn.h>

#include <cstdint>
#include <vector>

namespace {

namespace engine = sheller::engine;

constexpr std::uint64_t kRegionBase = 0x400000;
constexpr std::uint64_t kRegionSize = 0x10000;
constexpr std::uint64_t kEntryVa = kRegionBase + 0x1000; // the intercepted entry
constexpr std::uint64_t kStringVa = kRegionBase + 0x2000;
constexpr std::uint64_t kStackVa = kRegionBase + 0x8000;
constexpr std::uint64_t kRetVa = kRegionBase + 0x800; // a mapped return address

class InterceptCallback : public ::testing::Test {
  protected:
    void SetUp() override
    {
        uc_engine* uc = nullptr;
        ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &uc), UC_ERR_OK);
        uc_ = uc;
        ASSERT_EQ(uc_mem_map(uc, kRegionBase, kRegionSize, UC_PROT_ALL), UC_ERR_OK);
        // A stack slot with a return address under rsp, and the "hello" the
        // strlen handler walks.
        const std::uint64_t ret = kRetVa;
        ASSERT_EQ(uc_mem_write(uc, kStackVa, &ret, sizeof ret), UC_ERR_OK);
        ASSERT_EQ(uc_mem_write(uc, kStringVa, "hello", 6), UC_ERR_OK);
        static_cast<void>(uc_reg_write(uc, UC_X86_REG_RSP, &kStackVa));
        static_cast<void>(uc_reg_write(uc, UC_X86_REG_RCX, &kStringVa));
        state_.uc = uc;
        state_.intercept_vas = {kEntryVa};
        state_.intercept_ids = {static_cast<std::uint32_t>(engine::InterceptId::kStrlen)};
        state_.intercept_names = {"strlen"};
        state_.intercept_modules = {0};
        state_.intercept_span_table = engine::build_intercept_span_table(state_.intercept_vas);
    }

    void TearDown() override
    {
        if (uc_ != nullptr) {
            uc_close(uc_);
        }
    }

    uc_engine* uc_ = nullptr;
    engine::SyscallRunState state_;
};

// The span shape: every non-entry instruction of the owning module reaches the
// callback and must leave without a trace.
TEST_F(InterceptCallback, MissInsideSpanReturnsWithoutSideEffects)
{
    std::uint64_t rip_before = 0, rsp_before = 0;
    static_cast<void>(uc_reg_read(uc_, UC_X86_REG_RIP, &rip_before));
    static_cast<void>(uc_reg_read(uc_, UC_X86_REG_RSP, &rsp_before));

    engine::on_intercept(uc_, kEntryVa + 0x10, 0, &state_); // strictly inside, not the entry

    EXPECT_EQ(state_.pending_intercept, -1);
    std::uint64_t rip_after = 0, rsp_after = 0, rax_after = 0;
    static_cast<void>(uc_reg_read(uc_, UC_X86_REG_RIP, &rip_after));
    static_cast<void>(uc_reg_read(uc_, UC_X86_REG_RSP, &rsp_after));
    static_cast<void>(uc_reg_read(uc_, UC_X86_REG_RAX, &rax_after));
    EXPECT_EQ(rip_after, rip_before);
    EXPECT_EQ(rsp_after, rsp_before);
    EXPECT_EQ(rax_after, 0U);
}

TEST_F(InterceptCallback, MissOnEmptyTableReturnsWithoutSideEffects)
{
    engine::SyscallRunState empty_state;
    empty_state.uc = uc_;
    engine::on_intercept(uc_, kEntryVa, 0, &empty_state);
    EXPECT_EQ(empty_state.pending_intercept, -1);
}

// A hit dispatches through the original row (0 here), the strlen handler
// answers from real guest memory, and the return consumed the pending slot.
TEST_F(InterceptCallback, HitDispatchesTheHandlerAndPopsTheReturn)
{
    EXPECT_EQ(state_.pending_intercept, -1);
    engine::on_intercept(uc_, kEntryVa, 0, &state_);

    std::uint64_t rax = 0, rip = 0, rsp = 0;
    static_cast<void>(uc_reg_read(uc_, UC_X86_REG_RAX, &rax));
    static_cast<void>(uc_reg_read(uc_, UC_X86_REG_RIP, &rip));
    static_cast<void>(uc_reg_read(uc_, UC_X86_REG_RSP, &rsp));
    EXPECT_EQ(rax, 5U); // strlen("hello")
    EXPECT_EQ(rip, kRetVa);
    EXPECT_EQ(rsp, kStackVa + 8); // the return address popped
    EXPECT_EQ(state_.pending_intercept, -1);
}

// Row fidelity under a shuffled input: the table is sorted, so a hit must
// dispatch through the ORIGINAL row the index kept, not the row's position in
// the table. The two rows answer distinguishably - strlen walks the guest
// string, GetStdHandle answers its pseudo-handle - so the handler choice pins
// the row itself.
TEST_F(InterceptCallback, HitDispatchesTheOriginalRowNotTheTablePosition)
{
    constexpr std::uint64_t kOtherVa = kEntryVa - 0x100; // sorts BEFORE kEntryVa
    engine::SyscallRunState shuffled;
    shuffled.uc = uc_;
    shuffled.intercept_vas = {kEntryVa, kOtherVa}; // declared order, NOT sorted
    shuffled.intercept_ids = {static_cast<std::uint32_t>(engine::InterceptId::kStrlen),
                              static_cast<std::uint32_t>(engine::InterceptId::kGetStdHandle)};
    shuffled.intercept_names = {"strlen", "GetStdHandle"};
    shuffled.intercept_modules = {0, 0};
    shuffled.intercept_span_table = engine::build_intercept_span_table(shuffled.intercept_vas);
    ASSERT_EQ(shuffled.intercept_span_table.size(), 2U);
    ASSERT_EQ(shuffled.intercept_span_table[0].va, kOtherVa); // sorted first...
    ASSERT_EQ(shuffled.intercept_span_table[0].row, 1U);      // ...but it is row 1
    ASSERT_EQ(shuffled.intercept_span_table[1].va, kEntryVa);
    ASSERT_EQ(shuffled.intercept_span_table[1].row, 0U);

    // The entry is table position 1 but original row 0: the strlen handler
    // must answer - the table position would have dispatched GetStdHandle.
    engine::on_intercept(uc_, kEntryVa, 0, &shuffled);
    std::uint64_t rax = 0;
    static_cast<void>(uc_reg_read(uc_, UC_X86_REG_RAX, &rax));
    EXPECT_EQ(rax, 5U); // strlen("hello"), not the GetStdHandle pseudo-handle
}

} // namespace
