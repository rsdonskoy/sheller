// ESP-law stop target tests: crafted save/restore
// corpora drive the engine entry directly through the public
// run_snapshot_syscalls, so every address in play is a fixture constant.
// The faces: the esp form stops inside the completed restore read (the
// landing tail never runs); esp+xfer arms there and the xfer machinery
// takes the stop before the landing block; a window read that is not a pop
// (the anti-debug shape) never stops; the silent cells - entry without
// pushes, relocated stack - close on the miss path; the burn-loop probe's
// speculation keeps the window silent and keeps its fast-forward; and a run
// that never asked for an esp goal is untouched.

#include "esp_fixture.h"
#include "snapshot_fixture.h"
#include "test_temp.hpp"

#include <sheller/syscallrun.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

namespace {

namespace engine = sheller::engine;

using sheller_test::craft_esp_arm_snapshot;
using sheller_test::craft_esp_early_xfer_snapshot;
using sheller_test::craft_esp_page_end_restore_snapshot;
using sheller_test::craft_esp_snapshot;
using sheller_test::esp_anti_debug_code;
using sheller_test::esp_hit_code;
using sheller_test::esp_pop_rsp_code;
using sheller_test::esp_probe_guard_code;
using sheller_test::esp_relocated_stack_code;

engine::SyscallRunOptions options_with(const engine::EspStopGoal goal)
{
    engine::SyscallRunOptions options;
    options.max_instructions = 100000000; // the delay-loop fixtures outlive 1M
    options.timeout_ms = 60000;
    options.esp_stop_goal = goal;
    return options;
}

TEST(EspTarget, HitStopsInsideTheCompletedRestore)
{
    const auto result = engine::run_snapshot_syscalls(
        craft_esp_snapshot(esp_hit_code()), options_with(engine::EspStopGoal::kStopAtRestore));
    ASSERT_TRUE(result.has_value());
    const auto& stats = *result;
    EXPECT_TRUE(stats.esp_stop);
    EXPECT_FALSE(stats.terminated);
    EXPECT_EQ(stats.exit_code, 0u);
    // The stop landed mid-block: the fixture is one linear block ending at
    // the terminate syscall, counted twice because the first stack write
    // splits the leg (the write-prot claim stops the leg and the block
    // re-enters). One logical block, zero syscalls: the exact face of "the
    // restore was confirmed, the tail never ran".
    EXPECT_EQ(stats.blocks, 2u);
    EXPECT_EQ(stats.syscalls, 0u);
}

TEST(EspTarget, ArmFormStopsAtTheNextTransfer)
{
    const auto result = engine::run_snapshot_syscalls(
        craft_esp_arm_snapshot(), options_with(engine::EspStopGoal::kArmThenNextXfer));
    ASSERT_TRUE(result.has_value());
    const auto& stats = *result;
    // The arm form's stop is the xfer machinery's: the jump is the run's
    // only transfer, the landing block (the terminate tail) never executes.
    // The stop is still the esp goal's hit - esp_stop rides alongside
    // xfer_stop with xfers carrying the ordinal (the public contract in
    // the public syscallrun contract).
    EXPECT_TRUE(stats.esp_stop);
    EXPECT_TRUE(stats.xfer_stop);
    EXPECT_EQ(stats.xfers, 1u);
    EXPECT_FALSE(stats.terminated);
    // Leg split (the first stack write) plus the landing block's own hook
    // tick: the xfer stop fires inside the landing block's start hook, so
    // the block counts before its first instruction runs.
    EXPECT_EQ(stats.blocks, 3u);
    EXPECT_EQ(stats.syscalls, 0u);
}

TEST(EspTarget, PopRspPivotIsNotARestore)
{
    // The stack-pivot shape: the completion slot's pop writes RSP itself, so
    // the post-retirement pointer never returns to the entry face. The read
    // passes the window and RSP gates - the decode gate has to reject the
    // pivot destination, and the run closes on its own terminate.
    const auto result = engine::run_snapshot_syscalls(
        craft_esp_snapshot(esp_pop_rsp_code()), options_with(engine::EspStopGoal::kStopAtRestore));
    ASSERT_TRUE(result.has_value());
    const auto& stats = *result;
    EXPECT_FALSE(stats.esp_stop);
    EXPECT_FALSE(stats.xfer_stop);
    EXPECT_TRUE(stats.terminated);
    EXPECT_EQ(stats.exit_code, 0x1234u);
    EXPECT_EQ(stats.syscalls, 1u);
}

TEST(EspTarget, PageEndRestoreStillConfirms)
{
    // The completion pop sits with 7 mapped bytes behind it (image offset
    // 0xFF9 in a page ending at 0xFFF): a decodable 1-byte pop is complete
    // from its own bytes, and the short-read decode accepts it.
    const auto result = engine::run_snapshot_syscalls(
        craft_esp_page_end_restore_snapshot(), options_with(engine::EspStopGoal::kStopAtRestore));
    ASSERT_TRUE(result.has_value());
    const auto& stats = *result;
    EXPECT_TRUE(stats.esp_stop);
    EXPECT_FALSE(stats.terminated);
    EXPECT_EQ(stats.syscalls, 0u);
}

TEST(EspTarget, ExplicitXferBeforeRestoreIsNotAnEspStop)
{
    // The coexistence case: an explicit xfer ordinal (xfer_number=1, the
    // public API spelling of the CLI's --stop xfer=1) alongside the arm goal,
    // the transfer arrives before any restore confirms. The stop belongs to
    // the xfer target alone - esp_stop stays clear and the arm never set.
    auto options = options_with(engine::EspStopGoal::kArmThenNextXfer);
    options.xfer_number = 1;
    const auto result = engine::run_snapshot_syscalls(craft_esp_early_xfer_snapshot(), options);
    ASSERT_TRUE(result.has_value());
    const auto& stats = *result;
    EXPECT_TRUE(stats.xfer_stop);
    EXPECT_FALSE(stats.esp_stop);
    EXPECT_EQ(stats.xfers, 1u);
    EXPECT_FALSE(stats.terminated);
    EXPECT_EQ(stats.syscalls, 0u);
}

TEST(EspTarget, HitFormOnTheArmFixtureStopsBeforeTheJump)
{
    const auto result = engine::run_snapshot_syscalls(
        craft_esp_arm_snapshot(), options_with(engine::EspStopGoal::kStopAtRestore));
    ASSERT_TRUE(result.has_value());
    const auto& stats = *result;
    EXPECT_TRUE(stats.esp_stop);
    EXPECT_FALSE(stats.xfer_stop);
    EXPECT_EQ(stats.xfers, 0u); // the jump never ran
    EXPECT_EQ(stats.blocks, 2u);
    EXPECT_EQ(stats.syscalls, 0u);
}

TEST(EspTarget, NonPopWindowReadDoesNotStop)
{
    // The anti-debug shape: the window is read with the callback rsp at the
    // slot address, but the reader is a mov - only the decode gate rejects
    // it, and the run closes on its own terminate.
    const auto result =
        engine::run_snapshot_syscalls(craft_esp_snapshot(esp_anti_debug_code()),
                                      options_with(engine::EspStopGoal::kStopAtRestore));
    ASSERT_TRUE(result.has_value());
    const auto& stats = *result;
    EXPECT_FALSE(stats.esp_stop);
    EXPECT_TRUE(stats.terminated);
    EXPECT_EQ(stats.exit_code, 0x1234u);
    EXPECT_EQ(stats.syscalls, 1u);
}

TEST(EspTarget, RelocatedStackClosesOnTheMissPath)
{
    // The VM shape: the window arms (the entry pushes once) and is never
    // read - the run closes on the miss path, exactly like a goal that was
    // never requested.
    const auto result =
        engine::run_snapshot_syscalls(craft_esp_snapshot(esp_relocated_stack_code()),
                                      options_with(engine::EspStopGoal::kStopAtRestore));
    ASSERT_TRUE(result.has_value());
    const auto& stats = *result;
    EXPECT_FALSE(stats.esp_stop);
    EXPECT_TRUE(stats.terminated);
    EXPECT_EQ(stats.exit_code, 0x1234u);
    EXPECT_EQ(stats.syscalls, 1u);
}

TEST(EspTarget, EntryWithoutPushesIsSilent)
{
    // The instoll shape: the entry opens with something other than a push,
    // the extent is zero, the monitor is not established.
    const auto result =
        engine::run_snapshot_syscalls(sheller_test::xfer_delay_snapshot_bytes(),
                                      options_with(engine::EspStopGoal::kStopAtRestore));
    ASSERT_TRUE(result.has_value());
    const auto& stats = *result;
    EXPECT_FALSE(stats.esp_stop);
    EXPECT_FALSE(stats.xfer_stop); // no xfer goal: the transfer does not stop either
    EXPECT_TRUE(stats.terminated);
    EXPECT_EQ(stats.syscalls, 1u);
}

TEST(EspTarget, ProbeLegsKeepTheWindowSilentAndTheFastForwardAlive)
{
    // A burn loop whose body reads the window, a restore after it. The
    // probe's speculative chunks re-execute those reads with all hooks
    // alive; the esp hook must stay silent inside them, the loop must still
    // fast-forward (bounded blocks - the raw loop is 300000 block
    // executions), and the stop must land on the post-loop restore.
    const auto result =
        engine::run_snapshot_syscalls(craft_esp_snapshot(esp_probe_guard_code()),
                                      options_with(engine::EspStopGoal::kStopAtRestore));
    ASSERT_TRUE(result.has_value());
    const auto& stats = *result;
    EXPECT_TRUE(stats.esp_stop);
    EXPECT_FALSE(stats.terminated);
    EXPECT_EQ(stats.syscalls, 0u);
    EXPECT_LT(stats.blocks, 50000u);
}

TEST(EspTarget, NoGoalRunIsUntouched)
{
    // The same hit corpus with no esp goal: the run never stops at the
    // restore and closes on the terminate - the zero-marginal baseline the
    // default run must keep.
    auto options = options_with(engine::EspStopGoal::kNone);
    options.max_instructions = 1000000;
    const auto result = engine::run_snapshot_syscalls(craft_esp_snapshot(esp_hit_code()), options);
    ASSERT_TRUE(result.has_value());
    const auto& stats = *result;
    EXPECT_FALSE(stats.esp_stop);
    EXPECT_FALSE(stats.xfer_stop);
    EXPECT_TRUE(stats.terminated);
    EXPECT_EQ(stats.exit_code, 0x1234u);
    EXPECT_EQ(stats.syscalls, 1u);
}

} // namespace
