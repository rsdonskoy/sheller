// The intercept dispatch index and the span/solo registration split: pure
// table functions, driven over hand-built VA lists, attribution columns and
// module extents. No unicorn, no guest memory, no corpus - the index the span
// callback searches and the lists the registration site reads are the same
// tables, and these cases pin that they agree.
//
// The end-to-end intercept behavior (entry takeover, event identity) lives in
// the loader-route integration tests; this TU pins the mechanism underneath.

#include "../src/engine/intercept_span_dispatch.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {

namespace engine = sheller::engine;

// How many of the selected spans cover this address, under the same inclusive
// extent the hooks are registered over.
std::size_t coverage_count(const std::vector<engine::InterceptSpan>& spans, const std::uint64_t va)
{
    std::size_t count = 0;
    for (const auto& span : spans) {
        if (va >= span.base && va - span.base <= span.size) {
            ++count;
        }
    }
    return count;
}

bool is_solo(const std::vector<std::uint64_t>& solo_vas, const std::uint64_t va)
{
    for (const auto solo : solo_vas) {
        if (solo == va) {
            return true;
        }
    }
    return false;
}

// Unsorted with duplicates: the surviving rows must be the first of each VA,
// in VA order, and every row must still index the input.
TEST(InterceptSpanDispatch, BuildSortsAndKeepsTheFirstRowOfEachVa)
{
    const std::vector<std::uint64_t> vas{0x3000, 0x1000, 0x3000, 0x2000, 0x1000, 0x3000};
    const auto table = engine::build_intercept_span_table(vas);

    ASSERT_EQ(table.size(), 3U);
    EXPECT_EQ(table[0].va, 0x1000U);
    EXPECT_EQ(table[0].row, 1U);
    EXPECT_EQ(table[1].va, 0x2000U);
    EXPECT_EQ(table[1].row, 3U);
    EXPECT_EQ(table[2].va, 0x3000U);
    EXPECT_EQ(table[2].row, 0U);
    // The row is the original table index, not the position here: alias rows
    // keep pointing at the input rows they came from.
    for (const auto& entry : table) {
        EXPECT_EQ(vas[entry.row], entry.va);
    }
}

TEST(InterceptSpanDispatch, BuildOfEmptyInputIsEmpty)
{
    const std::vector<std::uint64_t> vas{};
    EXPECT_TRUE(engine::build_intercept_span_table(vas).empty());
}

// The forwarder shape: one VA entering the table from two modules' export
// rows with different names/modules. The table keeps the first row, and that
// row indexes the identity columns - so the first spelling is the event
// identity, exactly what the linear scan answered.
TEST(InterceptSpanDispatch, ForwarderTwinsKeepTheFirstRowsIdentity)
{
    const std::vector<std::uint64_t> vas{0x7FF001000, 0x7FF002000, 0x5000};
    const std::vector<std::string> names{"EnterCriticalSection", "RtlEnterCriticalSection", ""};
    const std::vector<std::uint16_t> modules{1, 2, engine::kInterceptModuleSentinel};
    const auto table = engine::build_intercept_span_table(vas);

    ASSERT_EQ(table.size(), 3U);
    const auto twin = std::vector<std::uint64_t>{vas[1], vas[1]};
    const auto aliased = engine::build_intercept_span_table(twin);
    ASSERT_EQ(aliased.size(), 1U);
    EXPECT_EQ(aliased[0].row, 0U); // the first row wins, not the second
    EXPECT_EQ(names[aliased[0].row], "EnterCriticalSection");
    EXPECT_EQ(modules[aliased[0].row], 1U);
}

TEST(InterceptSpanDispatch, FindHitsEverySlot)
{
    const std::vector<std::uint64_t> vas{0x9000, 0x1000, 0x5000, 0x3000, 0x7000,
                                         0x2000, 0x8000, 0x4000, 0x6000};
    const auto table = engine::build_intercept_span_table(vas);
    ASSERT_EQ(table.size(), vas.size());
    for (std::size_t slot = 0; slot < table.size(); ++slot) {
        const auto* hit = engine::find_intercept_span_entry(table, table[slot].va);
        ASSERT_NE(hit, nullptr) << "slot " << slot;
        EXPECT_EQ(hit->va, table[slot].va);
        EXPECT_EQ(hit->row, table[slot].row);
    }
}

TEST(InterceptSpanDispatch, FindMissesBelowBetweenAndAbove)
{
    const std::vector<std::uint64_t> vas{0x2000, 0x4000, 0x6000};
    const auto table = engine::build_intercept_span_table(vas);
    EXPECT_EQ(engine::find_intercept_span_entry(table, 0x1FFF), nullptr);
    EXPECT_EQ(engine::find_intercept_span_entry(table, 0x2001), nullptr);
    EXPECT_EQ(engine::find_intercept_span_entry(table, 0x3FFF), nullptr);
    EXPECT_EQ(engine::find_intercept_span_entry(table, 0x5000), nullptr);
    EXPECT_EQ(engine::find_intercept_span_entry(table, 0x6001), nullptr);
    EXPECT_EQ(engine::find_intercept_span_entry(table, 0xFFFFFFFFFFFFFFFFULL), nullptr);
}

TEST(InterceptSpanDispatch, FindOnEmptyTableIsNull)
{
    const std::vector<engine::InterceptSpanEntry> table{};
    EXPECT_EQ(engine::find_intercept_span_entry(table, 0x1000), nullptr);
    EXPECT_EQ(engine::find_intercept_span_entry(table, 0), nullptr);
}

TEST(InterceptSpanDispatch, FindOfAliasVaAnswersTheFirstRow)
{
    const std::vector<std::uint64_t> vas{0x5000, 0x5000, 0x5000};
    const auto table = engine::build_intercept_span_table(vas);
    ASSERT_EQ(table.size(), 1U);
    const auto* hit = engine::find_intercept_span_entry(table, 0x5000);
    ASSERT_NE(hit, nullptr);
    EXPECT_EQ(hit->row, 0U);
}

TEST(InterceptSpanDispatch, SelectOnEmptyInputIsEmpty)
{
    const std::vector<std::uint64_t> vas{};
    const std::vector<std::uint16_t> modules{};
    const std::vector<engine::InterceptModuleExtent> extents{{1, 0x7FF00000, 0x200000}};
    const auto selection = engine::select_intercept_spans(vas, modules, extents);
    EXPECT_TRUE(selection.spans.empty());
    EXPECT_TRUE(selection.solo_vas.empty());
}

// Sentinel-attributed rows keep their individual hook and never make a span,
// whatever their index column neighbors look like.
TEST(InterceptSpanDispatch, SentinelRowsStaySoloAndMakeNoSpan)
{
    const std::vector<std::uint64_t> vas{0x500000000000, 0x7FF001000, 0x7FF002000};
    const std::vector<std::uint16_t> modules{engine::kInterceptModuleSentinel, 1, 1};
    const std::vector<engine::InterceptModuleExtent> extents{
        {1, 0x7FF000000, 0x100000},
        {2, 0x90000000, 0x10000}}; // extent 2 owns no row: no span from it
    const auto selection = engine::select_intercept_spans(vas, modules, extents);

    ASSERT_EQ(selection.spans.size(), 1U);
    EXPECT_EQ(selection.spans[0].base, 0x7FF000000U);
    ASSERT_EQ(selection.solo_vas.size(), 1U);
    EXPECT_EQ(selection.solo_vas[0], 0x500000000000U);
    EXPECT_FALSE(is_solo(selection.solo_vas, 0x7FF001000));
}

// Every module with at least one non-sentinel row gets exactly one span, once,
// no matter how many rows point at it; modules without rows get none.
TEST(InterceptSpanDispatch, OneSpanPerOwningIndexInExtentOrder)
{
    const std::vector<std::uint64_t> vas{0x7FF001000, 0x7FF002000, 0x7FF003000, 0x10001000,
                                         0x10002000};
    const std::vector<std::uint16_t> modules{1, 1, 1, 2, 2};
    const std::vector<engine::InterceptModuleExtent> extents{
        {1, 0x7FF000000, 0x100000}, // rows 0-2 all carry index 1
        {3, 0x80000000, 0x10000},   // no row carries index 3
        {2, 0x10000000, 0x100000},  // rows 3-4 carry index 2
        {2, 0x20000000, 0x100000}}; // duplicate resolution of index 2
    const auto selection = engine::select_intercept_spans(vas, modules, extents);

    ASSERT_EQ(selection.spans.size(), 2U);
    EXPECT_EQ(selection.spans[0].base, 0x7FF000000U);
    EXPECT_EQ(selection.spans[0].size, 0x100000U);
    EXPECT_EQ(selection.spans[1].base, 0x10000000U); // the first extent wins
    EXPECT_EQ(selection.spans[1].size, 0x100000U);
    EXPECT_TRUE(selection.solo_vas.empty());
}

TEST(InterceptSpanDispatch, AllSentinelInputMakesNoSpan)
{
    const std::vector<std::uint64_t> vas{0x500000000000, 0x500000001000};
    const std::vector<std::uint16_t> modules{engine::kInterceptModuleSentinel,
                                             engine::kInterceptModuleSentinel};
    const std::vector<engine::InterceptModuleExtent> extents{{1, 0x7FF00000, 0x100000}};
    const auto selection = engine::select_intercept_spans(vas, modules, extents);
    EXPECT_TRUE(selection.spans.empty());
    ASSERT_EQ(selection.solo_vas.size(), 2U);
    EXPECT_EQ(selection.solo_vas[0], 0x500000000000U);
    EXPECT_EQ(selection.solo_vas[1], 0x500000001000U);
}

// The coverage hard invariant: a non-sentinel row the selected spans fail to
// cover exactly once degrades to a solo row - the attribution said "owned"
// but no span reaches the VA (drifted geometry, an index that resolved to no
// extent, a VA past its owner's chosen extent). The registration surface
// never loses the row either way.
TEST(InterceptSpanDispatch, UncoveredNonSentinelRowsDegradeToSolo)
{
    // The row's index resolves, but its VA sits past the first matching
    // extent's end: the duplicate-index extents below model exactly that
    // drift (the row lives in the second record's extent, the span took the
    // first's).
    const std::vector<std::uint64_t> vas{0x30001000, 0x10001000, 0x10002000};
    const std::vector<std::uint16_t> modules{2, 1, 1};
    const std::vector<engine::InterceptModuleExtent> extents{
        {1, 0x10000000, 0x100000},
        {2, 0x20000000, 0x100000},  // the first resolution of index 2
        {2, 0x30000000, 0x100000}}; // where the row's VA actually lives
    const auto selection = engine::select_intercept_spans(vas, modules, extents);

    // Index 1 and 2 each still make exactly one span, from the first extent.
    ASSERT_EQ(selection.spans.size(), 2U);
    EXPECT_EQ(selection.spans[0].base, 0x10000000U);
    EXPECT_EQ(selection.spans[1].base, 0x20000000U);
    // The drifted row is not silently dropped: it comes back as its own hook.
    ASSERT_EQ(selection.solo_vas.size(), 1U);
    EXPECT_EQ(selection.solo_vas[0], 0x30001000U);
    // An index that resolves to no extent at all degrades the same way.
    const std::vector<std::uint16_t> orphaned{1, 7};
    const std::vector<std::uint64_t> orphan_vas{0x10001000, 0x40001000};
    const auto orphan_selection = engine::select_intercept_spans(orphan_vas, orphaned, extents);
    ASSERT_EQ(orphan_selection.spans.size(), 1U);
    ASSERT_EQ(orphan_selection.solo_vas.size(), 1U);
    EXPECT_EQ(orphan_selection.solo_vas[0], 0x40001000U);
}

// The two halves read one plan: for every row, either exactly one span covers
// the VA (the span hook will fire and the table dispatches it) or the row is
// in the solo list (its own hook fires). No third state.
TEST(InterceptSpanDispatch, EveryRowIsSpanCoveredOrSolo)
{
    const std::vector<std::uint64_t> vas{0x7FF001000, 0x7FF002000, 0x10001000, 0x500000000000,
                                         0x30001000};
    const std::vector<std::uint16_t> modules{1, 1, 2, engine::kInterceptModuleSentinel, 3};
    const std::vector<engine::InterceptModuleExtent> extents{
        {1, 0x7FF000000, 0x100000},
        {2, 0x10000000, 0x100000},
        {3, 0x30000000, 0xF00}}; // ends below row 4's VA
    const auto table = engine::build_intercept_span_table(vas);
    const auto selection = engine::select_intercept_spans(vas, modules, extents);
    ASSERT_EQ(selection.spans.size(), 3U);

    for (const auto& entry : table) {
        const auto covering = coverage_count(selection.spans, entry.va);
        EXPECT_TRUE(covering == 1 || is_solo(selection.solo_vas, entry.va))
            << "va 0x" << std::hex << entry.va;
        if (covering == 1) {
            // The span-dispatched rows hit the table at their exact VA.
            const auto* hit = engine::find_intercept_span_entry(table, entry.va);
            ASSERT_NE(hit, nullptr);
            EXPECT_EQ(hit->row, entry.row);
        }
    }
    // The row the extent end fell short of degraded to solo.
    EXPECT_TRUE(is_solo(selection.solo_vas, 0x30001000U));
}

} // namespace
