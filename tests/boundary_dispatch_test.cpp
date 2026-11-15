// The boundary-trap dispatch index and the trap-owning module selection: pure
// table functions, driven over hand-built VA lists and module records. No
// unicorn, no guest memory, no corpus - the registration predicate and the
// runtime lookup are the same table, and these cases pin that they agree.
//
// The end-to-end trap behavior (named stop, direct-vs-replay diagnosis) lives
// in loader_directory_test; this TU pins the mechanism underneath it.

#include "../src/engine/boundary_dispatch.h"
#include "../src/engine/mem_region_map.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

namespace {

namespace engine = sheller::engine;
namespace mem_region = sheller::engine::mem_region;

mem_region::ModuleRecord module_record(const std::uint64_t base, const std::uint64_t size,
                                       const std::string_view name)
{
    mem_region::ModuleRecord record{};
    record.base = base;
    record.size = size;
    std::memcpy(record.name.data(), name.data(), name.size());
    return record;
}

// How many of the selected spans cover this address, under the same inclusive
// extent the hooks are registered over.
std::size_t coverage_count(const std::vector<engine::TrapSpan>& spans, const std::uint64_t va)
{
    std::size_t count = 0;
    for (const auto& span : spans) {
        if (va >= span.base && va - span.base <= span.size) {
            ++count;
        }
    }
    return count;
}

// Unsorted with two alias pairs: the surviving rows must be the first of each
// VA, in VA order, and the row numbers must still index the input.
TEST(BoundaryDispatch, BuildSortsAndKeepsTheFirstRowOfEachVa)
{
    const std::vector<std::uint64_t> trap_vas{0x3000, 0x1000, 0x3000, 0x2000, 0x1000, 0x3000};
    const auto table = engine::build_trap_span_table(trap_vas);

    ASSERT_EQ(table.size(), 3U);
    EXPECT_EQ(table[0].va, 0x1000U);
    EXPECT_EQ(table[0].row, 1U);
    EXPECT_EQ(table[1].va, 0x2000U);
    EXPECT_EQ(table[1].row, 3U);
    EXPECT_EQ(table[2].va, 0x3000U);
    EXPECT_EQ(table[2].row, 0U);
    for (const auto& entry : table) {
        EXPECT_EQ(trap_vas[entry.row], entry.va);
    }
}

TEST(BoundaryDispatch, BuildOfEmptyInputIsEmpty)
{
    const std::vector<std::uint64_t> trap_vas{};
    EXPECT_TRUE(engine::build_trap_span_table(trap_vas).empty());
}

TEST(BoundaryDispatch, BuildOfOneVaKeepsRowZero)
{
    const std::vector<std::uint64_t> trap_vas{0x7FFE1234};
    const auto table = engine::build_trap_span_table(trap_vas);
    ASSERT_EQ(table.size(), 1U);
    EXPECT_EQ(table[0].va, 0x7FFE1234U);
    EXPECT_EQ(table[0].row, 0U);
}

// Every slot is reachable, not just the ends: the search must answer for an
// arbitrary position in the sorted table.
TEST(BoundaryDispatch, FindHitsEverySlot)
{
    const std::vector<std::uint64_t> trap_vas{0x9000, 0x1000, 0x5000, 0x3000, 0x7000,
                                              0x2000, 0x8000, 0x4000, 0x6000};
    const auto table = engine::build_trap_span_table(trap_vas);
    ASSERT_EQ(table.size(), trap_vas.size());
    for (std::size_t slot = 0; slot < table.size(); ++slot) {
        const auto* hit = engine::find_trap_span_entry(table, table[slot].va);
        ASSERT_NE(hit, nullptr) << "slot " << slot;
        EXPECT_EQ(hit->va, table[slot].va);
        EXPECT_EQ(hit->row, table[slot].row);
    }
}

TEST(BoundaryDispatch, FindMissesBelowBetweenAndAbove)
{
    const std::vector<std::uint64_t> trap_vas{0x2000, 0x4000, 0x6000};
    const auto table = engine::build_trap_span_table(trap_vas);
    EXPECT_EQ(engine::find_trap_span_entry(table, 0x1FFF), nullptr);
    EXPECT_EQ(engine::find_trap_span_entry(table, 0x2001), nullptr);
    EXPECT_EQ(engine::find_trap_span_entry(table, 0x3FFF), nullptr);
    EXPECT_EQ(engine::find_trap_span_entry(table, 0x5000), nullptr);
    EXPECT_EQ(engine::find_trap_span_entry(table, 0x6001), nullptr);
    EXPECT_EQ(engine::find_trap_span_entry(table, 0xFFFFFFFFFFFFFFFFULL), nullptr);
}

TEST(BoundaryDispatch, FindOnEmptyTableIsNull)
{
    const std::vector<engine::TrapSpanEntry> table{};
    EXPECT_EQ(engine::find_trap_span_entry(table, 0x1000), nullptr);
    EXPECT_EQ(engine::find_trap_span_entry(table, 0), nullptr);
}

// An alias VA is one slot: the lookup answers with the first row, which is the
// row the named diagnosis keeps.
TEST(BoundaryDispatch, FindOfAliasVaAnswersTheFirstRow)
{
    const std::vector<std::uint64_t> trap_vas{0x5000, 0x5000, 0x5000};
    const auto table = engine::build_trap_span_table(trap_vas);
    ASSERT_EQ(table.size(), 1U);
    const auto* hit = engine::find_trap_span_entry(table, 0x5000);
    ASSERT_NE(hit, nullptr);
    EXPECT_EQ(hit->row, 0U);
}

TEST(BoundaryDispatch, EmptyTableSelectsNoSpans)
{
    const std::vector<engine::TrapSpanEntry> table{};
    const std::vector<mem_region::ModuleRecord> modules{
        module_record(0x00400000, 0x3000, "sample.exe"),
        module_record(0x7FF00000, 0x200000, "ntdll.dll")};
    EXPECT_TRUE(engine::select_trap_spans(table, modules).empty());
}

// The candidate positions around one module: before its base, at its base,
// strictly inside it, at its extent end, and past every trap. Only the middle
// three own a span.
TEST(BoundaryDispatch, SelectAcceptsBaseInsideAndExtentEnd)
{
    const std::vector<std::uint64_t> trap_vas{0x10000, 0x20000, 0x20800, 0x30000, 0x40000};
    const auto table = engine::build_trap_span_table(trap_vas);
    const std::vector<mem_region::ModuleRecord> modules{
        module_record(0x01000, 0x1000, "before_all.dll"), // first candidate is a later module's
        module_record(0x10000, 0x1000, "at_base.dll"),    // trap at base
        module_record(0x1F000, 0x2000, "inside.dll"),     // trap strictly inside
        module_record(0x2F000, 0x1000, "at_end.dll"),     // trap at base + size
        module_record(0x50000, 0x1000, "past_all.dll")};  // every trap before its base
    const auto spans = engine::select_trap_spans(table, modules);

    ASSERT_EQ(spans.size(), 3U);
    EXPECT_EQ(spans[0].base, 0x10000U);
    EXPECT_EQ(spans[0].size, 0x1000U);
    EXPECT_EQ(spans[1].base, 0x1F000U);
    EXPECT_EQ(spans[1].size, 0x2000U);
    EXPECT_EQ(spans[2].base, 0x2F000U);
    EXPECT_EQ(spans[2].size, 0x1000U);
    // The extent-end acceptance is the registered hook range, not a stricter
    // image-interior test: that trap is covered by the span it selected.
    EXPECT_EQ(coverage_count(spans, 0x30000), 1U);
}

TEST(BoundaryDispatch, SelectRejectsCandidatePastTheExtent)
{
    // The only trap is one byte past this module's extent: lower_bound finds it
    // (it is at or after the base) and the extent test must reject it.
    const std::vector<std::uint64_t> trap_vas{0x11001};
    const auto table = engine::build_trap_span_table(trap_vas);
    const std::vector<mem_region::ModuleRecord> modules{
        module_record(0x10000, 0x1000, "trap_free.dll"),
        module_record(0x11000, 0x1000, "owner.dll")};
    const auto spans = engine::select_trap_spans(table, modules);
    ASSERT_EQ(spans.size(), 1U);
    EXPECT_EQ(spans[0].base, 0x11000U);
    EXPECT_EQ(spans[0].size, 0x1000U);
}

TEST(BoundaryDispatch, SelectRejectsCandidateBeforeTheBase)
{
    // A module whose base is above every trap: the search runs off the end of
    // the table, and a module below the traps must not claim the next module's.
    const std::vector<std::uint64_t> trap_vas{0x20000};
    const auto table = engine::build_trap_span_table(trap_vas);
    const std::vector<mem_region::ModuleRecord> modules{
        module_record(0x10000, 0x1000, "below.dll"), module_record(0x30000, 0x1000, "above.dll"),
        module_record(0x20000, 0x1000, "owner.dll")};
    const auto spans = engine::select_trap_spans(table, modules);
    ASSERT_EQ(spans.size(), 1U);
    EXPECT_EQ(spans[0].base, 0x20000U);
}

// Many traps and alias rows in one module are still one span, and the spans
// keep the caller's module order rather than the table's VA order.
TEST(BoundaryDispatch, OneSpanPerModuleInModuleOrder)
{
    const std::vector<std::uint64_t> trap_vas{0x20100, 0x20100, 0x20200, 0x20300,
                                              0x10100, 0x10100, 0x10200};
    const auto table = engine::build_trap_span_table(trap_vas);
    ASSERT_EQ(table.size(), 5U);
    const std::vector<mem_region::ModuleRecord> modules{
        module_record(0x20000, 0x10000, "second.dll"),
        module_record(0x10000, 0x10000, "first.dll")};
    const auto spans = engine::select_trap_spans(table, modules);
    ASSERT_EQ(spans.size(), 2U);
    EXPECT_EQ(spans[0].base, 0x20000U);
    EXPECT_EQ(spans[1].base, 0x10000U);
}

// The coverage invariant over a world-shaped module table: the sample image and
// every trap-free module get no span, and each surviving trap VA is covered
// exactly once. No module is named or base-matched by the selection - the
// sample is span-free because it owns no trap VA.
TEST(BoundaryDispatch, EverySurvivingTrapVaIsCoveredExactlyOnce)
{
    // Disjoint image extents, the sample first and the trap owner in the
    // middle: ntdll spans 0x7F100000..0x7F200000, kernelbase starts above it.
    const std::vector<mem_region::ModuleRecord> modules{
        module_record(0x00400000, 0x30000, "sample.exe"),
        module_record(0x7F000000, 0x20000, "kernel32.dll"),
        module_record(0x7F100000, 0x100000, "ntdll.dll"),
        module_record(0x7F210000, 0x80000, "kernelbase.dll"),
        module_record(0x7F300000, 0x20000, "user32.dll")};
    std::vector<std::uint64_t> trap_vas{};
    for (std::uint64_t offset = 0x1000; offset < 0xF0000; offset += 0x1000) {
        trap_vas.push_back(0x7F100000 + offset);
    }
    // Alias rows on one of them, plus one trap in a second module.
    trap_vas.push_back(0x7F101000);
    trap_vas.push_back(0x7F101000);
    trap_vas.push_back(0x7F212000);
    const auto table = engine::build_trap_span_table(trap_vas);
    const auto spans = engine::select_trap_spans(table, modules);

    ASSERT_EQ(spans.size(), 2U);
    EXPECT_EQ(spans[0].base, 0x7F100000U);
    EXPECT_EQ(spans[1].base, 0x7F210000U);
    for (const auto& entry : table) {
        EXPECT_EQ(coverage_count(spans, entry.va), 1U) << "va 0x" << std::hex << entry.va;
    }
    // The sample and the trap-free modules are outside every span.
    for (const auto base : {0x00400000ULL, 0x7F000000ULL, 0x7F300000ULL}) {
        EXPECT_EQ(coverage_count(spans, base), 0U) << "base 0x" << std::hex << base;
        EXPECT_EQ(coverage_count(spans, base + 0x1000), 0U);
    }
    // A non-trap instruction inside a trap-owning module is covered by the span
    // but is not a dispatch hit: that miss is the callback's no-op branch.
    EXPECT_EQ(coverage_count(spans, 0x7F101800), 1U);
    EXPECT_EQ(engine::find_trap_span_entry(table, 0x7F101800), nullptr);
}

// The two halves read one table: every VA the selection covers as a trap is a
// lookup hit, and every other address in the same span is a miss.
TEST(BoundaryDispatch, SelectionAndLookupAgree)
{
    const std::vector<std::uint64_t> trap_vas{0x10400, 0x10800, 0x10800, 0x10C00};
    const auto table = engine::build_trap_span_table(trap_vas);
    const std::vector<mem_region::ModuleRecord> modules{
        module_record(0x10000, 0x10000, "owner.dll")};
    const auto spans = engine::select_trap_spans(table, modules);
    ASSERT_EQ(spans.size(), 1U);
    for (std::uint64_t va = spans[0].base; va <= spans[0].base + spans[0].size; ++va) {
        const bool is_trap = std::find(trap_vas.begin(), trap_vas.end(), va) != trap_vas.end();
        const auto* hit = engine::find_trap_span_entry(table, va);
        EXPECT_EQ(hit != nullptr, is_trap) << "va 0x" << std::hex << va;
        if (hit != nullptr) {
            EXPECT_EQ(hit->va, va);
        }
    }
}

} // namespace