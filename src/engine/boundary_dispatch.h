// Boundary-trap dispatch: the index a trap span hook searches at run time, and
// the predicate that decides which modules own a span at all.
//
// unicorn walks the whole code-hook table for every instruction a hook covers,
// and the run's instruction budget covers every executed instruction, so one
// hook per trap export taxes the sample's own execution too. The registration
// form is instead one hook per module owning at least one surviving trap VA,
// and this header is the table both halves read: the covered set and the
// looked-up set cannot drift apart.
//
// Pure: no unicorn, no run state, no guest memory.

#ifndef SHELLER_ENGINE_BOUNDARY_DISPATCH_H
#define SHELLER_ENGINE_BOUNDARY_DISPATCH_H

#include "mem_region_map.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace sheller::engine {

// One dispatch row: a surviving trap VA and the row it came from in the plan's
// trap table. Alias exports share a VA legally, so the index collapses
// duplicates to their first row - the same first-wins spelling the named
// diagnosis uses - and the trap tables themselves are never rewritten.
struct TrapSpanEntry {
    std::uint64_t va{};
    std::size_t row{};
};

// Sorted by VA, duplicates collapsed to the first row. The input order is the
// plan's trap order, which is what makes "first row" a stable answer.
inline std::vector<TrapSpanEntry> build_trap_span_table(std::span<const std::uint64_t> trap_vas)
{
    std::vector<TrapSpanEntry> table;
    table.reserve(trap_vas.size());
    for (std::size_t row = 0; row < trap_vas.size(); ++row) {
        table.push_back({trap_vas[row], row});
    }
    std::stable_sort(
        table.begin(), table.end(),
        [](const TrapSpanEntry& left, const TrapSpanEntry& right) { return left.va < right.va; });
    const auto tail = std::unique(
        table.begin(), table.end(),
        [](const TrapSpanEntry& left, const TrapSpanEntry& right) { return left.va == right.va; });
    table.erase(tail, table.end());
    return table;
}

// The row whose VA is exactly `address`, or null when this instruction is not a
// trap entry. One binary search over the unique VAs; an empty table answers
// null.
inline const TrapSpanEntry* find_trap_span_entry(std::span<const TrapSpanEntry> table,
                                                 const std::uint64_t address)
{
    const auto hit = std::lower_bound(
        table.begin(), table.end(), address,
        [](const TrapSpanEntry& entry, const std::uint64_t va) { return entry.va < va; });
    if (hit == table.end() || hit->va != address) {
        return nullptr;
    }
    return &*hit;
}

// One registered span: a trap-owning module's image extent, the same
// base..base+size range spelling the stub hooks use.
struct TrapSpan {
    std::uint64_t base{};
    std::uint64_t size{};
};

// The modules owning at least one surviving trap VA, in the caller's module
// order and at most once each. Per module the first candidate at or after its
// base is found by binary search and accepted only when it lies inside the
// module's extent, so a module owning no trap - the sample image included -
// gets no span without being named or base-matched. An empty table selects
// nothing.
inline std::vector<TrapSpan> select_trap_spans(std::span<const TrapSpanEntry> table,
                                               std::span<const mem_region::ModuleRecord> modules)
{
    std::vector<TrapSpan> spans;
    for (const auto& mod : modules) {
        const auto candidate = std::lower_bound(
            table.begin(), table.end(), mod.base,
            [](const TrapSpanEntry& entry, const std::uint64_t base) { return entry.va < base; });
        // Inside means an offset from the base of at most the image size: the
        // inclusive extent the hook is registered over, so the selection and
        // the registered coverage accept exactly the same VAs. The subtraction
        // keeps a base near the top of the address space from wrapping.
        if (candidate == table.end() || candidate->va - mod.base > mod.size) {
            continue;
        }
        spans.push_back({mod.base, mod.size});
    }
    return spans;
}

} // namespace sheller::engine

#endif // SHELLER_ENGINE_BOUNDARY_DISPATCH_H