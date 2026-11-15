// Intercept dispatch: the index the span hooks search at run time, and the
// span/solo split the registration site reads off the plan's identity columns.
//
// The registration form mirrors the trap side (one code hook per module owning
// intercepted entries instead of one hook per entry) with one difference the
// callback has to absorb: a span hook fires on every instruction in the
// owning module, so a miss is the common case and the lookup must be a
// side-effect-free binary search. The index keeps original plan rows - the
// identity columns stay row-aligned with the intercept list and are never
// rewritten - so an alias VA keeps the first row's name and module, the same
// first-wins spelling the linear scan answered with.
//
// Pure: no unicorn, no run state, no guest memory.

#ifndef SHELLER_ENGINE_INTERCEPT_SPAN_DISPATCH_H
#define SHELLER_ENGINE_INTERCEPT_SPAN_DISPATCH_H

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace sheller::engine {

// The attribution column's "no region-map owner resolved" spelling (the value
// run_plan's module_index_for_va returns outside every module extent).
inline constexpr std::uint16_t kInterceptModuleSentinel{0xFFFF};

// One dispatch row: an intercepted VA and the row it came from in the plan's
// intercept list. Forwarder twins (one VA entering the table from two modules'
// export rows) collapse to their first row legally - that row's name/module is
// the event identity, and the parallel columns are never rewritten.
struct InterceptSpanEntry {
    std::uint64_t va{};
    std::size_t row{};
};

// Sorted by VA, duplicates collapsed to the first row. The input order is the
// plan's intercept order, which is what makes "first row" a stable answer.
inline std::vector<InterceptSpanEntry>
build_intercept_span_table(std::span<const std::uint64_t> intercept_vas)
{
    std::vector<InterceptSpanEntry> table;
    table.reserve(intercept_vas.size());
    for (std::size_t row = 0; row < intercept_vas.size(); ++row) {
        table.push_back({intercept_vas[row], row});
    }
    std::stable_sort(table.begin(), table.end(),
                     [](const InterceptSpanEntry& left, const InterceptSpanEntry& right) {
                         return left.va < right.va;
                     });
    const auto tail =
        std::unique(table.begin(), table.end(),
                    [](const InterceptSpanEntry& left, const InterceptSpanEntry& right) {
                        return left.va == right.va;
                    });
    table.erase(tail, table.end());
    return table;
}

// The row whose VA is exactly `address`, or null when this instruction is not
// an intercepted entry. One binary search over the unique VAs; an empty table
// answers null. This is the hot path - the span hooks land here on every
// instruction of every intercept-owning module.
inline const InterceptSpanEntry*
find_intercept_span_entry(std::span<const InterceptSpanEntry> table, const std::uint64_t address)
{
    const auto hit = std::lower_bound(
        table.begin(), table.end(), address,
        [](const InterceptSpanEntry& entry, const std::uint64_t va) { return entry.va < va; });
    if (hit == table.end() || hit->va != address) {
        return nullptr;
    }
    return &*hit;
}

// One registered span: an intercept-owning module's image extent, the same
// base..base+size range spelling the trap spans and stub hooks use.
struct InterceptSpan {
    std::uint64_t base{};
    std::uint64_t size{};
};

// One candidate extent: a loader module's image span keyed by the region-map
// index the attribution column stores. The caller resolves these from the same
// module list the attribution walked (module_index_for_va's loader-modules +
// folded-name region-map lookup), so the span geometry and the attribution
// share one source.
struct InterceptModuleExtent {
    std::uint16_t region_index{};
    std::uint64_t base{};
    std::uint64_t size{};
};

struct InterceptSpanSelection {
    std::vector<InterceptSpan> spans{};
    // The rows that keep an individual 1-byte hook: sentinel-attributed rows,
    // plus any non-sentinel row no selected span covers exactly once.
    std::vector<std::uint64_t> solo_vas{};
};

// The registration split over the plan's identity columns. Sentinel rows never
// make a span (no region-map owner to size one from); every remaining index
// with at least one row gets exactly one span, geometry from the first
// matching extent. The coverage hard invariant closes the one way this could
// drop an intercept: a non-sentinel row the selected spans fail to cover
// exactly once (attribution/geometry drift, an index that resolved to no
// extent, a VA sitting past its owner's chosen extent) comes back as a solo
// row and is registered individually - the registration surface never loses a
// row. Like the trap selection this reads module extents as disjoint mapped
// images; overlap handling would be dead weight against the memory map's own
// invariant.
inline InterceptSpanSelection select_intercept_spans(std::span<const std::uint64_t> vas,
                                                     std::span<const std::uint16_t> modules,
                                                     std::span<const InterceptModuleExtent> extents)
{
    InterceptSpanSelection selection;
    for (std::size_t row = 0; row < vas.size(); ++row) {
        if (modules[row] == kInterceptModuleSentinel) {
            selection.solo_vas.push_back(vas[row]);
        }
    }
    // One span per deduplicated owning index, in the caller's extent order.
    std::vector<std::uint16_t> spanned;
    for (const auto& extent : extents) {
        if (extent.region_index == kInterceptModuleSentinel) {
            continue;
        }
        const bool owned =
            std::any_of(modules.begin(), modules.end(), [extent](const std::uint16_t module_index) {
                return module_index == extent.region_index;
            });
        if (!owned ||
            std::find(spanned.begin(), spanned.end(), extent.region_index) != spanned.end()) {
            continue;
        }
        spanned.push_back(extent.region_index);
        selection.spans.push_back({extent.base, extent.size});
    }
    // The coverage check, under the same inclusive extent the hooks register
    // over; the subtraction keeps a base near the top of the address space
    // from wrapping.
    for (std::size_t row = 0; row < vas.size(); ++row) {
        if (modules[row] == kInterceptModuleSentinel) {
            continue;
        }
        std::size_t covering = 0;
        for (const auto& span : selection.spans) {
            if (vas[row] >= span.base && vas[row] - span.base <= span.size) {
                ++covering;
            }
        }
        if (covering != 1) {
            selection.solo_vas.push_back(vas[row]);
        }
    }
    return selection;
}

} // namespace sheller::engine

#endif // SHELLER_ENGINE_INTERCEPT_SPAN_DISPATCH_H
