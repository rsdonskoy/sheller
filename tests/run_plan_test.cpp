// The run plan's pure decision core (change run-plan-decision-core): every case
// drives build_run_plan over a hand-built PreparedGuest with a NULL unicorn -
// the plan never touches the engine, which is exactly the property under test.
// T1-T6 pin the adjudication rules that used to live in assemble_run_state
// between write side effects; T8 pins the per-mode cursor layout. T7 (the
// syscall number <-> name inverse) lives with the facts layer it belongs to:
// see run_facts_test's SyscallNumberAndNameTablesAreInverse.
//
// Portable by design: no capture route, no corpus, no guest memory.

#include "../src/engine/intercept.h"
#include "../src/engine/mem_region_map.h"
#include "../src/engine/rebuild_state.h"
#include "../src/engine/run_facts.h"
#include "../src/engine/run_plan.h"

#include <sheller/snapshot.h>
#include <sheller/syscallrun.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

namespace engine = sheller::engine;
namespace mem_region = sheller::engine::mem_region;
namespace snapshot = sheller::snapshot;

mem_region::ModuleImage module_image(const std::uint64_t base, const std::uint64_t size,
                                     const std::string_view name)
{
    mem_region::ModuleImage image{};
    image.module.base = base;
    image.module.size = size;
    std::memcpy(image.module.name.data(), name.data(), name.size());
    return image;
}

engine::LoaderExportEntry module_export(const std::uint64_t module_base, const std::uint64_t va,
                                        std::string name)
{
    engine::LoaderExportEntry entry{};
    entry.module_base = module_base;
    entry.function_va = va;
    entry.name = std::move(name);
    return entry;
}

// A guest nothing runs on: build_run_plan must be testable without unicorn, so
// the handle stays null and the module tables carry everything the rules read.
engine::PreparedGuest make_guest(std::vector<mem_region::ModuleImage> images = {},
                                 std::vector<mem_region::RegionRecord> regions = {})
{
    std::vector<mem_region::ModuleRecord> loader_modules;
    loader_modules.reserve(images.size());
    for (const auto& image : images) {
        loader_modules.push_back(image.module);
    }
    snapshot::Metadata metadata{};
    metadata.image_base = 0x00400000;
    metadata.entry_address = 0x00400000;
    mem_region::MemRegionMap map(images, regions);
    engine::PreparedGuest guest{engine::UnicornEngine{nullptr},
                                engine::GuestMode::kX64,
                                metadata,
                                std::move(map),
                                std::move(images),
                                std::move(regions)};
    guest.loader_modules = std::move(loader_modules);
    return guest;
}

engine::RunPlan plan_for(const engine::PreparedGuest& guest,
                         const engine::SyscallRunOptions& options = {})
{
    const engine::GuestFacts facts;
    auto plan = engine::build_run_plan(guest, facts, options);
    EXPECT_TRUE(plan.has_value());
    return plan.has_value() ? std::move(*plan) : engine::RunPlan{};
}

constexpr std::uint32_t id_of(const engine::InterceptId id)
{
    return static_cast<std::uint32_t>(id);
}

// T1: alias rows share one VA -> one stub slot, the first whitelist row is the
// stable canonical name (run.cpp's pre-split comment contract).
TEST(RunPlan, AliasRowsCollapseToTheFirstWhitelistName)
{
    auto guest = make_guest({module_image(0x00400000, 0x3000, "sample.exe")});
    guest.directory_mode = true;
    guest.stub_whitelist = {module_export(0x00400000, 0x00401000, "AliasFirst"),
                            module_export(0x00400000, 0x00401000, "AliasSecond")};

    const auto plan = plan_for(guest);
    ASSERT_EQ(plan.stub_entries.size(), 1U);
    EXPECT_EQ(plan.stub_entries[0].name, "AliasFirst");
    EXPECT_EQ(plan.stub_entries[0].module, 0U);
    ASSERT_EQ(plan.stub_slots.size(), 1U);
    const auto slot = plan.stub_slots.find(0x00401000);
    ASSERT_NE(slot, plan.stub_slots.end());
    EXPECT_EQ(slot->second, 0U);
}

// T2: a VA registered as an intercept supersedes the boundary trap; the trap
// hook never attaches there (the ud2 body cannot be reached).
TEST(RunPlan, InterceptSupersedesTheBoundaryTrap)
{
    auto guest = make_guest({module_image(0x00400000, 0x3000, "sample.exe")});
    guest.directory_mode = true;
    guest.intercepts = {{0x00402000, 5}};
    guest.loader_exports = {module_export(0x00400000, 0x00402000, "Intercepted")};
    guest.boundary_trap_vas = {0x00402000, 0x00402100};

    const auto plan = plan_for(guest);
    ASSERT_EQ(plan.boundary_trap_vas.size(), 1U);
    EXPECT_EQ(plan.boundary_trap_vas[0], 0x00402100U);
    EXPECT_EQ(std::count(plan.intercept_vas.begin(), plan.intercept_vas.end(), 0x00402000U), 1);
    ASSERT_EQ(plan.intercept_ids.size(), 1U);
    EXPECT_EQ(plan.intercept_ids[0], 5U);
}

// T3: directory mode counts only the explicit whitelist - the "every
// non-intercepted export is a stub" inference is the synthetic-mode rule.
TEST(RunPlan, DirectoryModeCountsOnlyTheWhitelist)
{
    std::vector<mem_region::ModuleImage> images{module_image(0x00400000, 0x3000, "sample.exe")};
    auto directory_guest = make_guest(images);
    directory_guest.directory_mode = true;
    directory_guest.loader_exports = {module_export(0x00400000, 0x00403000, "RealBody"),
                                      module_export(0x00400000, 0x00403100, "Compat")};
    directory_guest.stub_whitelist = {module_export(0x00400000, 0x00403100, "Compat")};

    const auto directory_plan = plan_for(directory_guest);
    ASSERT_EQ(directory_plan.stub_entries.size(), 1U);
    EXPECT_EQ(directory_plan.stub_entries[0].name, "Compat");
    EXPECT_EQ(directory_plan.stub_slots.count(0x00403000), 0U);

    auto synthetic_guest = make_guest(images);
    synthetic_guest.loader_exports = directory_guest.loader_exports;
    const auto synthetic_plan = plan_for(synthetic_guest);
    ASSERT_EQ(synthetic_plan.stub_entries.size(), 2U);
    EXPECT_EQ(synthetic_plan.stub_entries[0].name, "RealBody");
    EXPECT_EQ(synthetic_plan.stub_entries[1].name, "Compat");
    EXPECT_EQ(synthetic_plan.stub_slots.size(), 2U);
}

// T4: heap/Ldr family names match through the case-folding helper, not by
// exact spelling.
TEST(RunPlan, FamilyNamesMatchThroughFolding)
{
    auto guest = make_guest({module_image(0x00400000, 0x3000, "sample.exe")});
    guest.loader_exports = {module_export(0x00400000, 0x00404000, "RTLALLOCATEHEAP"),
                            module_export(0x00400000, 0x00404100, "ldrloaddll")};

    const auto plan = plan_for(guest);
    ASSERT_EQ(plan.intercept_vas.size(), 2U);
    EXPECT_EQ(plan.intercept_vas[0], 0x00404000U);
    EXPECT_EQ(plan.intercept_vas[1], 0x00404100U);
    ASSERT_EQ(plan.intercept_ids.size(), 2U);
    EXPECT_EQ(plan.intercept_ids[0], id_of(engine::InterceptId::kRtlAllocateHeap));
    EXPECT_EQ(plan.intercept_ids[1], id_of(engine::InterceptId::kLdrLoadDll));
    EXPECT_EQ(plan.intercept_names[0], "RTLALLOCATEHEAP");
    EXPECT_EQ(plan.intercept_names[1], "ldrloaddll");
}

// T5: a VA already registered (declared intercept or an earlier family row) is
// never appended twice - the family registration keeps the first registration's
// id.
TEST(RunPlan, RegisteredVaIsNotAppendedTwice)
{
    auto guest = make_guest({module_image(0x00400000, 0x3000, "sample.exe")});
    guest.intercepts = {{0x00405000, 7}};
    guest.loader_exports = {module_export(0x00400000, 0x00405000, "RtlAllocateHeap"),
                            module_export(0x00400000, 0x00405000, "RtlFreeHeap")};

    const auto plan = plan_for(guest);
    EXPECT_EQ(std::count(plan.intercept_vas.begin(), plan.intercept_vas.end(), 0x00405000U), 1);
    ASSERT_EQ(plan.intercept_ids.size(), 1U);
    EXPECT_EQ(plan.intercept_ids[0], 7U);
}

// T6: module index for an intercept VA: the owning module's region-map index
// inside a module span, the 0xFFFF runtime sentinel outside every span.
TEST(RunPlan, ModuleIndexResolvesInsideTheSpanAndFallsBackOutside)
{
    auto guest = make_guest({module_image(0x00400000, 0x3000, "sample.exe"),
                             module_image(0x00500000, 0x2000, "ntdll.dll")});
    guest.intercepts = {{0x00401000, 1}, {0x00501000, 2}, {0x00600000, 3}};

    const auto plan = plan_for(guest);
    ASSERT_EQ(plan.intercept_modules.size(), 3U);
    EXPECT_EQ(plan.intercept_modules[0], 0U);
    EXPECT_EQ(plan.intercept_modules[1], 1U);
    EXPECT_EQ(plan.intercept_modules[2], 0xFFFFU);
}

// T8: the per-mode deterministic layout: trampoline page at the front of the
// alloc bump range, its scratch one page in, cursors on the layout constants,
// and no overlap between the trampoline, heap, stack and environment ranges.
TEST(RunPlan, LayoutCursorsArePerModeAndDisjoint)
{
    const auto disjoint = [](const std::uint64_t lo1, const std::uint64_t hi1,
                             const std::uint64_t lo2,
                             const std::uint64_t hi2) { return hi1 <= lo2 || hi2 <= lo1; };
    for (const auto mode : {engine::GuestMode::kX64, engine::GuestMode::kX86}) {
        auto guest = make_guest();
        guest.guest_mode = mode;
        const auto plan = plan_for(guest);
        const auto& layout = engine::layout_for(mode);

        EXPECT_EQ(plan.seh_trampoline, layout.alloc_base);
        EXPECT_EQ(plan.seh_scratch, layout.alloc_base + 0x1000);
        EXPECT_EQ(plan.valloc_cursor, layout.alloc_base + 0x21000);
        EXPECT_EQ(plan.heap_cursor, layout.heap_base);

        const auto tramp_lo = plan.seh_trampoline;
        const auto tramp_hi = plan.seh_trampoline + 0x21000;
        EXPECT_LE(tramp_hi, layout.alloc_end);
        EXPECT_TRUE(
            disjoint(tramp_lo, tramp_hi, layout.heap_base, layout.heap_base + layout.heap_size));
        EXPECT_TRUE(
            disjoint(tramp_lo, tramp_hi, layout.stack_base, layout.stack_base + layout.stack_size));
        EXPECT_TRUE(
            disjoint(tramp_lo, tramp_hi, layout.env_base, layout.env_base + layout.env_block_size));
        EXPECT_TRUE(disjoint(layout.heap_base, layout.heap_base + layout.heap_size,
                             layout.stack_base, layout.stack_base + layout.stack_size));
        EXPECT_TRUE(disjoint(layout.heap_base, layout.heap_base + layout.heap_size, layout.env_base,
                             layout.env_base + layout.env_block_size));
    }
    EXPECT_NE(engine::kLayout64.alloc_base, engine::kLayout86.alloc_base);
    EXPECT_NE(engine::kLayout64.heap_base, engine::kLayout86.heap_base);
}

} // namespace
