// KnownDLL section views: the world-sourced backfill contract. A hand-built
// guest (fixture resident module + region map) drives the engine's
// NtOpenSection / NtCreateSection / NtMapViewOfSection apply layer, and every
// view is pinned byte-for-byte against an independently recomputed
// expectation: resident copy + this-base relocation delta + bitness-aware
// hygiene + the foreign-thunk compat patch. Nothing here touches a host
// system directory - the fixture bytes match no host image, so byte equality
// is the no-host-read proof on every platform. Portable by design.

#include "fake_ntdll.hpp"

#include "guest_objects.h"
#include "mem_region_map.h"

#include "../src/loader/loader.h"

#include <unicorn/unicorn.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace {

namespace engine = sheller::engine;
namespace loader = sheller::loader;
namespace mem_region = sheller::engine::mem_region;
namespace syscalls = sheller::syscalls;

using sheller_test::build_fake_known_dll;
using sheller_test::kFixtureBoundRva;
using sheller_test::kFixtureDllImageSize;
using sheller_test::kFixtureRelocPointerRva;
using sheller_test::kFixtureThunkSlotRva;

// The x64 world's fixed addresses: the module sits at the fixture's own
// preferred base; scratch (guest call structures) and the view destinations
// sit clear of every module slot. The x86 world shifts everything below 4GB.
constexpr std::uint64_t kX64Scratch = 0x7FFD00000000;
constexpr std::uint64_t kX64ViewArea = 0x7FFE00000000;
constexpr std::uint64_t kX86ModuleBase = 0x10000000;
constexpr std::uint64_t kX86Scratch = 0x20000000;
constexpr std::uint64_t kX86ViewArea = 0x28000000;

// One test world: a uc instance, the fixture placed as a resident module, the
// region map carrying its ModuleRecord, and a SyscallRunState wired the way
// the engine's run loop holds it. mapped_bytes selects the resident span that
// actually carries content in guest memory (a sparse captured world's
// content-absent tail: reads past it keep the world's own zeros).
struct ViewWorld {
    explicit ViewWorld(const std::string& module_name, const bool pe32plus,
                       const std::uint64_t mapped_bytes, const bool place_module = true)
    {
        const auto mode = pe32plus ? engine::GuestMode::kX64 : engine::GuestMode::kX86;
        const auto uc_opened = pe32plus ? uc_open(UC_ARCH_X86, UC_MODE_64, &uc)
                                        : uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
        if (uc_opened != UC_ERR_OK) {
            return;
        }
        // the guest span that carries content (module + scratch + views)
        const auto module_base = pe32plus ? sheller_test::kFixtureDllBase : kX86ModuleBase;
        const auto scratch = pe32plus ? kX64Scratch : kX86Scratch;
        const auto view_area = pe32plus ? kX64ViewArea : kX86ViewArea;
        uc_mem_map(uc, module_base, static_cast<std::size_t>(mapped_bytes), UC_PROT_ALL);
        uc_mem_map(uc, scratch, 0x1000, UC_PROT_ALL);
        uc_mem_map(uc, view_area, 0x30000, UC_PROT_ALL);
        image = build_fake_known_dll(module_base, pe32plus);
        if (place_module) {
            const auto placed =
                static_cast<std::size_t>(mapped_bytes < image.size() ? mapped_bytes : image.size());
            uc_mem_write(uc, module_base, image.data(), placed);

            mem_region::ModuleRecord record;
            record.base = module_base;
            record.size = image.size();
            const auto name_bytes = (std::min)(module_name.size(), record.name.size() - 1);
            std::memcpy(record.name.data(), module_name.data(), name_bytes);
            auto header = image;
            header.resize(0x1000);
            images.push_back(mem_region::ModuleImage{record, std::move(header)});
        }
        map = std::make_unique<mem_region::MemRegionMap>(
            images, std::span<const mem_region::RegionRecord>{});
        state.uc = uc;
        state.guest_mode = mode;
        state.region_map = map.get();
        base = module_base;
        scratch_base = scratch;
        view_base = view_area;
        width64 = pe32plus;
    }

    ~ViewWorld()
    {
        if (uc != nullptr) {
            uc_close(uc);
        }
    }

    ViewWorld(const ViewWorld&) = delete;
    ViewWorld& operator=(const ViewWorld&) = delete;

    std::vector<std::uint8_t> read_guest(const std::uint64_t address, const std::size_t size) const
    {
        std::vector<std::uint8_t> bytes(size, std::uint8_t{0xAA});
        uc_mem_read(uc, address, bytes.data(), bytes.size());
        return bytes;
    }

    uc_engine* uc{};
    std::vector<mem_region::ModuleImage> images;
    std::unique_ptr<mem_region::MemRegionMap> map;
    engine::SyscallRunState state;
    std::vector<std::uint8_t> image;
    std::uint64_t base{};
    std::uint64_t scratch_base{};
    std::uint64_t view_base{};
    bool width64{};
};

// Writes the guest-side OBJECT_ATTRIBUTES naming \KnownDlls\<name> (arch
// width per world) and drives apply_open_section; returns the issued handle
// or 0 (with the status riding the outcome for the caller to check).
std::uint64_t open_known_dll(ViewWorld& world, const std::string& name, std::uint32_t& status)
{
    const auto scratch = world.scratch_base;
    const auto text = std::string("\\KnownDlls\\") + name;
    std::u16string wide{text.begin(), text.end()};
    const auto unicode = scratch;       // UNICODE_STRING
    const auto buffer = scratch + 0x10; // UTF-16 text
    const auto objattr = scratch + 0x100;
    const auto handle_out = scratch + 0x200;

    const auto put8 = [&](const std::uint64_t address, const std::uint64_t value) {
        uc_mem_write(world.uc, address, &value, sizeof value);
    };
    const auto put4 = [&](const std::uint64_t address, const std::uint32_t value) {
        uc_mem_write(world.uc, address, &value, sizeof value);
    };
    const auto put2 = [&](const std::uint64_t address, const std::uint16_t value) {
        uc_mem_write(world.uc, address, &value, sizeof value);
    };
    put2(unicode, static_cast<std::uint16_t>(wide.size() * 2));
    put2(unicode + 2, static_cast<std::uint16_t>(wide.size() * 2));
    std::vector<std::uint8_t> text_bytes;
    for (const auto unit : wide) {
        text_bytes.push_back(static_cast<std::uint8_t>(unit));
        text_bytes.push_back(static_cast<std::uint8_t>(unit >> 8));
    }
    uc_mem_write(world.uc, buffer, text_bytes.data(), text_bytes.size());
    if (world.width64) {
        put8(unicode + 8, buffer);
        put8(objattr + 0x10, unicode);
    } else {
        put4(unicode + 4, static_cast<std::uint32_t>(buffer));
        put4(objattr + 8, static_cast<std::uint32_t>(unicode));
    }

    syscalls::SyscallFrame frame{};
    syscalls::SyscallOutcome outcome;
    outcome.section_objattr = objattr;
    outcome.section_handle_out = handle_out;
    engine::apply_open_section(world.state, world.uc, frame, outcome);
    status = outcome.status;
    if (outcome.status != 0) {
        return 0;
    }
    std::uint64_t handle = 0;
    if (world.width64) {
        uc_mem_read(world.uc, handle_out, &handle, sizeof handle);
    } else {
        std::uint32_t handle32 = 0;
        uc_mem_read(world.uc, handle_out, &handle32, sizeof handle32);
        handle = handle32;
    }
    return handle;
}

// Drives apply_map_view_of_section for a caller-reserved base; returns the
// answered base (0 on failure, status riding the outcome).
std::uint64_t map_view(ViewWorld& world, const std::uint64_t handle, const std::uint64_t requested,
                       std::uint32_t& status)
{
    const auto base_slot = world.scratch_base + 0x300;
    const auto size_slot = world.scratch_base + 0x308;
    if (world.width64) {
        uc_mem_write(world.uc, base_slot, &requested, sizeof requested);
        const std::uint64_t zero = 0;
        uc_mem_write(world.uc, size_slot, &zero, sizeof zero);
    } else {
        const auto requested32 = static_cast<std::uint32_t>(requested);
        uc_mem_write(world.uc, base_slot, &requested32, sizeof requested32);
        const std::uint32_t zero = 0;
        uc_mem_write(world.uc, size_slot, &zero, sizeof zero);
    }
    syscalls::SyscallFrame frame{};
    syscalls::SyscallOutcome outcome;
    outcome.map_view_handle = handle;
    outcome.map_view_base_ptr = base_slot;
    outcome.map_view_size_ptr = size_slot;
    engine::apply_map_view_of_section(world.state, world.uc, frame, outcome);
    status = outcome.status;
    if (outcome.status != 0) {
        return 0;
    }
    std::uint64_t base = 0;
    if (world.width64) {
        uc_mem_read(world.uc, base_slot, &base, sizeof base);
    } else {
        std::uint32_t base32 = 0;
        uc_mem_read(world.uc, base_slot, &base32, sizeof base32);
        base = base32;
    }
    return base;
}

// The independent expectation: resident copy + this-base relocation delta +
// bitness-aware hygiene (CheckSum and the Security directory entry zeroed by
// the test's own offset math) + the compat stub (x64 worlds) and the
// unbound-thunk repoint. `resident` arrives as the world's own copy at
// resident_base (sparse gaps already zeroed by the caller).
std::vector<std::uint8_t> expected_view(std::vector<std::uint8_t> resident,
                                        const std::uint64_t resident_base,
                                        const std::uint64_t view_base, const bool width64,
                                        const bool repoint_thunks = true)
{
    const auto info = loader::parse_pe(resident);
    if (!info.has_value()) {
        return {};
    }
    static_cast<void>(loader::apply_relocations(resident, *info, view_base - resident_base));
    const auto e_lfanew = static_cast<std::size_t>(resident[0x3C]) |
                          (static_cast<std::size_t>(resident[0x3D]) << 8) |
                          (static_cast<std::size_t>(resident[0x3E]) << 16) |
                          (static_cast<std::size_t>(resident[0x3F]) << 24);
    const auto optional = e_lfanew + 0x18;
    const auto magic =
        static_cast<std::uint16_t>(resident[optional]) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(resident[optional + 1]) << 8);
    const auto directory = optional + (magic == 0x20B ? 0x70U : 0x60U);
    for (std::size_t i = 0; i < 4; ++i) {
        resident[optional + 0x40 + i] = 0;       // CheckSum
        resident[directory + 4 * 8 + i] = 0;     // Security VA
        resident[directory + 4 * 8 + 4 + i] = 0; // Security size
    }
    if (width64 && repoint_thunks) {
        const auto stub_offset = resident.size() - 0x20;
        const std::uint8_t stub[9] = {0xC7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x31, 0xC0, 0xC3};
        std::memcpy(resident.data() + stub_offset, stub, sizeof stub);
        const std::uint64_t stub_va = view_base + stub_offset;
        std::memcpy(resident.data() + kFixtureThunkSlotRva, &stub_va, sizeof stub_va);
    } else if (width64) {
        // the gap swallowed the thunk structures: the stub lands anyway
        // (it writes before the export walk), the slot keeps its
        // delta-shifted world bytes
        const auto stub_offset = resident.size() - 0x20;
        const std::uint8_t stub[9] = {0xC7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x31, 0xC0, 0xC3};
        std::memcpy(resident.data() + stub_offset, stub, sizeof stub);
    }
    return resident;
}

// The pin: every view byte equals the independently computed expectation.
void expect_view_matches(ViewWorld& world, const std::uint64_t view_address,
                         const std::vector<std::uint8_t>& expected)
{
    const auto actual = world.read_guest(view_address, expected.size());
    ASSERT_EQ(actual.size(), expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        ASSERT_EQ(actual[i], expected[i]) << "byte " << std::hex << i;
    }
}

// ---- task 2.1: the full transform set visible, byte for byte ---------------

TEST(KnownDllView, ViewBytesEqualIndependentExpectation)
{
    ViewWorld world("kernel32.dll", true, sheller_test::kFixtureDllImageSize);
    ASSERT_NE(world.uc, nullptr);
    std::uint32_t status = 0;
    const auto handle = open_known_dll(world, "kernel32.dll", status);
    ASSERT_EQ(status, 0u);
    ASSERT_NE(handle, 0u);
    const auto view_base = world.view_base;
    const auto mapped = map_view(world, handle, view_base, status);
    ASSERT_EQ(status, 0u);
    EXPECT_EQ(mapped, view_base);

    const auto expected = expected_view(world.image, world.base, view_base, true);
    ASSERT_FALSE(expected.empty());
    expect_view_matches(world, view_base, expected);

    // the individual transforms, observable at their own addresses
    const auto view = world.read_guest(view_base, world.image.size());
    const std::size_t optional = 0x40 + 0x18;
    const std::size_t checksum = optional + 0x40;
    EXPECT_EQ(std::memcmp(view.data() + checksum, "\0\0\0\0", 4), 0);
    const std::size_t security = optional + 0x70 + 4 * 8;
    std::uint32_t security_va = 0;
    std::memcpy(&security_va, view.data() + security, 4);
    EXPECT_EQ(security_va, 0u);
    std::uint32_t security_size = 0;
    std::memcpy(&security_size, view.data() + security + 4, 4);
    EXPECT_EQ(security_size, 0u);
    std::uint32_t adjacent = 0;
    std::memcpy(&adjacent, view.data() + optional + 0x28, 4);
    EXPECT_EQ(adjacent, sheller_test::kFixtureAdjacentWords); // the wrong-offset spot
    std::uint64_t pointer = 0;
    std::memcpy(&pointer, view.data() + kFixtureRelocPointerRva, 8);
    EXPECT_EQ(pointer, view_base + kFixtureRelocPointerRva); // this base's delta
    std::uint64_t slot = 0;
    std::memcpy(&slot, view.data() + kFixtureThunkSlotRva, 8);
    EXPECT_EQ(slot, view_base + world.image.size() - 0x20); // repointed at the stub
    for (std::size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(view[sheller_test::kFixtureTailRva + i], 0x77); // tail bytes ride
    }
    // the bound-shape export stays untouched by the patch
    EXPECT_EQ(view[kFixtureBoundRva], 0xE9);
}

// ---- task 2.2: the same handle maps twice, each view its own delta --------

TEST(KnownDllView, SameHandleTwoBasesRelocateIndependently)
{
    ViewWorld world("kernel32.dll", true, sheller_test::kFixtureDllImageSize);
    ASSERT_NE(world.uc, nullptr);
    std::uint32_t status = 0;
    const auto handle = open_known_dll(world, "kernel32.dll", status);
    ASSERT_EQ(status, 0u);
    const auto first = map_view(world, handle, world.view_base, status);
    ASSERT_EQ(status, 0u);
    const auto second = map_view(world, handle, world.view_base + 0x10000, status);
    ASSERT_EQ(status, 0u);
    EXPECT_NE(first, second);

    expect_view_matches(world, first, expected_view(world.image, world.base, first, true));
    expect_view_matches(world, second, expected_view(world.image, world.base, second, true));
    // and no view carries the other base's pointers
    std::uint64_t first_slot = 0;
    std::memcpy(&first_slot,
                world.read_guest(first, world.image.size()).data() + kFixtureRelocPointerRva, 8);
    EXPECT_EQ(first_slot, first + kFixtureRelocPointerRva);
}

TEST(KnownDllView, FileBoundSectionTwoBasesRelocateIndependently)
{
    // the file-bound NtCreateSection path: the pristine stage is the
    // loader-built image (slots at the preferred base), each view relocates
    // from there for its own base
    ViewWorld world("", true, 0, false); // no resident module needed
    ASSERT_NE(world.uc, nullptr);
    world.state.files.push_back({});
    world.state.files.back().content = world.image;

    syscalls::SyscallFrame frame{};
    syscalls::SyscallOutcome outcome;
    outcome.section_file_handle = engine::kFileHandleBase;
    const auto handle_out = world.scratch_base + 0x200;
    outcome.section_handle_out = handle_out;
    engine::apply_create_section(world.state, world.uc, frame, outcome);
    ASSERT_EQ(outcome.status, 0u);
    std::uint64_t handle = 0;
    uc_mem_read(world.uc, handle_out, &handle, sizeof handle);
    ASSERT_NE(handle, 0u);

    const auto first = map_view(world, handle, world.view_base, outcome.status);
    ASSERT_EQ(outcome.status, 0u);
    const auto second = map_view(world, handle, world.view_base + 0x10000, outcome.status);
    ASSERT_EQ(outcome.status, 0u);

    const auto info = loader::parse_pe(world.image);
    ASSERT_TRUE(info.has_value());
    const auto built = loader::build_image(world.image, *info);
    ASSERT_TRUE(built.has_value());
    expect_view_matches(world, first, expected_view(*built, info->image_base, first, true));
    expect_view_matches(world, second, expected_view(*built, info->image_base, second, true));
}

// ---- task 2.4: the 48-63 character folded name opens through its index -----

TEST(KnownDllView, LongFoldedNameOpensAndServesContent)
{
    // ModuleRecord carries 64 name bytes, the SectionObject field 48: the
    // open binds the module INDEX, so a name too long for the section field
    // still opens its module and serves its view
    const std::string name = "api-ms-win-core-psapi-l1-1-0-with-a-deliberately-long-name.dll";
    ASSERT_GE(name.size(), 48u);
    ASSERT_LE(name.size(), 63u);
    ViewWorld world(name, true, sheller_test::kFixtureDllImageSize);
    ASSERT_NE(world.uc, nullptr);
    std::uint32_t status = 0;
    const auto handle = open_known_dll(world, name, status);
    ASSERT_EQ(status, 0u) << "the truncated section name must not miss the module";
    ASSERT_NE(handle, 0u);
    const auto view_base = map_view(world, handle, world.view_base, status);
    ASSERT_EQ(status, 0u);
    expect_view_matches(world, view_base, expected_view(world.image, world.base, view_base, true));
}

// ---- task 2.5: a sparse resident module serves its own zeros ---------------

TEST(KnownDllView, SparseResidentModuleServesGapPagesAsZeros)
{
    // only the first half of the module span carries content (the captured
    // world's content-absent protection pages): the copy reads the gap as
    // zeros, the view serves, and the run stays intact
    ViewWorld world("kernel32.dll", true, 0x2000);
    ASSERT_NE(world.uc, nullptr);
    std::uint32_t status = 0;
    const auto handle = open_known_dll(world, "kernel32.dll", status);
    ASSERT_EQ(status, 0u);
    const auto view_base = map_view(world, handle, world.view_base, status);
    ASSERT_EQ(status, 0u);

    auto resident = world.image;
    std::fill(resident.begin() + 0x2000, resident.end(), std::uint8_t{0});
    // the gap swallows the export directory and the thunk (they sit past
    // 0x2000): the patch writes the stub but finds no walkable export, so
    // the slot keeps its delta-shifted world bytes
    expect_view_matches(world, view_base,
                        expected_view(resident, world.base, view_base, true, false));

    // run intact: a second mapping of the same sparse module still answers
    const auto second = map_view(world, handle, world.view_base + 0x10000, status);
    ASSERT_EQ(status, 0u);
    expect_view_matches(world, second, expected_view(resident, world.base, second, true, false));
}

// ---- task 2.6: hostile headers reject before any unbounded read ------------

TEST(KnownDllView, OutOfBoundsHeadersKeepTheZeroFilledView)
{
    // truncated optional header (SizeOfOptionalHeader puts the section table
    // past the copy): the pre-validation rejects, the view stays zero-filled
    // and the run answers the next call intact
    ViewWorld world("kernel32.dll", true, sheller_test::kFixtureDllImageSize);
    ASSERT_NE(world.uc, nullptr);
    auto corrupted = world.image;
    std::uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, corrupted.data() + 0x3C, 4);
    const std::uint16_t huge = 0xF000;
    std::memcpy(corrupted.data() + e_lfanew + 0x14, &huge, 2);
    uc_mem_write(world.uc, world.base, corrupted.data(), corrupted.size());

    std::uint32_t status = 0;
    const auto handle = open_known_dll(world, "kernel32.dll", status);
    ASSERT_EQ(status, 0u);
    const auto view_base = map_view(world, handle, world.view_base, status);
    ASSERT_EQ(status, 0u);
    const auto view = world.read_guest(view_base, corrupted.size());
    for (std::size_t i = 0; i < view.size(); ++i) {
        ASSERT_EQ(view[i], 0) << "byte " << std::hex << i;
    }

    // the same face with an out-of-bounds section table
    const std::uint16_t many_sections = 0x4000;
    corrupted = world.image;
    std::memcpy(corrupted.data() + e_lfanew + 6, &many_sections, 2);
    uc_mem_write(world.uc, world.base, corrupted.data(), corrupted.size());
    const auto second_handle = open_known_dll(world, "kernel32.dll", status);
    ASSERT_EQ(status, 0u);
    const auto second = map_view(world, second_handle, world.view_base + 0x10000, status);
    ASSERT_EQ(status, 0u);
    const auto second_view = world.read_guest(second, corrupted.size());
    for (std::size_t i = 0; i < second_view.size(); ++i) {
        ASSERT_EQ(second_view[i], 0) << "byte " << std::hex << i;
    }
}

// ---- task 2.7: the hygiene offsets are magic-dependent ---------------------

TEST(KnownDllView, HygieneClearsOnlyTheTargetFields)
{
    // x64: the CheckSum at optional+0x40 and the Security entry at
    // DataDirectory[4] arrive zeroed; the adjacent words the old wrong-offset
    // zeroing cleared, SizeOfInitializedData and the reloc directory entry
    // all survive
    {
        ViewWorld world("kernel32.dll", true, sheller_test::kFixtureDllImageSize);
        ASSERT_NE(world.uc, nullptr);
        std::uint32_t status = 0;
        const auto handle = open_known_dll(world, "kernel32.dll", status);
        ASSERT_EQ(status, 0u);
        const auto view_base = map_view(world, handle, world.view_base, status);
        ASSERT_EQ(status, 0u);
        const auto view = world.read_guest(view_base, world.image.size());
        const std::size_t optional = 0x40 + 0x18;
        std::uint32_t adjacent = 0;
        std::memcpy(&adjacent, view.data() + optional + 0x28, 4);
        EXPECT_EQ(adjacent, sheller_test::kFixtureAdjacentWords);
        std::uint32_t initialized = 0;
        std::memcpy(&initialized, view.data() + optional + 0x08, 4);
        EXPECT_EQ(initialized, sheller_test::kFixtureSizeOfInitializedData);
        std::uint32_t checksum = 0;
        std::memcpy(&checksum, view.data() + optional + 0x40, 4);
        EXPECT_EQ(checksum, 0u);
        std::uint32_t security_va = 0;
        std::uint32_t security_size = 0;
        std::memcpy(&security_va, view.data() + optional + 0x70 + 4 * 8, 4);
        std::memcpy(&security_size, view.data() + optional + 0x70 + 4 * 8 + 4, 4);
        EXPECT_EQ(security_va, 0u);
        EXPECT_EQ(security_size, 0u);
        std::uint32_t reloc_rva = 0;
        std::memcpy(&reloc_rva, view.data() + optional + 0x70 + 5 * 8, 4);
        EXPECT_NE(reloc_rva, 0u);
    }
    // x86 (PE32): the Security entry sits at DataDirectory[4] off the PE32
    // data-directory base (optional+0x60) - the fixed 0x70 spelling cleared
    // the wrong directory. Same survivors, the unbound thunk slot untouched
    // (the compat patch is an x64 face).
    {
        ViewWorld world("kernel32.dll", false, sheller_test::kFixtureDllImageSize);
        ASSERT_NE(world.uc, nullptr);
        std::uint32_t status = 0;
        const auto handle = open_known_dll(world, "kernel32.dll", status);
        ASSERT_EQ(status, 0u);
        const auto view_base = map_view(world, handle, world.view_base, status);
        ASSERT_EQ(status, 0u);
        const auto view = world.read_guest(view_base, world.image.size());
        const std::size_t optional = 0x40 + 0x18;
        std::uint32_t checksum = 0;
        std::memcpy(&checksum, view.data() + optional + 0x40, 4);
        EXPECT_EQ(checksum, 0u);
        std::uint32_t security_va = 0;
        std::uint32_t security_size = 0;
        std::memcpy(&security_va, view.data() + optional + 0x60 + 4 * 8, 4);
        std::memcpy(&security_size, view.data() + optional + 0x60 + 4 * 8 + 4, 4);
        EXPECT_EQ(security_va, 0u);
        EXPECT_EQ(security_size, 0u);
        std::uint32_t adjacent = 0;
        std::memcpy(&adjacent, view.data() + optional + 0x28, 4);
        EXPECT_EQ(adjacent, sheller_test::kFixtureAdjacentWords);
        std::uint32_t reloc_rva = 0;
        std::memcpy(&reloc_rva, view.data() + optional + 0x60 + 5 * 8, 4);
        EXPECT_NE(reloc_rva, 0u);
        std::uint32_t slot = 0;
        std::memcpy(&slot, view.data() + kFixtureThunkSlotRva, 4);
        EXPECT_EQ(slot, static_cast<std::uint32_t>(static_cast<std::uint32_t>(world.base) +
                                                   kFixtureThunkSlotRva));
        const std::uint32_t pointer = static_cast<std::uint32_t>(
            static_cast<std::uint32_t>(view_base) + kFixtureRelocPointerRva);
        std::uint32_t relocated = 0;
        std::memcpy(&relocated, view.data() + kFixtureRelocPointerRva, 4);
        EXPECT_EQ(relocated, pointer);
    }
}

} // namespace
