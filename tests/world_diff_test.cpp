// World diff harness test: the Python tool (tools/world_diff.py) is driven
// end to end over engine-written fixture snapshots - the sheller::snapshot
// Writer serializes both worlds, so a format drift turns this test red
// before the tool's own reader can silently diverge. The fixture pair plants
// one difference of every cause class (relocation delta, import binding,
// plain .data byte, KUSD time fields, Ldr chain shape, module set) and the
// checker script asserts the classification per entry, plus the reader's
// named refusals, the v2 pending-block paths, and the --interest states.
#include <gtest/gtest.h>

#include <sheller/snapshot.h>

#include "snapshot_fixture.h"
#include "test_temp.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <sys/wait.h>
#endif

#ifndef WORLD_DIFF_TOOL
#error WORLD_DIFF_TOOL not defined
#endif
#ifndef WORLD_DIFF_CHECK
#error WORLD_DIFF_CHECK not defined
#endif
#ifndef WORLD_DIFF_PYTHON
#error WORLD_DIFF_PYTHON not defined
#endif

namespace fs = std::filesystem;
namespace snapshot = sheller::snapshot;
using sheller_test::put_u16;
using sheller_test::put_u32;
using sheller_test::put_u64;

namespace {

constexpr std::uint32_t kPageReadwrite = 0x04;
constexpr std::uint32_t kPageReadonly = 0x02;
constexpr std::uint32_t kMemImage = 0x1000000;
constexpr std::uint32_t kMemPrivate = 0x20000;

// Capture-world constants: real-shaped layout, UTF-16 Ldr names.
constexpr std::uint64_t kCapNtdll = 0x7FF912345000;
constexpr std::uint64_t kCapK32 = 0x7FF9DEF50000;
constexpr std::uint64_t kCapW32u = 0x7FF9CFF00000;
constexpr std::uint64_t kCapTail = 0x7FF9B0000000;
constexpr std::uint64_t kCapIntended = 0x7FF9BB000000;
constexpr std::uint64_t kCapUnrelated = 0x7FF9BC000000;
constexpr std::uint64_t kCapImporter = 0x7FF9BD000000;
constexpr std::uint64_t kCapImporterBad = 0x7FF9BE000000;
constexpr std::uint64_t kCapHeap = 0x7FF9D0000000; // Ldr area lives here
constexpr std::uint64_t kCapPeb = 0x7FF9E0001000;
constexpr std::uint64_t kCapTeb = 0x7FF9E0000000;
constexpr std::uint64_t kCapImageBase = 0x140000000;
constexpr std::uint64_t kCapStack = 0x7FF9F0000000;

// Crafted-world constants: the engine's env-block layout, narrow ASCII names.
constexpr std::uint64_t kCraNtdll = 0x7FFEE0000000;
constexpr std::uint64_t kCraK32 = 0x7FFEE0010000;
constexpr std::uint64_t kCraW32u = 0x7FFEE0020000;
constexpr std::uint64_t kCraWmi = 0x7FFEE0030000;
constexpr std::uint64_t kCraTail = 0x7FFEE0040000;
constexpr std::uint64_t kCraIntended = 0x7FFEE0050000;
constexpr std::uint64_t kCraUnrelated = 0x7FFEE0060000;
constexpr std::uint64_t kCraImporter = 0x7FFEE0070000;
constexpr std::uint64_t kCraImporterBad = 0x7FFEE0080000;
constexpr std::uint64_t kCraEnv = 0x330000000; // TEB@+0, PEB@+0x1000, Ldr@+0x3000
constexpr std::uint64_t kCraHeap = 0x320000000;
constexpr std::uint64_t kCraImageBase = 0x400000;
constexpr std::uint64_t kCraStack = 0x300000000;

constexpr std::uint64_t kKusd = 0x7FFE0000;

struct PeSectionDef {
    std::string_view name;
    std::uint32_t rva;
    std::uint32_t vsize;
};

// A minimal PE32+ image with optional reloc (DIR64 entries at page 0x4000)
// and import (descriptor at 0x2780, IAT slots at 0x2800, imported-module
// name spelled at 0x2820) directories.
std::vector<std::uint8_t> build_pe_image(
    std::uint32_t image_size, const std::vector<PeSectionDef>& sections,
    const std::vector<std::uint32_t>& reloc_qwords,
    const std::vector<std::pair<std::uint32_t, std::uint64_t>>& iat_slots,
    std::string_view import_name = "ntdll.dll")
{
    std::vector<std::uint8_t> image(image_size, std::uint8_t{0});
    image[0] = 'M';
    image[1] = 'Z';
    put_u32(image, 0x3C, 0x40);
    put_u32(image, 0x40, 0x00004550);
    put_u16(image, 0x44, 0x8664);
    put_u16(image, 0x46, static_cast<std::uint16_t>(sections.size()));
    put_u16(image, 0x54, 0xF0);
    constexpr std::size_t kOptional = 0x58;
    put_u16(image, kOptional, 0x020B);
    put_u32(image, kOptional + 16, 0x1000);
    put_u64(image, kOptional + 24, 0);
    put_u32(image, kOptional + 32, 0x1000);
    put_u32(image, kOptional + 36, 0x200);
    put_u32(image, kOptional + 56, image_size);
    put_u32(image, kOptional + 60, 0x1000);
    put_u32(image, kOptional + 108, 16); // NumberOfRvaAndSizes
    constexpr std::size_t kDd = kOptional + 112;
    if (!iat_slots.empty()) {
        put_u32(image, kDd + 8, 0x2780);
        put_u32(image, kDd + 12, 0x100);
    }
    if (!reloc_qwords.empty()) {
        put_u32(image, kDd + 40, 0x4000);
        put_u32(image, kDd + 44, 0x100);
    }
    const std::size_t kTable = kOptional + 0xF0;
    for (std::size_t i = 0; i < sections.size(); ++i) {
        const std::size_t at = kTable + 40 * i;
        std::copy(sections[i].name.begin(), sections[i].name.end(),
                  image.begin() + static_cast<std::ptrdiff_t>(at));
        put_u32(image, at + 8, sections[i].vsize);
        put_u32(image, at + 12, sections[i].rva);
        put_u32(image, at + 16, sections[i].vsize);
        put_u32(image, at + 20, sections[i].rva);
        put_u32(image, at + 36, 0x60000020);
    }
    if (!reloc_qwords.empty()) {
        const std::uint32_t page = reloc_qwords.front() & ~0xFFFu;
        std::vector<std::uint16_t> rel;
        for (const auto rva : reloc_qwords) {
            rel.push_back(static_cast<std::uint16_t>((10 << 12) | (rva - page)));
        }
        if (rel.size() % 2 != 0) {
            rel.push_back(0); // ABSOLUTE pad keeps the block 4-byte aligned
        }
        put_u32(image, 0x4000, page);
        put_u32(image, 0x4004, static_cast<std::uint32_t>(8 + rel.size() * 2));
        for (std::size_t i = 0; i < rel.size(); ++i) {
            put_u16(image, 0x4008 + 2 * i, rel[i]);
        }
    }
    if (!iat_slots.empty()) {
        put_u32(image, 0x2780, 0);      // OriginalFirstThunk
        put_u32(image, 0x2784, 0);      // TimeDateStamp
        put_u32(image, 0x2788, 0);      // ForwarderChain
        put_u32(image, 0x278C, 0x2820); // Name
        put_u32(image, 0x2790, 0x2800); // FirstThunk
        for (const auto& [rva, value] : iat_slots) {
            put_u64(image, rva, value);
        }
        std::copy(import_name.begin(), import_name.end(), image.begin() + 0x2820);
    }
    return image;
}

struct LdrModule {
    std::string name;
    std::uint64_t base;
    std::uint32_t size;
};

// The engine's Ldr area (env.cpp layout): three closed chains with heads at
// +0x10/0x20/0x30, entries at +0x58+i*0x100, DllBase@+0x30, SizeOfImage@+0x40,
// BaseDllName UNICODE_STRING@+0x58 aliasing the name bytes at block+0x80.
// narrow=true spells names as ASCII with byte-count Length (the synthetic
// environment shape); narrow=false spells UTF-16LE (real capture shape).
std::vector<std::uint8_t> build_ldr_area(std::uint64_t area_va,
                                         const std::vector<LdrModule>& modules, bool narrow)
{
    std::vector<std::uint8_t> area(0x10000, std::uint8_t{0});
    const std::size_t count = modules.size();
    const auto entry_base = [&](std::size_t i) { return area_va + 0x58 + i * 0x100; };
    for (std::size_t c = 0; c < 3; ++c) {
        const std::size_t head = 0x10 + c * 0x10;
        if (count == 0) {
            continue;
        }
        put_u64(area, head, entry_base(0) + c * 0x10);
        put_u64(area, head + 8, entry_base(count - 1) + c * 0x10);
        for (std::size_t i = 0; i < count; ++i) {
            const std::size_t at = 0x58 + i * 0x100 + c * 0x10;
            const std::uint64_t next =
                i + 1 < count ? entry_base(i + 1) + c * 0x10 : area_va + head;
            const std::uint64_t prev = i > 0 ? entry_base(i - 1) + c * 0x10 : area_va + head;
            put_u64(area, at, next);
            put_u64(area, at + 8, prev);
        }
    }
    for (std::size_t i = 0; i < count; ++i) {
        const std::size_t block = 0x58 + i * 0x100;
        put_u64(area, block + 0x30, modules[i].base);
        put_u32(area, block + 0x40, modules[i].size);
        std::vector<std::uint8_t> raw;
        std::uint16_t max_len = 0;
        if (narrow) {
            raw.assign(modules[i].name.begin(), modules[i].name.end());
            max_len = static_cast<std::uint16_t>(raw.size() + 1);
        } else {
            for (const char ch : modules[i].name) {
                raw.push_back(static_cast<std::uint8_t>(ch));
                raw.push_back(std::uint8_t{0});
            }
            max_len = static_cast<std::uint16_t>(raw.size() + 2);
        }
        std::copy(raw.begin(), raw.end(),
                  area.begin() + static_cast<std::ptrdiff_t>(block + 0x80));
        const std::uint64_t buffer_va = area_va + block + 0x80;
        put_u16(area, block + 0x48, static_cast<std::uint16_t>(raw.size()));
        put_u16(area, block + 0x4A, max_len);
        put_u64(area, block + 0x50, buffer_va);
        put_u16(area, block + 0x58, static_cast<std::uint16_t>(raw.size()));
        put_u16(area, block + 0x5A, max_len);
        put_u64(area, block + 0x60, buffer_va);
    }
    return area;
}

struct RegionDef {
    std::uint64_t base{};
    std::uint32_t protection{};
    std::uint32_t type{};
    std::vector<std::uint8_t> content; // empty -> content-absent record
};

// One fixture world, serialized by the real snapshot Writer (v1, or v2 with
// the pending block). The module set and the planted diffs are the test's
// contract - see AlignClassifiesEveryCauseClass below. break_teb_self zeroes
// the crafted TEB's Self field so the self-check entries have something to
// find (used by the interest side-matching test).
void write_fixture_world(const fs::path& path, bool crafted, bool include_kusd,
                         const std::optional<std::pair<std::string, std::vector<std::uint8_t>>>&
                             pending,
                         bool break_teb_self = false)
{
    std::vector<std::uint8_t> ntdll = build_pe_image(
        0x6000,
        {{".text", 0x1000, 0x1000}, {".rdata", 0x2000, 0x1000},
         {".data", 0x3000, 0x1000}, {".reloc", 0x4000, 0x1000}},
        {0x1000, 0x1008}, {});
    std::vector<std::uint8_t> k32 = build_pe_image(
        0x3000, {{".text", 0x1000, 0x1000}, {".data", 0x2000, 0x1000}}, {}, {});
    std::vector<std::uint8_t> w32u =
        build_pe_image(0x2000, {{".text", 0x1000, 0x1000}}, {}, {});
    std::vector<std::uint8_t> wmi = build_pe_image(0x2000, {{".text", 0x1000, 0x1000}}, {}, {});
    // tailmod: .tail's virtual size is not qword-aligned (0x1004) and the
    // crafted copy differs only in the last byte - the sub-qword residual
    // must still report.
    std::vector<std::uint8_t> tailmod =
        build_pe_image(0x4000, {{".text", 0x1000, 0x1000}, {".tail", 0x2000, 0x1004}}, {}, {});
    std::vector<std::uint8_t> tailmod_crafted = tailmod;
    tailmod_crafted[0x3003] ^= 0xFF; // the last byte: a sub-qword residual diff
    // intended/unrelated: the importer's slots are judged against the
    // referenced module's identity, not "any loaded module"
    std::vector<std::uint8_t> intended =
        build_pe_image(0x2000, {{".text", 0x1000, 0x1000}}, {}, {});
    std::vector<std::uint8_t> unrelated =
        build_pe_image(0x2000, {{".text", 0x1000, 0x1000}}, {}, {});

    std::uint64_t peb = 0;
    std::uint64_t teb = 0;
    std::uint64_t image_base = 0;
    std::vector<LdrModule> modules;
    bool narrow = false;
    std::vector<RegionDef> regions;

    if (!crafted) {
        peb = kCapPeb;
        teb = kCapTeb;
        image_base = kCapImageBase;
        narrow = false;
        modules = {{"ntdll.dll", kCapNtdll, 0x6000},
                   {"kernel32.dll", kCapK32, 0x3000},
                   {"win32u.dll", kCapW32u, 0x2000},
                   {"tailmod.dll", kCapTail, 0x4000},
                   {"intended.dll", kCapIntended, 0x2000},
                   {"unrelated.dll", kCapUnrelated, 0x2000},
                   {"importer.dll", kCapImporter, 0x3000},
                   {"importer_bad.dll", kCapImporterBad, 0x3000}};
        // relocation-covered qwords: one carrying the base delta, one fixed;
        // IAT slots bound inside the capture world's ntdll span
        ntdll = build_pe_image(
            0x6000,
            {{".text", 0x1000, 0x1000}, {".rdata", 0x2000, 0x1000},
             {".data", 0x3000, 0x1000}, {".reloc", 0x4000, 0x1000}},
            {0x1000, 0x1008},
            {{0x2800, kCapNtdll + 0x1000}, {0x2808, kCapNtdll + 0x800}});
        put_u64(ntdll, 0x1000, kCapNtdll + 0x2000);
        put_u64(ntdll, 0x1008, 0x2222222222222222);
        // importer: both slots claim intended.dll; both capture bindings sit
        // in the capture world's intended span
        std::vector<std::uint8_t> importer = build_pe_image(
            0x3000,
            {{".text", 0x1000, 0x1000}, {".rdata", 0x2000, 0x1000}},
            {},
            {{0x2800, kCapIntended + 0x1000}, {0x2808, kCapIntended + 0x800}},
            "intended.dll");
        // importer_bad: its descriptor's Name RVA leaves the image, so the
        // slot identity is unreadable - a diff there is cause-uncertain
        std::vector<std::uint8_t> importer_bad = build_pe_image(
            0x3000,
            {{".text", 0x1000, 0x1000}, {".rdata", 0x2000, 0x1000}},
            {},
            {{0x2800, kCapIntended + 0x1000}, {0x2808, kCapIntended + 0x800}},
            "intended.dll");
        put_u32(importer_bad, 0x278C, 0x7FFFFFFF);
        regions.push_back({kCapNtdll, 0x20, kMemImage, ntdll});
        regions.push_back({kCapK32, 0x20, kMemImage, k32});
        regions.push_back({kCapW32u, 0x20, kMemImage, w32u});
        regions.push_back({kCapTail, 0x20, kMemImage, tailmod});
        regions.push_back({kCapIntended, 0x20, kMemImage, intended});
        regions.push_back({kCapUnrelated, 0x20, kMemImage, unrelated});
        regions.push_back({kCapImporter, 0x20, kMemImage, importer});
        regions.push_back({kCapImporterBad, 0x20, kMemImage, importer_bad});
    } else {
        teb = kCraEnv;
        peb = kCraEnv + 0x1000;
        image_base = kCraImageBase;
        narrow = true;
        modules = {{"ntdll.dll", kCraNtdll, 0x6000},
                   {"win32u.dll", kCraW32u, 0x2000},
                   {"kernel32.dll", kCraK32, 0x3000},
                   {"wmi.dll", kCraWmi, 0x2000},
                   {"tailmod.dll", kCraTail, 0x4000},
                   {"intended.dll", kCraIntended, 0x2000},
                   {"unrelated.dll", kCraUnrelated, 0x2000},
                   {"importer.dll", kCraImporter, 0x3000},
                   {"importer_bad.dll", kCraImporterBad, 0x3000}};
        ntdll = build_pe_image(
            0x6000,
            {{".text", 0x1000, 0x1000}, {".rdata", 0x2000, 0x1000},
             {".data", 0x3000, 0x1000}, {".reloc", 0x4000, 0x1000}},
            {0x1000, 0x1008},
            {{0x2800, kCraNtdll + 0x1000}, {0x2808, 0x1234567812345678}});
        put_u64(ntdll, 0x1000, kCraNtdll + 0x2000);
        put_u64(ntdll, 0x1008, 0x4444444444444444); // relocation anomaly
        ntdll[0x3005] = 0xAA;                       // the one-byte .data diff
        // importer: slot0 still binds into crafted intended (expected), slot1
        // binds into unrelated - a wrong-module target is an anomaly even
        // though it lands inside SOME loaded module
        std::vector<std::uint8_t> importer = build_pe_image(
            0x3000,
            {{".text", 0x1000, 0x1000}, {".rdata", 0x2000, 0x1000}},
            {},
            {{0x2800, kCraIntended + 0x1000}, {0x2808, kCraUnrelated + 0x800}},
            "intended.dll");
        std::vector<std::uint8_t> importer_bad = build_pe_image(
            0x3000,
            {{".text", 0x1000, 0x1000}, {".rdata", 0x2000, 0x1000}},
            {},
            {{0x2800, kCraIntended + 0x1000}, {0x2808, kCraIntended + 0x400}},
            "intended.dll");
        put_u32(importer_bad, 0x278C, 0x7FFFFFFF);
        regions.push_back({kCraNtdll, 0x20, kMemImage, ntdll});
        regions.push_back({kCraK32, 0x20, kMemImage, k32});
        regions.push_back({kCraW32u, 0x20, kMemImage, w32u});
        regions.push_back({kCraWmi, 0x20, kMemImage, wmi});
        regions.push_back({kCraTail, 0x20, kMemImage, tailmod_crafted});
        regions.push_back({kCraIntended, 0x20, kMemImage, intended});
        regions.push_back({kCraUnrelated, 0x20, kMemImage, unrelated});
        regions.push_back({kCraImporter, 0x20, kMemImage, importer});
        regions.push_back({kCraImporterBad, 0x20, kMemImage, importer_bad});
    }

    // KUSD page: capture carries real-shaped values, crafted the engine seeds
    // (env.cpp fill_kuser_shared_data) plus honest zeros elsewhere. Offsets
    // are the SDK's KUSER_SHARED_DATA layout (ksamd64.inc): InterruptTime
    // 0x08, SystemTime 0x14, TickCount 0x320, NtSystemRoot 0x30.
    std::vector<std::uint8_t> kusd(0x1000, std::uint8_t{0});
    if (!crafted) {
        for (int i = 0; i < 12; ++i) {
            kusd[0x08 + i] = static_cast<std::uint8_t>(0x11 + i);
        }
        put_u64(kusd, 0x14, 0x01D8F0123456789A);
        kusd[0x320] = 0xEF;
        kusd[0x321] = 0xBE;
        kusd[0x322] = 0x00;
        kusd[0x323] = 0x0B;
        const std::string_view root = "C:\\WINDOWS";
        for (std::size_t i = 0; i < root.size(); ++i) {
            kusd[0x30 + 2 * i] = static_cast<std::uint8_t>(root[i]);
        }
    } else {
        put_u64(kusd, 0x14, 0x01D9000000000000);
        put_u32(kusd, 0x320, 0x10000000);
    }
    if (include_kusd) {
        regions.push_back({kKusd, kPageReadonly, kMemPrivate, kusd});
    }

    if (!crafted) {
        const std::uint64_t area_va = kCapHeap;
        regions.push_back({kCapHeap, kPageReadwrite, kMemPrivate,
                           build_ldr_area(area_va, modules, narrow)});
        std::vector<std::uint8_t> peb_page(0x1000, std::uint8_t{0});
        put_u64(peb_page, 0x10, image_base);
        put_u64(peb_page, 0x18, area_va);
        put_u64(peb_page, 0x30, kCapHeap + 0x10000);
        regions.push_back({kCapPeb, kPageReadwrite, kMemPrivate, peb_page});
        std::vector<std::uint8_t> teb_page(0x1000, std::uint8_t{0});
        put_u64(teb_page, 0x30, teb);
        put_u64(teb_page, 0x60, peb);
        regions.push_back({kCapTeb, kPageReadwrite, kMemPrivate, teb_page});
        regions.push_back({kCapStack, kPageReadwrite, kMemPrivate,
                           std::vector<std::uint8_t>(0x1000, std::uint8_t{0x5A})});
    } else {
        const std::uint64_t area_va = kCraEnv + 0x3000;
        std::vector<std::uint8_t> page(0x13000, std::uint8_t{0});
        const auto area = build_ldr_area(area_va, modules, narrow);
        std::copy(area.begin(), area.end(), page.begin() + 0x3000);
        if (!break_teb_self) {
            put_u64(page, 0x30, teb);
        }
        put_u64(page, 0x60, peb);
        put_u64(page, 0x1010, image_base);
        put_u64(page, 0x1018, area_va);
        put_u64(page, 0x1030, kCraHeap);
        regions.push_back({kCraEnv, kPageReadwrite, kMemPrivate, page});
        regions.push_back({kCraHeap, kPageReadwrite, kMemPrivate,
                           std::vector<std::uint8_t>(0x1000, std::uint8_t{0})});
        regions.push_back({kCraStack, kPageReadwrite, kMemPrivate,
                           std::vector<std::uint8_t>(0x1000, std::uint8_t{0x5A})});
    }

    std::ostringstream out;
    snapshot::Writer writer{out};
    EXPECT_TRUE(writer.write_header(snapshot::Header{
        .version = pending.has_value() ? snapshot::kVersionV2 : snapshot::kVersion,
        .bitness = snapshot::kBitness64}));
    snapshot::Registers registers{};
    registers.rip = image_base + 0x1000;
    registers.rflags = 0x246;
    EXPECT_TRUE(writer.write_registers(registers));
    snapshot::Metadata metadata{};
    metadata.peb_address = peb;
    metadata.teb_address = teb;
    metadata.image_base = image_base;
    metadata.entry_address = image_base + 0x1000;
    EXPECT_TRUE(writer.write_metadata(metadata));
    for (const auto& region : regions) {
        snapshot::RegionHeader header{.base_address = region.base,
                                      .size = region.content.size(),
                                      .protection = region.protection,
                                      .type = region.type,
                                      .content = region.content.empty()
                                                     ? snapshot::kContentAbsent
                                                     : snapshot::kContentPresent};
        EXPECT_TRUE(writer.write_region(
            header, region.content.empty() ? nullptr : region.content.data()));
    }
    EXPECT_TRUE(writer.finalize_region_count());
    if (pending.has_value()) {
        snapshot::PendingModule module{.name = pending->first,
                                       .bitness = snapshot::kBitness64,
                                       .bytes = pending->second};
        EXPECT_TRUE(writer.write_pending(module));
    }
    const std::string bytes = out.str();
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    ASSERT_TRUE(static_cast<bool>(file));
}

// std::system + a redirect into a log file: the proven invocation shape here
// (a piped cmd line trips the shell's quote handling). POSIX wait statuses
// carry the code in the high byte, so unwrap it for the exit-code checks.
int wait_status_code(int status)
{
#ifdef _WIN32
    return status;
#else
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
#endif
}

struct RunResult {
    int exit_code = -1;
    std::string log;
};

RunResult run_command(const std::string& command)
{
    const auto log_path = sheller_test::temp_path("world_diff_run_log");
    const std::string line =
        command + " > \"" + log_path.string() + "\" 2>&1";
    RunResult result;
    result.exit_code = wait_status_code(std::system(line.c_str()));
    std::ifstream in(log_path, std::ios::binary);
    result.log = {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    return result;
}

RunResult run_tool(const std::string& arguments)
{
    return run_command(std::string(WORLD_DIFF_PYTHON) + " \"" + WORLD_DIFF_TOOL + "\" " +
                       arguments);
}

RunResult run_checker(const fs::path& report, const fs::path& checks)
{
    return run_command(std::string(WORLD_DIFF_PYTHON) + " \"" + WORLD_DIFF_CHECK + "\" \"" +
                       report.string() + "\" \"" + checks.string() + "\"");
}

std::string write_text(const fs::path& path, const std::string& content)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    return path.string();
}

std::vector<std::uint8_t> read_bytes(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::string check_json(const std::string& must_include_json,
                       const std::string& must_not_include_json = "[]",
                       const std::string& expect_json = "{}")
{
    return "{\"must_include\": " + must_include_json +
           ", \"must_not_include\": " + must_not_include_json +
           ", \"expect\": " + expect_json + "}";
}

fs::path fixture_dir()
{
    const auto dir = sheller_test::temp_path("world_diff_test");
    fs::create_directories(dir);
    return dir;
}

} // namespace

// The main matrix: alignment across differing bases, one entry per cause
// class, the module set, the infrastructure fields, and the .data one-byte
// acceptance - same-name modules always enter the per-section comparison.
TEST(WorldDiff, AlignClassifiesEveryCauseClass)
{
    const auto dir = fixture_dir();
    const auto cap = dir / "capture.snap";
    const auto cra = dir / "crafted.snap";
    ASSERT_NO_FATAL_FAILURE(write_fixture_world(cap, false, true, std::nullopt));
    ASSERT_NO_FATAL_FAILURE(write_fixture_world(cra, true, true, std::nullopt));
    const auto report = dir / "report.json";
    const auto run = run_tool("\"" + cap.string() + "\" \"" + cra.string() + "\" --output \"" +
                              report.string() + "\"");
    EXPECT_EQ(run.exit_code, 0) << run.log;

    const auto checks = write_text(
        dir / "checks.json",
        check_json(
            R"([
              {"domain": "module_set", "classification": "expected", "module": "wmi.dll", "present": "crafted"},
              {"domain": "module_image", "classification": "candidate", "module": "ntdll.dll", "section": ".data", "diff_count": 1},
              {"domain": "module_image", "classification": "expected-reloc", "module": "ntdll.dll", "section": ".text", "diff_count": 1},
              {"domain": "module_image", "classification": "candidate-reloc-anomaly", "module": "ntdll.dll", "section": ".text", "diff_count": 1},
              {"domain": "module_image", "classification": "expected-import", "module": "ntdll.dll", "section": ".rdata", "diff_count": 1, "first_offset": "0x2800"},
              {"domain": "module_image", "classification": "candidate-import-anomaly", "module": "ntdll.dll", "section": ".rdata", "diff_count": 1, "first_offset": "0x2808"},
              {"domain": "module_image", "classification": "candidate", "module": "tailmod.dll", "section": ".tail", "diff_count": 1, "first_offset": "0x3003"},
              {"domain": "module_image", "classification": "expected-import", "module": "importer.dll", "section": ".rdata", "diff_count": 1, "first_offset": "0x2800"},
              {"domain": "module_image", "classification": "candidate-import-anomaly", "module": "importer.dll", "section": ".rdata", "diff_count": 1, "first_offset": "0x2808"},
              {"domain": "module_image", "classification": "cause-uncertain", "module": "importer_bad.dll", "section": ".rdata", "diff_count": 2},
              {"domain": "infrastructure", "classification": "expected-volatile", "target": "kusd.systemtime"},
              {"domain": "infrastructure", "classification": "expected-volatile", "target": "kusd.tick_count"},
              {"domain": "infrastructure", "classification": "expected-volatile", "target": "kusd.interrupt_time"},
              {"domain": "infrastructure", "classification": "candidate", "target": "kusd.nt_system_root", "capture": "c:\\windows"},
              {"domain": "infrastructure", "classification": "candidate", "target": "ldr.load", "detail": "count capture=8 crafted=9"},
              {"domain": "infrastructure", "classification": "candidate", "target": "ldr.load", "detail": "order differs at index 1: capture=kernel32.dll crafted=win32u.dll"},
              {"domain": "infrastructure", "classification": "candidate", "target": "peb.process_heap"}
            ])",
            R"([
              {"classification": "unresolvable"}
            ])",
            R"({
              "modules.only_crafted": ["wmi.dll"],
              "inputs.capture.version": 1,
              "inputs.crafted.version": 1
            })"));
    const auto check = run_checker(report, checks);
    EXPECT_EQ(check.exit_code, 0) << check.log;
}

// Report determinism: same inputs twice, byte-identical output.
TEST(WorldDiff, TwoRunsAreByteIdentical)
{
    const auto dir = fixture_dir();
    const auto cap = dir / "capture.snap";
    const auto cra = dir / "crafted.snap";
    ASSERT_NO_FATAL_FAILURE(write_fixture_world(cap, false, true, std::nullopt));
    ASSERT_NO_FATAL_FAILURE(write_fixture_world(cra, true, true, std::nullopt));
    const auto first = dir / "report1.json";
    const auto second = dir / "report2.json";
    const auto run1 = run_tool("\"" + cap.string() + "\" \"" + cra.string() + "\" --output \"" +
                               first.string() + "\"");
    const auto run2 = run_tool("\"" + cap.string() + "\" \"" + cra.string() + "\" --output \"" +
                               second.string() + "\"");
    EXPECT_EQ(run1.exit_code, 0) << run1.log;
    EXPECT_EQ(run2.exit_code, 0) << run2.log;
    EXPECT_EQ(read_bytes(first), read_bytes(second));
}

// v2 pairs: the pending block participates (equal by construction), a
// differing payload is a candidate, and a v1/v2 mix is refused by name.
TEST(WorldDiff, PendingBlockPaths)
{
    const auto dir = fixture_dir();
    const auto cap_v2 = dir / "cap_v2.snap";
    const auto cra_v2 = dir / "cra_v2.snap";
    const auto cra_diff = dir / "cra_v2_diff.snap";
    const std::pair<std::string, std::vector<std::uint8_t>> pending = {
        "packed.dll", {0x4D, 0x5A, 0x90, 0x00, 0x01, 0x02, 0x03, 0x04}};
    std::pair<std::string, std::vector<std::uint8_t>> pending_other = pending;
    pending_other.second[7] ^= 0xFF;
    ASSERT_NO_FATAL_FAILURE(write_fixture_world(cap_v2, false, true, pending));
    ASSERT_NO_FATAL_FAILURE(write_fixture_world(cra_v2, true, true, pending));
    ASSERT_NO_FATAL_FAILURE(write_fixture_world(cra_diff, true, true, pending_other));

    const auto equal_report = dir / "pending_equal.json";
    const auto run = run_tool("\"" + cap_v2.string() + "\" \"" + cra_v2.string() +
                              "\" --output \"" + equal_report.string() + "\"");
    EXPECT_EQ(run.exit_code, 0) << run.log;
    const auto equal_checks = write_text(
        dir / "pending_equal_checks.json",
        check_json("[]", R"([{"domain": "pending"}])", R"({"pending.equal": true})"));
    const auto equal_check = run_checker(equal_report, equal_checks);
    EXPECT_EQ(equal_check.exit_code, 0) << equal_check.log;

    const auto diff_report = dir / "pending_diff.json";
    const auto run_diff = run_tool("\"" + cap_v2.string() + "\" \"" + cra_diff.string() +
                                   "\" --output \"" + diff_report.string() + "\"");
    EXPECT_EQ(run_diff.exit_code, 0) << run_diff.log;
    const auto diff_checks = write_text(
        dir / "pending_diff_checks.json",
        check_json(R"([{"domain": "pending", "classification": "candidate"}])"));
    const auto diff_check = run_checker(diff_report, diff_checks);
    EXPECT_EQ(diff_check.exit_code, 0) << diff_check.log;
}

// Reader refusals: every named rejection exits nonzero and names itself;
// the v1/v2 mix refusal carries its own name too.
TEST(WorldDiff, ReaderRefusalsAreNamed)
{
    const auto dir = fixture_dir();
    const auto cap = dir / "capture.snap";
    const auto cra = dir / "crafted.snap";
    ASSERT_NO_FATAL_FAILURE(write_fixture_world(cap, false, true, std::nullopt));
    ASSERT_NO_FATAL_FAILURE(write_fixture_world(cra, true, true, std::nullopt));
    const auto bytes = read_bytes(cap);

    // an intact v2 pair on disk, plus a copy of the crafted side whose
    // pending name length is over the format bound
    const auto cap_v2 = dir / "cap_v2_ok.snap";
    const auto cra_v2 = dir / "cra_v2_good.snap";
    const std::pair<std::string, std::vector<std::uint8_t>> pending = {
        "packed.dll", {0x4D, 0x5A, 0x00, 0x00}};
    ASSERT_NO_FATAL_FAILURE(write_fixture_world(cap_v2, false, true, pending));
    ASSERT_NO_FATAL_FAILURE(write_fixture_world(cra_v2, true, true, pending));

    struct Refusal {
        std::string file;
        std::vector<std::uint8_t> content;
        const char* named;
        bool pairs_with_v2; // the bad crafted v2 file must run against a v2 capture
    };
    std::vector<Refusal> refusals;
    {
        auto copy = bytes;
        copy[0] = 'X';
        refusals.push_back({"bad_magic.snap", copy, "kBadMagic", false});
    }
    {
        auto copy = bytes;
        put_u32(copy, 8, 3);
        refusals.push_back({"bad_version.snap", copy, "kUnsupportedVersion", false});
    }
    {
        auto copy = bytes;
        copy[12] = 32;
        refusals.push_back({"bad_bitness.snap", copy, "kBitnessMismatch", false});
    }
    refusals.push_back({"truncated.snap",
                        std::vector<std::uint8_t>(bytes.begin(), bytes.begin() + 100),
                        "kTruncated", false});
    {
        auto copy = read_bytes(cra_v2);
        const std::string marker = "PENDMOD1";
        const auto at =
            std::search(copy.begin(), copy.end(), marker.begin(), marker.end());
        ASSERT_NE(at, copy.end());
        put_u32(copy, static_cast<std::size_t>(at - copy.begin()) + 8, 300);
        refusals.push_back({"cra_bad_pending.snap", copy, "kBadPending", true});
    }

    for (const auto& refusal : refusals) {
        const auto path = write_text(dir / refusal.file,
                                     std::string(refusal.content.begin(), refusal.content.end()));
        const auto first = refusal.pairs_with_v2 ? cap_v2.string() : cap.string();
        const auto run =
            run_tool("\"" + first + "\" \"" + path + "\"");
        EXPECT_NE(run.exit_code, 0) << refusal.file << " accepted: " << run.log;
        EXPECT_NE(run.log.find(refusal.named), std::string::npos)
            << refusal.file << " did not name " << refusal.named << ": " << run.log;
    }
    const auto mixed = run_tool("\"" + cap.string() + "\" \"" + cra_v2.string() + "\"");
    EXPECT_NE(mixed.exit_code, 0);
    EXPECT_NE(mixed.log.find("version-mismatch"), std::string::npos) << mixed.log;
}

// A world whose snapshot lacks a KUSD region leaves the domain named
// unresolvable - never guessed, never silently dropped.
TEST(WorldDiff, KusdMissingRegionIsNamedUnresolvable)
{
    const auto dir = fixture_dir();
    const auto cap = dir / "capture.snap";
    const auto cra = dir / "crafted_no_kusd.snap";
    ASSERT_NO_FATAL_FAILURE(write_fixture_world(cap, false, true, std::nullopt));
    ASSERT_NO_FATAL_FAILURE(write_fixture_world(cra, true, false, std::nullopt));
    const auto report = dir / "report.json";
    const auto run = run_tool("\"" + cap.string() + "\" \"" + cra.string() + "\" --output \"" +
                              report.string() + "\"");
    EXPECT_EQ(run.exit_code, 0) << run.log;
    const auto checks = write_text(
        dir / "checks.json",
        check_json(
            R"([{"domain": "infrastructure", "classification": "unresolvable", "target": "kusd.region"}])"));
    const auto check = run_checker(report, checks);
    EXPECT_EQ(check.exit_code, 0) << check.log;
}

namespace interest {

// The fourth read sits at an unchanged offset inside the same ntdll .data
// section that carries the diff - interest matching runs on the entry's
// actual diff windows, so it must stay unmatched.
constexpr const char* kFullReport = R"({
  "events": {"counts": {"mem-read": 4}, "stub_calls": {}, "detail": [
    {"type": "mem-read", "seq": 1, "tid": 7, "pc": "0x14001000", "addr": "0x7ffee0003000",
     "size": 8, "value": "0xaa"},
    {"type": "mem-read", "seq": 4, "tid": 7, "pc": "0x14001000", "addr": "0x7ffee0003800",
     "size": 8, "value": "0x0"},
    {"type": "mem-read", "seq": 2, "tid": 7, "pc": "0x14001000", "addr": "0x7ffe0014",
     "size": 8, "value": "0x1"},
    {"type": "mem-read", "seq": 3, "tid": 7, "pc": "0x14001000", "addr": "0xdead0000",
     "size": 4, "value": "0x0"}
  ]}})";

constexpr const char* kSemanticReport = R"({
  "events": {"counts": {"mem-read": 1}, "stub_calls": {}, "detail": [
    {"type": "mem-read", "seq": 1, "addr": "0x7ffee0003000", "size": 8, "value": "0xaa"}
  ]}})";

constexpr const char* kEmptyReport =
    R"({"events": {"counts": {}, "stub_calls": {}, "detail": []}})";

} // namespace interest

// --interest over a full-level report: hits annotate and top-sort; the
// semantic-level report matches module domains but names the infrastructure
// restriction; an entry-less report is named insufficient, never a no-hit.
TEST(WorldDiff, InterestAnnotationStates)
{
    const auto dir = fixture_dir();
    const auto cap = dir / "capture.snap";
    const auto cra = dir / "crafted.snap";
    ASSERT_NO_FATAL_FAILURE(write_fixture_world(cap, false, true, std::nullopt));
    ASSERT_NO_FATAL_FAILURE(write_fixture_world(cra, true, true, std::nullopt));

    const auto full = write_text(dir / "full_report.json", interest::kFullReport);
    const auto report = dir / "interest_full.json";
    const auto run = run_tool("\"" + cap.string() + "\" \"" + cra.string() + "\" --interest \"" +
                              full + "\" --interest-side crafted --output \"" + report.string() +
                              "\"");
    EXPECT_EQ(run.exit_code, 0) << run.log;
    const auto full_checks = write_text(
        dir / "interest_full_checks.json",
        check_json(
            R"([
              {"domain": "module_image", "classification": "candidate", "section": ".data", "interest": true},
              {"domain": "infrastructure", "classification": "expected-volatile", "target": "kusd.systemtime", "interest": true}
            ])",
            R"([
              {"target": "kusd.nt_system_root", "interest": true}
            ])",
            R"({
              "interest.detail_state": "sufficient",
              "interest.report_level": "full",
              "interest.side": "crafted",
              "interest.matched": 2
            })"));
    const auto full_check = run_checker(report, full_checks);
    EXPECT_EQ(full_check.exit_code, 0) << full_check.log;

    const auto semantic = write_text(dir / "sem_report.json", interest::kSemanticReport);
    const auto sem_out = dir / "interest_sem.json";
    const auto sem_run =
        run_tool("\"" + cap.string() + "\" \"" + cra.string() + "\" --interest \"" + semantic +
                 "\" --interest-side crafted --output \"" + sem_out.string() + "\"");
    EXPECT_EQ(sem_run.exit_code, 0) << sem_run.log;
    const auto sem_checks = write_text(
        dir / "interest_sem_checks.json",
        check_json(
            R"([
              {"domain": "module_image", "classification": "candidate", "section": ".data", "interest": true}
            ])",
            R"([
              {"domain": "infrastructure", "interest": true}
            ])",
            R"({
              "interest.report_level": "semantic",
              "interest.detail_state": "sufficient",
              "interest.matched": 1
            })"));
    const auto sem_check = run_checker(sem_out, sem_checks);
    EXPECT_EQ(sem_check.exit_code, 0) << sem_check.log;

    const auto empty = write_text(dir / "empty_report.json", interest::kEmptyReport);
    const auto empty_out = dir / "interest_empty.json";
    const auto empty_run =
        run_tool("\"" + cap.string() + "\" \"" + cra.string() + "\" --interest \"" + empty +
                 "\" --interest-side crafted --output \"" + empty_out.string() + "\"");
    EXPECT_EQ(empty_run.exit_code, 0) << empty_run.log;
    const auto empty_checks = write_text(
        dir / "interest_empty_checks.json",
        check_json("[]",
                   R"([
                     {"interest": true}
                   ])",
                   R"({
                     "interest.detail_state": "insufficient",
                     "interest.matched": 0
                   })"));
    const auto empty_check = run_checker(empty_out, empty_checks);
    EXPECT_EQ(empty_check.exit_code, 0) << empty_check.log;

    // refusals: side missing, report file missing
    const auto no_side =
        run_tool("\"" + cap.string() + "\" \"" + cra.string() + "\" --interest \"" + full + "\"");
    EXPECT_NE(no_side.exit_code, 0);
    EXPECT_NE(no_side.log.find("--interest-side"), std::string::npos) << no_side.log;
    const auto no_file = run_tool("\"" + cap.string() + "\" \"" + cra.string() +
                                  "\" --interest \"" + (dir / "absent.json").string() +
                                  "\" --interest-side crafted");
    EXPECT_NE(no_file.exit_code, 0);
    EXPECT_NE(no_file.log.find("interest report unreadable"), std::string::npos) << no_file.log;
}

// A crafted-side self-check failure (TEB Self != metadata) carries its range
// in the crafted side's coordinates with actual/expected spelled out, so
// --interest-side crafted annotates it - reading the checked address marks
// exactly that entry.
TEST(WorldDiff, InterestSelfCheckMatchesOnItsSide)
{
    const auto dir = fixture_dir();
    const auto cap = dir / "capture.snap";
    const auto cra = dir / "crafted_teb_defect.snap";
    ASSERT_NO_FATAL_FAILURE(write_fixture_world(cap, false, true, std::nullopt));
    ASSERT_NO_FATAL_FAILURE(write_fixture_world(cra, true, true, std::nullopt,
                                                /*break_teb_self=*/true));
    const char* report = R"({
      "events": {"counts": {"mem-read": 1}, "stub_calls": {}, "detail": [
        {"type": "mem-read", "seq": 1, "tid": 7, "pc": "0x18001000", "addr": "0x330000030",
         "size": 8, "value": "0x0"}
      ]}})";
    const auto interest = write_text(dir / "teb_report.json", report);
    const auto out = dir / "interest_teb.json";
    const auto run = run_tool("\"" + cap.string() + "\" \"" + cra.string() + "\" --interest \"" +
                              interest + "\" --interest-side crafted --output \"" + out.string() +
                              "\"");
    EXPECT_EQ(run.exit_code, 0) << run.log;
    const auto checks = write_text(
        dir / "teb_checks.json",
        check_json(
            R"json([
              {"domain": "infrastructure", "classification": "candidate",
               "target": "teb.self(crafted)", "interest": true,
               "actual": "0x0", "expected": "0x330000000"}
            ])json",
            R"([])",
            R"({"interest.matched": 1})"));
    const auto check = run_checker(out, checks);
    EXPECT_EQ(check.exit_code, 0) << check.log;
}
