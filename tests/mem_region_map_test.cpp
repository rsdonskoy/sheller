// Memory region map tests: PE32+ section-table parsing from synthetic
// image bytes, and the three-tier interval attribution (image section >
// headers pseudo-section > snapshot region), with unmapped addresses
// returning no attribution. The Ldr-walk case runs a real unicorn instance
// over a synthetic guest chain; the rest is pure standard library, both
// platforms.

#include "mem_region_map.h"

#include <gtest/gtest.h>

#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

namespace mem = sheller::engine::mem_region;

// Builds a minimal loaded-image header: DOS header, PE signature, file
// header (section_count sections), PE32+ optional header, section table.
// size_of_image lands in the optional header at +56 - the parse rejects
// zero (the [1, 4GB) legality bound).
std::vector<std::uint8_t> build_image(std::uint32_t size_of_headers,
                                      std::uint32_t section_alignment,
                                      const std::vector<std::array<std::uint8_t, 40>>& sections,
                                      std::uint32_t size_of_image = 0x4000)
{
    std::vector<std::uint8_t> image(size_of_headers, 0);
    image[0] = 'M';
    image[1] = 'Z';
    const auto pe_offset = static_cast<std::uint32_t>(0x40);
    std::memcpy(image.data() + 0x3C, &pe_offset, sizeof pe_offset);
    const std::uint32_t pe_signature = 0x00004550;
    std::memcpy(image.data() + pe_offset, &pe_signature, sizeof pe_signature);
    const std::uint16_t section_count = static_cast<std::uint16_t>(sections.size());
    std::memcpy(image.data() + pe_offset + 6, &section_count, sizeof section_count);
    const std::uint16_t optional_size = 240;
    std::memcpy(image.data() + pe_offset + 20, &optional_size, sizeof optional_size);
    const auto optional = pe_offset + 24;
    const std::uint16_t magic = 0x20B;
    std::memcpy(image.data() + optional, &magic, sizeof magic);
    std::memcpy(image.data() + optional + 32, &section_alignment, sizeof section_alignment);
    std::memcpy(image.data() + optional + 56, &size_of_image, sizeof size_of_image);
    std::memcpy(image.data() + optional + 60, &size_of_headers, sizeof size_of_headers);
    auto table = optional + optional_size;
    for (const auto& section : sections) {
        image.resize(table + section.size() > image.size() ? table + section.size() : image.size());
        std::memcpy(image.data() + table, section.data(), section.size());
        table += static_cast<std::uint32_t>(section.size());
    }
    image.resize(size_of_headers);
    return image;
}

std::array<std::uint8_t, 40> section_entry(const char* name, std::uint32_t virtual_size,
                                           std::uint32_t virtual_address,
                                           std::uint32_t characteristics)
{
    std::array<std::uint8_t, 40> entry{};
    std::memcpy(entry.data(), name, std::strlen(name) < 8 ? std::strlen(name) : 8);
    std::memcpy(entry.data() + 8, &virtual_size, sizeof virtual_size);
    std::memcpy(entry.data() + 12, &virtual_address, sizeof virtual_address);
    std::memcpy(entry.data() + 36, &characteristics, sizeof characteristics);
    return entry;
}

std::vector<std::uint8_t> synthetic_two_section_image()
{
    return build_image(0x200, 0x1000,
                       {section_entry(".text", 0x800, 0x1000, 0x60000020),
                        section_entry(".data", 0x40, 0x3000, 0xC0000040)});
}

mem::ModuleRecord synthetic_module(const char* name, std::uint64_t base, std::uint64_t size)
{
    mem::ModuleRecord module;
    module.base = base;
    module.size = size;
    std::memcpy(module.name.data(), name, std::strlen(name) + 1);
    return module;
}

TEST(PeParse, SyntheticImageSectionTable)
{
    const auto image = synthetic_two_section_image();
    mem::ImageLayout layout;
    ASSERT_EQ(mem::parse_section_table(image.data(), image.size(), layout),
              mem::PeParseError::kNone);
    EXPECT_EQ(layout.size_of_headers, 0x200U);
    ASSERT_EQ(layout.sections.size(), 2U);
    EXPECT_EQ(layout.sections[0].rva, 0x1000U);
    EXPECT_EQ(layout.sections[0].span, 0x1000U); // 0x800 aligned up to 0x1000
    EXPECT_EQ(layout.sections[0].characteristics, 0x60000020U);
    EXPECT_STREQ(layout.sections[0].name.data(), ".text");
    EXPECT_EQ(layout.sections[1].rva, 0x3000U);
    EXPECT_EQ(layout.sections[1].span, 0x1000U); // 0x40 aligned up to 0x1000
    EXPECT_STREQ(layout.sections[1].name.data(), ".data");
}

TEST(PeParse, BadInputsReportErrors)
{
    const auto image = synthetic_two_section_image();
    mem::ImageLayout layout;

    // no MZ
    auto bad = image;
    bad[0] = 'X';
    EXPECT_EQ(mem::parse_section_table(bad.data(), bad.size(), layout), mem::PeParseError::kBadDos);

    // broken PE signature
    bad = image;
    bad[0x40] = 'X';
    EXPECT_EQ(mem::parse_section_table(bad.data(), bad.size(), layout), mem::PeParseError::kBadPe);

    // not PE32+
    bad = image;
    const std::uint16_t magic = 0x10B;
    std::memcpy(bad.data() + 0x40 + 24, &magic, sizeof magic);
    EXPECT_EQ(mem::parse_section_table(bad.data(), bad.size(), layout),
              mem::PeParseError::kNotPe32Plus);

    // section table truncated
    bad = image;
    bad.resize(0x180);
    EXPECT_EQ(mem::parse_section_table(bad.data(), bad.size(), layout),
              mem::PeParseError::kTruncated);
}

TEST(MemRegionMap, ThreeTierAttribution)
{
    auto module = synthetic_module("test.dll", 0x400000, 0x4000);
    mem::ModuleImage image;
    image.module = module;
    image.header_bytes = synthetic_two_section_image();

    // One image region covering the module, one private heap, one mapped page.
    const std::vector<mem::RegionRecord> regions{
        {0x400000, 0x10000, 0x20, 0x1000000}, // image region (RWX, MEM_IMAGE)
        {0x10000000, 0x10000, 0x4, 0x20000},  // private (RW, MEM_PRIVATE)
        {0x20000000, 0x1000, 0x2, 0x40000},   // mapped (R, MEM_MAPPED)
    };
    const mem::MemRegionMap map({&image, 1}, regions);

    // image section wins over the containing image region
    const auto text = map.query(0x401234);
    ASSERT_TRUE(text.has_value());
    EXPECT_EQ(text->kind, mem::AttributionKind::kImageSection);
    EXPECT_EQ(text->module_index, 0U);
    EXPECT_EQ(text->module_name, "test.dll");
    EXPECT_EQ(text->section_name, ".text");
    EXPECT_EQ(text->region_index, 0U); // owning region still reported

    // header pseudo-section
    const auto headers = map.query(0x400010);
    ASSERT_TRUE(headers.has_value());
    EXPECT_EQ(headers->kind, mem::AttributionKind::kImageHeaders);
    EXPECT_EQ(headers->section_name, "headers");

    // alignment gap inside the image but outside any section: region wins
    const auto gap = map.query(0x402500);
    ASSERT_TRUE(gap.has_value());
    EXPECT_EQ(gap->kind, mem::AttributionKind::kRegion);
    EXPECT_EQ(gap->type, 0x1000000U); // MEM_IMAGE

    // beyond SizeOfImage but inside the image region: region wins
    const auto beyond = map.query(0x405000);
    ASSERT_TRUE(beyond.has_value());
    EXPECT_EQ(beyond->kind, mem::AttributionKind::kRegion);

    // private and mapped regions
    const auto priv = map.query(0x10000010);
    ASSERT_TRUE(priv.has_value());
    EXPECT_EQ(priv->kind, mem::AttributionKind::kRegion);
    EXPECT_EQ(priv->type, 0x20000U);
    EXPECT_EQ(priv->protection, 0x4U);
    const auto data = map.query(0x403000);
    ASSERT_TRUE(data.has_value());
    EXPECT_EQ(data->kind, mem::AttributionKind::kImageSection);
    EXPECT_EQ(data->section_name, ".data");
    const auto mapped = map.query(0x20000010);
    ASSERT_TRUE(mapped.has_value());
    EXPECT_EQ(mapped->type, 0x40000U);

    // unmapped: no attribution
    EXPECT_FALSE(map.query(0x30000000).has_value());
}

TEST(MemRegionMap, ProtectionFragmentInSectionSpanKeepsSectionAttribution)
{
    // The packed shape at unit scale: a large section (UPX1, span 0x28000)
    // whose RWX tail page exists as a protection-split region fragment.
    // Adjudication is hierarchical - the section refines the fragment
    // whatever the span sizes - so the query must answer the section, never
    // the 0x1000 fragment. The old smallest-span-wins rule answers this
    // wrong: this test is red under that semantics.
    mem::ModuleImage image;
    image.module = synthetic_module("packed.exe", 0x400000, 0x44000);
    image.header_bytes = build_image(0x200, 0x1000,
                                     {section_entry("UPX0", 0x1000, 0x1000, 0x60000020),
                                      section_entry("UPX1", 0x27890, 0x2000, 0x60000020)},
                                     0x44000);
    const std::vector<mem::RegionRecord> regions{
        {0x400000, 0x44000, 0x20, sheller::engine::kMemImage}, // image region (RWX, MEM_IMAGE)
    };
    mem::MemRegionMap map({&image, 1}, regions);
    map.apply_protection(0x429000, 0x1000, 0x40); // the RWX stub page, UPX1's tail

    // The stub page answers as UPX1 - kind, module and wire slots all
    // section-level (not the fragment's (0xFF00, 0xFFFF)).
    const auto stub = map.query(0x429800);
    ASSERT_TRUE(stub.has_value());
    EXPECT_EQ(stub->kind, mem::AttributionKind::kImageSection);
    EXPECT_EQ(stub->module_index, 0U);
    EXPECT_EQ(stub->module_name, "packed.exe");
    EXPECT_EQ(stub->section_name, "UPX1");
    const auto stub_slots = mem::xfer_payload_slots(stub->identity);
    EXPECT_EQ(stub_slots.first, 0U);
    EXPECT_EQ(stub_slots.second, 2U);

    // The OEP lands in the earlier section: the packed OEP edge is a rule-1
    // firing (sample image section -> sample image section), from-slots
    // render packed.exe!UPX1 -> packed.exe!UPX0.
    const auto oep = map.query(0x401100);
    ASSERT_TRUE(oep.has_value());
    EXPECT_EQ(oep->kind, mem::AttributionKind::kImageSection);
    EXPECT_EQ(oep->section_name, "UPX0");
    const auto oep_slots = mem::xfer_payload_slots(oep->identity);
    EXPECT_EQ(oep_slots.first, 0U);
    EXPECT_EQ(oep_slots.second, 1U);
    const auto stub_territory = mem::xfer_territory(*stub, 0);
    const auto oep_territory = mem::xfer_territory(*oep, 0);
    EXPECT_EQ(stub_territory, mem::XferTerritory::kSampleImage);
    EXPECT_EQ(oep_territory, mem::XferTerritory::kSampleImage);
    EXPECT_TRUE(mem::is_xfer_transition(stub->identity, oep->identity));
    EXPECT_TRUE(mem::is_xfer_edge(stub_territory, oep_territory));
}

TEST(MemRegionMap, RegionModuleOwnershipTruthTable)
{
    // Module membership truth table: overlap (image alignment gap inside
    // the span), adjacency (companion page abutting either span end - the
    // ntdll forwarder-thunk page is the real-world shape), orphan (neither;
    // fixture-only - no executed real corpus region exists yet). Ownership
    // decides the xfer territory: module-owned regions ride their module,
    // orphans are sample-side.
    std::vector<mem::ModuleImage> images;
    mem::ModuleImage sample_image;
    sample_image.module = synthetic_module("packed.exe", 0x400000, 0x4000);
    mem::ModuleImage ntdll_image;
    ntdll_image.module = synthetic_module("ntdll.dll", 0x7FF800000000ULL, 0x200000);
    images.push_back(sample_image);
    images.push_back(ntdll_image);

    const std::vector<mem::RegionRecord> regions{
        {0x402000, 0x1000, 0x20, sheller::engine::kMemImage},       // gap inside the sample span
        {0x7FF800100000, 0x1000, 0x20, sheller::engine::kMemImage}, // gap inside ntdll
        {0x7FF800200000, 0x1000, 0x20, sheller::engine::kMemImage}, // end-adjacent companion page
        {0x7FF7FFFFF000, 0x1000, 0x20, sheller::engine::kMemImage}, // base-abutting companion page
        {0x5000000, 0x1000, 0x20, sheller::engine::kMemPrivate}, // orphan: no overlap, no adjacency
    };
    const mem::MemRegionMap map(images, regions);

    const auto owner_at = [&](const std::uint64_t address) {
        const auto attribution = map.query(address);
        EXPECT_TRUE(attribution.has_value()) << std::hex << address;
        EXPECT_EQ(attribution->kind, mem::AttributionKind::kRegion) << std::hex << address;
        return attribution->module_owner;
    };
    EXPECT_EQ(owner_at(0x402000), 0U);
    EXPECT_EQ(owner_at(0x7FF800100000), 1U);
    EXPECT_EQ(owner_at(0x7FF800200000), 1U);
    EXPECT_EQ(owner_at(0x7FF7FFFFF000), 1U);
    EXPECT_EQ(owner_at(0x5000000), mem::kNoModuleIndex);

    const auto gap = map.query(0x402000);
    ASSERT_TRUE(gap.has_value());
    EXPECT_EQ(mem::xfer_territory(*gap, 0), mem::XferTerritory::kSampleImage);
    const auto forwarder = map.query(0x7FF800200000);
    ASSERT_TRUE(forwarder.has_value());
    EXPECT_EQ(mem::xfer_territory(*forwarder, 0), mem::XferTerritory::kOther);
    const auto orphan = map.query(0x5000000);
    ASSERT_TRUE(orphan.has_value());
    EXPECT_EQ(mem::xfer_territory(*orphan, 0), mem::XferTerritory::kSampleAlloc);
}

TEST(MemRegionMap, XferTransitionSemantics)
{
    // Same-identity steps stay silent; any identity change is a transition.
    // The key is the stable value pair, not the positional interval index.
    const mem::AttributionIdentity section_a{mem::AttributionKind::kImageSection, 0, 1};
    const mem::AttributionIdentity section_b{mem::AttributionKind::kImageSection, 0, 2};
    const mem::AttributionIdentity headers{mem::AttributionKind::kImageHeaders, 0, 0};
    const mem::AttributionIdentity region{mem::AttributionKind::kRegion, 3,
                                          mem::kRegionSentinelUnclassified};
    EXPECT_FALSE(mem::is_xfer_transition(section_a, section_a));
    EXPECT_TRUE(mem::is_xfer_transition(section_a, section_b)); // cross-section
    EXPECT_TRUE(mem::is_xfer_transition(section_a, headers));   // into the headers
    EXPECT_TRUE(mem::is_xfer_transition(section_a, region));    // into a region
    const mem::AttributionIdentity data{mem::AttributionKind::kRegion, 7,
                                        mem::kRegionSentinelRuntimeBase + 2};
    const mem::AttributionIdentity exec{mem::AttributionKind::kRegion, 7,
                                        mem::kRegionSentinelRuntimeBase + 1};
    const mem::AttributionIdentity other_alloc{mem::AttributionKind::kRegion, 8,
                                               mem::kRegionSentinelRuntimeBase + 2};
    EXPECT_TRUE(mem::is_xfer_transition(data, exec));        // class flip: exactly one event
    EXPECT_TRUE(mem::is_xfer_transition(data, other_alloc)); // allocation boundary
}

TEST(XferEdgeRules, TerritoryTruthTable)
{
    // The territory classification truth table, in adjudication order:
    // sample-issued registration, runtime registration fact (infrastructure),
    // module ownership, orphan. The image layer only ever consults the
    // module index.
    const std::size_t sample = 0;
    const std::size_t system = 1;
    const auto image_attribution = [](const mem::AttributionKind kind, const std::size_t index) {
        mem::MemAttribution attribution;
        attribution.kind = kind;
        attribution.module_index = index;
        return attribution;
    };
    const auto region_attribution = [](const bool runtime_registered, const bool runtime_event,
                                       const std::size_t module_owner) {
        mem::MemAttribution attribution;
        attribution.kind = mem::AttributionKind::kRegion;
        attribution.module_index = mem::kNoModuleIndex;
        attribution.runtime_registered = runtime_registered;
        attribution.runtime_event = runtime_event;
        attribution.module_owner = module_owner;
        return attribution;
    };

    EXPECT_EQ(
        mem::xfer_territory(image_attribution(mem::AttributionKind::kImageSection, sample), sample),
        mem::XferTerritory::kSampleImage);
    EXPECT_EQ(
        mem::xfer_territory(image_attribution(mem::AttributionKind::kImageHeaders, sample), sample),
        mem::XferTerritory::kSampleImage);
    EXPECT_EQ(
        mem::xfer_territory(image_attribution(mem::AttributionKind::kImageSection, system), sample),
        mem::XferTerritory::kOther);

    EXPECT_EQ(mem::xfer_territory(region_attribution(true, true, mem::kNoModuleIndex), sample),
              mem::XferTerritory::kSampleAlloc); // sample-issued allocation
    EXPECT_EQ(mem::xfer_territory(region_attribution(false, true, mem::kNoModuleIndex), sample),
              mem::XferTerritory::kOther); // system-issued: infrastructure
    EXPECT_EQ(mem::xfer_territory(region_attribution(false, true, sample), sample),
              mem::XferTerritory::kOther); // infrastructure short-circuits ownership
    EXPECT_EQ(mem::xfer_territory(region_attribution(false, false, mem::kNoModuleIndex), sample),
              mem::XferTerritory::kSampleAlloc); // orphan captured region
    EXPECT_EQ(mem::xfer_territory(region_attribution(false, false, sample), sample),
              mem::XferTerritory::kSampleImage); // sample span gap
    EXPECT_EQ(mem::xfer_territory(region_attribution(false, false, system), sample),
              mem::XferTerritory::kOther); // system companion page

    // Degenerate unknown sample module: no image attribution can be sample
    // territory (the all-silent face); the orphan branch never consults the
    // sample index.
    EXPECT_EQ(mem::xfer_territory(image_attribution(mem::AttributionKind::kImageSection, sample),
                                  mem::kNoModuleIndex),
              mem::XferTerritory::kOther);
    EXPECT_EQ(mem::xfer_territory(region_attribution(false, false, mem::kNoModuleIndex),
                                  mem::kNoModuleIndex),
              mem::XferTerritory::kSampleAlloc);
}

TEST(XferEdgeRules, EdgeTruthTableExhaustive)
{
    // The narrowed event face, exhaustive over the 3x3 territory pairs: the
    // three sample-territory edges fire, all six others stay silent.
    const mem::XferTerritory territories[] = {mem::XferTerritory::kOther,
                                              mem::XferTerritory::kSampleImage,
                                              mem::XferTerritory::kSampleAlloc};
    for (const auto from : territories) {
        for (const auto to : territories) {
            const bool fires =
                (from == mem::XferTerritory::kSampleImage && to != mem::XferTerritory::kOther) ||
                (from == mem::XferTerritory::kSampleAlloc &&
                 to == mem::XferTerritory::kSampleImage);
            EXPECT_EQ(mem::is_xfer_edge(from, to), fires)
                << static_cast<int>(from) << " -> " << static_cast<int>(to);
        }
    }
    // The three live edges, named.
    EXPECT_TRUE(
        mem::is_xfer_edge(mem::XferTerritory::kSampleImage, mem::XferTerritory::kSampleImage));
    EXPECT_TRUE(
        mem::is_xfer_edge(mem::XferTerritory::kSampleImage, mem::XferTerritory::kSampleAlloc));
    EXPECT_TRUE(
        mem::is_xfer_edge(mem::XferTerritory::kSampleAlloc, mem::XferTerritory::kSampleImage));
    // The silent faces the narrowing chose: system crossings, allocation-to-
    // allocation hops, infrastructure entries.
    EXPECT_FALSE(mem::is_xfer_edge(mem::XferTerritory::kSampleImage, mem::XferTerritory::kOther));
    EXPECT_FALSE(
        mem::is_xfer_edge(mem::XferTerritory::kSampleAlloc, mem::XferTerritory::kSampleAlloc));
    EXPECT_FALSE(mem::is_xfer_edge(mem::XferTerritory::kSampleAlloc, mem::XferTerritory::kOther));
    EXPECT_FALSE(mem::is_xfer_edge(mem::XferTerritory::kOther, mem::XferTerritory::kSampleImage));
    EXPECT_FALSE(mem::is_xfer_edge(mem::XferTerritory::kOther, mem::XferTerritory::kSampleAlloc));
    EXPECT_FALSE(mem::is_xfer_edge(mem::XferTerritory::kOther, mem::XferTerritory::kOther));
}

TEST(RegionClass, PureFunctionClassification)
{
    // The spec's five families: private-exec, private-data, mapped, the
    // image gap (never classified from its execute bits), and the unknown
    // inputs (foreign types, zero protection).
    EXPECT_EQ(mem::region_class(0x40, sheller::engine::kMemPrivate),
              mem::RegionClass::kPrivateExec);
    EXPECT_EQ(mem::region_class(0x10, sheller::engine::kMemPrivate),
              mem::RegionClass::kPrivateExec);
    EXPECT_EQ(mem::region_class(0x04, sheller::engine::kMemPrivate),
              mem::RegionClass::kPrivateData);
    EXPECT_EQ(mem::region_class(0x02, sheller::engine::kMemMapped), mem::RegionClass::kMapped);
    EXPECT_EQ(mem::region_class(0x40, sheller::engine::kMemImage), mem::RegionClass::kUnclassified);
    EXPECT_EQ(mem::region_class(0x40, 0xDEADU), mem::RegionClass::kUnclassified);
    EXPECT_EQ(mem::region_class(0, sheller::engine::kMemPrivate), mem::RegionClass::kUnclassified);
    // Guard/nocache modifiers ride above the base byte and do not hide it.
    EXPECT_EQ(mem::region_class(0x40 | 0x100, sheller::engine::kMemPrivate),
              mem::RegionClass::kPrivateExec);
}

TEST(RegionClass, SentinelEncoding)
{
    // 0xFF0x snapshot tier, 0xFF1x runtime tier, same class = same slot;
    // unclassified falls back to 0xFF00 in both tiers.
    EXPECT_EQ(mem::region_class_sentinel(mem::RegionClass::kPrivateExec, false), 0xFF01);
    EXPECT_EQ(mem::region_class_sentinel(mem::RegionClass::kPrivateData, false), 0xFF02);
    EXPECT_EQ(mem::region_class_sentinel(mem::RegionClass::kMapped, false), 0xFF03);
    EXPECT_EQ(mem::region_class_sentinel(mem::RegionClass::kPrivateExec, true), 0xFF11);
    EXPECT_EQ(mem::region_class_sentinel(mem::RegionClass::kPrivateData, true), 0xFF12);
    EXPECT_EQ(mem::region_class_sentinel(mem::RegionClass::kMapped, true), 0xFF13);
    EXPECT_EQ(mem::region_class_sentinel(mem::RegionClass::kUnclassified, false), 0xFF00);
    EXPECT_EQ(mem::region_class_sentinel(mem::RegionClass::kUnclassified, true), 0xFF00);
    // The runtime tier is the signal layer's sample-territory marker.
    EXPECT_TRUE(mem::is_runtime_region_sentinel(0xFF11));
    EXPECT_TRUE(mem::is_runtime_region_sentinel(0xFF13));
    EXPECT_FALSE(mem::is_runtime_region_sentinel(0xFF01));
    EXPECT_FALSE(mem::is_runtime_region_sentinel(0xFF00));
    EXPECT_FALSE(mem::is_runtime_region_sentinel(0xFFFF));
}

TEST(RegionClass, PayloadSlots)
{
    const mem::AttributionIdentity section{mem::AttributionKind::kImageSection, 2, 5};
    const auto image_slots = mem::xfer_payload_slots(section);
    EXPECT_EQ(image_slots.first, 2U);
    EXPECT_EQ(image_slots.second, 5U);
    const mem::AttributionIdentity region{mem::AttributionKind::kRegion, 9, 0xFF12};
    const auto region_slots = mem::xfer_payload_slots(region);
    EXPECT_EQ(region_slots.first, 0xFF12U);  // class sentinel in the module slot
    EXPECT_EQ(region_slots.second, 0xFFFFU); // no section refinement
}

TEST(MemRegionMap, LdrWalkFoldsBothNameEncodings)
{
    // Current containers carry Ldr names as UTF-16 (Length = bytes); worlds
    // built before the shared-convention change carried narrow ASCII
    // (Length = the character count). The content sniff must keep reading
    // both in one walk - the legacy shape never has the zero high byte the
    // wide shape carries on every other byte.
    uc_engine* uc = nullptr;
    ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &uc), UC_ERR_OK);
    uc_mem_map(uc, 0x500000, 0x3000, UC_PROT_ALL);
    const auto put64 = [&](std::uint64_t at, std::uint64_t value) {
        uc_mem_write(uc, 0x500000 + at, &value, sizeof value);
    };
    const auto put32 = [&](std::uint64_t at, std::uint32_t value) {
        uc_mem_write(uc, 0x500000 + at, &value, sizeof value);
    };
    const auto put16 = [&](std::uint64_t at, std::uint16_t value) {
        uc_mem_write(uc, 0x500000 + at, &value, sizeof value);
    };
    // TEB@+0x000 (PEB at +0x60), PEB@+0x100 (Ldr at +0x18), Ldr@+0x200
    // (InLoadOrder head at +0x10); two entries at +0x300 and +0x400.
    put64(0x060, 0x500100);
    put64(0x118, 0x500200);
    put64(0x210, 0x500300); // head.Flink -> entry 0
    // entry 0: legacy narrow "ntdll.dll" (Length = 9 characters)
    put64(0x300, 0x500400); // Flink -> entry 1
    put64(0x308, 0x500210); // Blink -> head
    put64(0x330, 0x501000); // DllBase
    put32(0x340, 0x1000);   // SizeOfImage
    put16(0x358, 9);        // BaseDllName.Length (narrow characters)
    put64(0x360, 0x500380); // BaseDllName.Buffer
    const char narrow[] = "ntdll.dll";
    uc_mem_write(uc, 0x500380, narrow, sizeof narrow);
    // entry 1: UTF-16 "kernel32.dll" (Length = 24 bytes), closes the chain
    put64(0x400, 0x500210); // Flink -> head
    put64(0x408, 0x500300); // Blink -> entry 0
    put64(0x430, 0x502000); // DllBase
    put32(0x440, 0x1000);   // SizeOfImage
    put16(0x458, 24);       // BaseDllName.Length (bytes)
    put64(0x460, 0x500480); // BaseDllName.Buffer
    const char16_t wide[] = u"kernel32.dll";
    uc_mem_write(uc, 0x500480, wide, sizeof wide);
    std::uint64_t gs_base = 0x500000;
    uc_reg_write(uc, UC_X86_REG_GS_BASE, &gs_base);

    const auto images = mem::enumerate_guest_images(uc);
    ASSERT_EQ(images.size(), 2U);
    EXPECT_STREQ(images[0].module.name.data(), "ntdll.dll");
    EXPECT_EQ(images[0].module.base, 0x501000ULL);
    EXPECT_STREQ(images[1].module.name.data(), "kernel32.dll");
    EXPECT_EQ(images[1].module.base, 0x502000ULL);
    uc_close(uc);
}

namespace evolution {

// Two fresh maps run the same register/protect sequence; every probe-grid
// query must agree on the full attribution value.
void run_sequence(mem::MemRegionMap& map)
{
    map.register_region(0x7F0000000000ULL, 0x10000, 0x04, sheller::engine::kMemPrivate, true);
    map.register_region(0x7F0000100000ULL, 0x4000, 0x20, sheller::engine::kMemPrivate, true);
    map.apply_protection(0x7F0000001000ULL, 0x2000, 0x20);
    map.apply_protection(0x7F0000100000ULL, 0x1000, 0x04);
}

::testing::AssertionResult attributions_equal(const mem::MemAttribution& a,
                                              const mem::MemAttribution& b)
{
    if (a.kind == b.kind && a.region_index == b.region_index && a.protection == b.protection &&
        a.type == b.type && a.identity == b.identity &&
        a.runtime_registered == b.runtime_registered && a.origin == b.origin) {
        return ::testing::AssertionSuccess();
    }
    return ::testing::AssertionFailure()
           << "kind=" << static_cast<int>(a.kind) << "/" << static_cast<int>(b.kind)
           << " region=" << a.region_index << "/" << b.region_index << " prot=" << std::hex
           << a.protection << "/" << b.protection << std::dec << " origin=" << a.origin << "/"
           << b.origin;
}

} // namespace evolution

TEST(MemRegionMapEvolution, RegisteredRegionOwnsItsAddresses)
{
    mem::MemRegionMap map({}, {});
    map.register_region(0x7F0000000000ULL, 0x10000, 0x40, sheller::engine::kMemPrivate, true);
    const auto landing = map.query(0x7F0000008000ULL);
    ASSERT_TRUE(landing.has_value());
    EXPECT_EQ(landing->kind, mem::AttributionKind::kRegion);
    EXPECT_EQ(landing->protection, 0x40U);
    EXPECT_EQ(landing->type, sheller::engine::kMemPrivate);
    EXPECT_TRUE(landing->runtime_registered);
    EXPECT_EQ(landing->origin, 0U);
    // The runtime private-exec landing rides the runtime sentinel tier.
    EXPECT_EQ(landing->identity.secondary, 0xFF11U);
    const auto slots = mem::xfer_payload_slots(landing->identity);
    EXPECT_EQ(slots.first, 0xFF11U);
    EXPECT_EQ(slots.second, 0xFFFFU);

    // A second allocation takes the next origin; outside stays unmapped.
    map.register_region(0x7F0000100000ULL, 0x1000, 0x04, sheller::engine::kMemPrivate, true);
    const auto second = map.query(0x7F0000100000ULL);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->origin, 1U);
    EXPECT_EQ(second->identity.primary, 1U);
    EXPECT_FALSE(map.query(0x7F0000200000ULL).has_value());
}

TEST(MemRegionMapEvolution, ProtectionSplitSplitsQueryResponses)
{
    mem::MemRegionMap map({}, {});
    const std::uint64_t base = 0x7F0000000000ULL;
    map.register_region(base, 0x4000, 0x04, sheller::engine::kMemPrivate, true); // four RW pages
    map.apply_protection(base + 0x1000, 0x2000, 0x20); // middle two become RX

    const auto head = map.query(base);
    const auto mid = map.query(base + 0x1000);
    const auto tail = map.query(base + 0x3000);
    ASSERT_TRUE(head.has_value());
    ASSERT_TRUE(mid.has_value());
    ASSERT_TRUE(tail.has_value());

    // The middle answers the carved record through region(), the MBI
    // source: new protection on the split extent. Head and tail keep the
    // original record - the original answer (records are immutable, only
    // the covered part carves).
    EXPECT_EQ(head->region_index, 0U);
    EXPECT_EQ(tail->region_index, 0U);
    EXPECT_NE(mid->region_index, 0U);
    EXPECT_EQ(map.region(head->region_index).base, base);
    EXPECT_EQ(map.region(head->region_index).size, 0x4000U);
    EXPECT_EQ(map.region(head->region_index).protection, 0x04U);
    EXPECT_EQ(map.region(mid->region_index).base, base + 0x1000);
    EXPECT_EQ(map.region(mid->region_index).size, 0x2000U);
    EXPECT_EQ(map.region(mid->region_index).protection, 0x20U);
    // Attribution-level values agree with the records.
    EXPECT_EQ(head->protection, 0x04U);
    EXPECT_EQ(mid->protection, 0x20U);
    EXPECT_EQ(tail->protection, 0x04U);
}

TEST(MemRegionMapEvolution, CarvedSegmentsInheritOriginAndFlag)
{
    mem::MemRegionMap map({}, {});
    const std::uint64_t base = 0x7F0000000000ULL;
    map.register_region(base, 0x4000, 0x04, sheller::engine::kMemPrivate, true);
    map.apply_protection(base + 0x1000, 0x2000, 0x20);
    // Every child of one allocation shares its origin and runtime flag;
    // only the protection differs.
    for (const std::uint64_t offset :
         {std::uint64_t{0}, std::uint64_t{0x1000}, std::uint64_t{0x3000}}) {
        const auto part = map.query(base + offset);
        ASSERT_TRUE(part.has_value());
        EXPECT_EQ(part->origin, 0U);
        EXPECT_TRUE(part->runtime_registered);
        EXPECT_EQ(part->identity.primary, 0U);
        EXPECT_EQ(part->type, sheller::engine::kMemPrivate);
    }
    // The middle segment flipped class (private-data -> private-exec), the
    // flanks did not.
    EXPECT_EQ(map.query(base)->identity.secondary, 0xFF12U);
    EXPECT_EQ(map.query(base + 0x1000)->identity.secondary, 0xFF11U);
}

TEST(MemRegionMapEvolution, ProtectAcrossAdjacentRegions)
{
    mem::MemRegionMap map({}, {});
    const std::uint64_t base_a = 0x7F0000000000ULL;
    const std::uint64_t base_b = base_a + 0x2000;
    map.register_region(base_a, 0x2000, 0x04, sheller::engine::kMemPrivate, true);
    map.register_region(base_b, 0x2000, 0x04, sheller::engine::kMemPrivate, true);
    map.apply_protection(base_a + 0x1000, 0x2000, 0x02); // last page of A + first of B

    // Each region's covered part carves its own record, keeping its origin.
    const auto tail_a = map.query(base_a + 0x1000);
    const auto head_b = map.query(base_b);
    const auto rest_b = map.query(base_b + 0x1000);
    ASSERT_TRUE(tail_a.has_value());
    ASSERT_TRUE(head_b.has_value());
    ASSERT_TRUE(rest_b.has_value());
    EXPECT_EQ(tail_a->protection, 0x02U);
    EXPECT_EQ(head_b->protection, 0x02U);
    EXPECT_EQ(rest_b->protection, 0x04U);
    EXPECT_NE(tail_a->region_index, head_b->region_index);
    EXPECT_EQ(tail_a->origin, 0U);
    EXPECT_EQ(head_b->origin, 1U);
    EXPECT_EQ(rest_b->region_index, 1U); // untouched part stays on B's record
    EXPECT_EQ(map.query(base_a)->region_index, 0U);
}

TEST(MemRegionMapEvolution, SameSequenceEvolvesIdentically)
{
    mem::MemRegionMap a({}, {});
    mem::MemRegionMap b({}, {});
    evolution::run_sequence(a);
    evolution::run_sequence(b);
    for (std::uint64_t offset = 0; offset < 0x110000; offset += 0x1000) {
        const auto qa = a.query(0x7F0000000000ULL + offset);
        const auto qb = b.query(0x7F0000000000ULL + offset);
        ASSERT_EQ(qa.has_value(), qb.has_value()) << std::hex << offset;
        if (qa.has_value() && qb.has_value()) {
            EXPECT_TRUE(evolution::attributions_equal(*qa, *qb)) << std::hex << offset;
        }
    }
}

TEST(MemRegionMapIdentity, IdentitySurvivesInsertResort)
{
    auto module = synthetic_module("test.dll", 0x400000, 0x4000);
    mem::ModuleImage image;
    image.module = module;
    image.header_bytes = synthetic_two_section_image();
    const std::vector<mem::RegionRecord> regions{
        {0x400000, 0x10000, 0x20, 0x1000000},
        {0x10000000, 0x10000, 0x4, 0x20000},
    };
    mem::MemRegionMap map({&image, 1}, regions);

    const auto before_section = map.query(0x401234);
    const auto before_region = map.query(0x10000010);
    ASSERT_TRUE(before_section.has_value());
    ASSERT_TRUE(before_region.has_value());

    // Registering an allocation re-sorts the interval vector; the image
    // section and the untouched snapshot region keep their identities.
    map.register_region(0x7F0000000000ULL, 0x1000, 0x40, sheller::engine::kMemPrivate, true);
    const auto after_section = map.query(0x401234);
    const auto after_region = map.query(0x10000010);
    ASSERT_TRUE(after_section.has_value());
    ASSERT_TRUE(after_region.has_value());
    EXPECT_EQ(after_section->identity, before_section->identity);
    EXPECT_EQ(after_region->identity, before_region->identity);

    // Splitting a different region changes nothing for the others either.
    map.apply_protection(0x10000000, 0x8000, 0x40);
    const auto post_section = map.query(0x401234);
    ASSERT_TRUE(post_section.has_value());
    EXPECT_EQ(post_section->identity, before_section->identity);
}

TEST(MemRegionMapIdentity, SameClassSplitKeepsIdentity)
{
    // The zero-event semantics: a protection update that does not change
    // the class (RW -> R) carves a record but keeps the identity key.
    mem::MemRegionMap map({}, {});
    const std::uint64_t base = 0x7F0000000000ULL;
    map.register_region(base, 0x2000, 0x04, sheller::engine::kMemPrivate, true);
    const auto before = map.query(base + 0x1000);
    ASSERT_TRUE(before.has_value());
    map.apply_protection(base + 0x1000, 0x1000, 0x02);
    const auto after = map.query(base + 0x1000);
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(after->protection, 0x02U);          // the fact did change...
    EXPECT_EQ(after->identity, before->identity); // ...the identity did not
    EXPECT_NE(after->region_index, before->region_index);
}

TEST(MemRegionMapIdentity, XferSequenceSemantics)
{
    // The engine-level event contract, replayed at identity level: block
    // landings walk a sequence of queries; transitions count xfer events.
    mem::MemRegionMap map({}, {});
    const std::uint64_t alloc_a = 0x7F0000000000ULL;
    const std::uint64_t alloc_b = 0x7F0000100000ULL;
    map.register_region(alloc_a, 0x4000, 0x04, sheller::engine::kMemPrivate, true); // private-data
    map.register_region(alloc_b, 0x1000, 0x04, sheller::engine::kMemPrivate, true);

    std::uint64_t transitions = 0;
    mem::AttributionIdentity current{};
    const auto land = [&](const std::uint64_t address) {
        const auto attribution = map.query(address);
        if (!attribution.has_value()) {
            return;
        }
        if (current != attribution->identity) {
            ++transitions;
            current = attribution->identity;
        }
    };

    // Allocate A, run inside it: entering is one event, staying is silent.
    land(alloc_a);
    EXPECT_EQ(transitions, 1U);
    land(alloc_a + 0x100);
    land(alloc_a + 0x200);
    EXPECT_EQ(transitions, 1U);

    // Protect A without a class change (RW -> R): continued execution in
    // the same region does not misreport.
    map.apply_protection(alloc_a, 0x4000, 0x02);
    land(alloc_a + 0x300);
    EXPECT_EQ(transitions, 1U);

    // Flip the middle two pages to RX (private-data -> private-exec):
    // entering the payload is exactly one event, running in it is silent.
    map.apply_protection(alloc_a + 0x1000, 0x2000, 0x20);
    land(alloc_a + 0x1000);
    EXPECT_EQ(transitions, 2U);
    land(alloc_a + 0x1800);
    land(alloc_a + 0x2000);
    EXPECT_EQ(transitions, 2U);
    // The payload landing rides the runtime private-exec sentinel.
    const auto payload = map.query(alloc_a + 0x1000);
    ASSERT_TRUE(payload.has_value());
    EXPECT_EQ(mem::xfer_payload_slots(payload->identity).first, 0xFF11U);

    // Jump into the other allocation: not missed, exactly one event.
    land(alloc_b);
    EXPECT_EQ(transitions, 3U);
}

TEST(PeParse, SizeOfImageLegalityBounds)
{
    mem::ImageLayout layout;

    // Zero SizeOfImage is illegal ([1, 4GB); the dword field makes the
    // upper bound structural - no u32 value reaches 4GB).
    auto bad = synthetic_two_section_image();
    const std::uint32_t zero = 0;
    std::memcpy(bad.data() + 0x40 + 24 + 56, &zero, sizeof zero);
    EXPECT_EQ(mem::parse_section_table(bad.data(), bad.size(), layout),
              mem::PeParseError::kBadImageSize);

    // A sane value parses and carries the optional-header value through.
    const auto good = synthetic_two_section_image();
    ASSERT_EQ(mem::parse_section_table(good.data(), good.size(), layout), mem::PeParseError::kNone);
    EXPECT_EQ(layout.size_of_image, 0x4000U);
}

namespace synth {

// The instoll payload's captured shape: 8 contiguous MEM_IMAGE regions,
// the head 64KB-aligned with a RO header page; the chain union is
// 0x402000 and equals the head image's SizeOfImage exactly.
constexpr std::uint64_t kChainBase = 0x7ff89b420000ULL;

std::vector<mem::UnknownImageCandidate>
instoll_shape_candidates(const std::vector<std::uint8_t>& header_page)
{
    return {
        {kChainBase, 0x1000, sheller::engine::kMemImage, header_page},
        {kChainBase + 0x1000, 0x1a9000, sheller::engine::kMemImage, {}},
        {kChainBase + 0x1aa000, 0x1fe000, sheller::engine::kMemImage, {}},
        {kChainBase + 0x3a8000, 0x4000, sheller::engine::kMemImage, {}},
        {kChainBase + 0x3ac000, 0x1000, sheller::engine::kMemImage, {}},
        {kChainBase + 0x3ad000, 0x4000, sheller::engine::kMemImage, {}},
        {kChainBase + 0x3b1000, 0x2000, sheller::engine::kMemImage, {}},
        {kChainBase + 0x3b3000, 0x4f000, sheller::engine::kMemImage, {}},
    };
}

mem::ModuleImage ldr_image(const char* name, std::uint64_t base, std::uint64_t size)
{
    mem::ModuleImage image;
    image.module = synthetic_module(name, base, size);
    image.header_bytes = synthetic_two_section_image();
    return image;
}

} // namespace synth

TEST(UnknownImageSynthesis, InstollShapeChainGetsSectionAttribution)
{
    // The anchor page parses to a payload-shaped layout: a large
    // executable .text spanning the RX member and a second section.
    auto header_page = build_image(0x200, 0x1000,
                                   {section_entry(".text", 0x1a8000, 0x1000, 0x60000020),
                                    section_entry(".rdata", 0x1000, 0x1aa000, 0x40000040)},
                                   0x402000);
    header_page.resize(0x1000, 0); // the captured header page
    const auto candidates = synth::instoll_shape_candidates(header_page);

    // One Ldr module well away from the chain: synthesized products must
    // append after it.
    auto ldr = synth::ldr_image("real.dll", 0x7ff89a000000ULL, 0x10000);
    const std::vector<mem::ModuleImage> ldr_images{ldr};
    const auto synthesized =
        mem::synthesize_unknown_images(ldr_images, {candidates.data(), candidates.size()});
    ASSERT_EQ(synthesized.size(), 1U);
    EXPECT_EQ(synthesized[0].module.base, synth::kChainBase);
    // min(SizeOfImage, chain union) with both at 0x402000
    EXPECT_EQ(synthesized[0].module.size, 0x402000U);
    EXPECT_TRUE(synthesized[0].module.synthesized);
    EXPECT_STREQ(synthesized[0].module.name.data(), "unknown-image-00007ff89b420000");
    // the anchor page rides along as the parse input
    EXPECT_EQ(synthesized[0].header_bytes, header_page);

    // Section-level attribution through the map: the deep RX address lands
    // in the synthesized image's .text, module index after the Ldr set.
    std::vector<mem::RegionRecord> regions;
    for (const auto& candidate : candidates) {
        regions.push_back({candidate.base, candidate.size, 0x20, candidate.type});
    }
    regions.push_back({0x7ff89a000000ULL, 0x10000, 0x20, sheller::engine::kMemImage});
    // rebuild with the full set: Ldr images + synthesized appended
    std::vector<mem::ModuleImage> all_images(ldr_images);
    all_images.insert(all_images.end(), synthesized.begin(), synthesized.end());
    const mem::MemRegionMap full_map(all_images, regions);

    const auto text = full_map.query(synth::kChainBase + 0x100000);
    ASSERT_TRUE(text.has_value());
    EXPECT_EQ(text->kind, mem::AttributionKind::kImageSection);
    EXPECT_EQ(text->module_index, 1U); // after the one Ldr module
    EXPECT_EQ(text->module_name, "unknown-image-00007ff89b420000");
    EXPECT_EQ(text->section_name, ".text");
    const auto rdata = full_map.query(synth::kChainBase + 0x1aa500);
    ASSERT_TRUE(rdata.has_value());
    EXPECT_EQ(rdata->kind, mem::AttributionKind::kImageSection);
    EXPECT_EQ(rdata->section_name, ".rdata");
    const auto headers = full_map.query(synth::kChainBase + 0x10);
    ASSERT_TRUE(headers.has_value());
    EXPECT_EQ(headers->kind, mem::AttributionKind::kImageHeaders);
    EXPECT_TRUE(full_map.module(1).synthesized);
    EXPECT_FALSE(full_map.module(0).synthesized);
}

TEST(UnknownImageSynthesis, TwoChainsSortAscendingByBase)
{
    // Two independent chains; input order reversed to prove the output
    // order is the base order. Each union (0x3000) is below SizeOfImage
    // (0x4000): the min() clamp takes the union.
    const std::uint64_t base_a = 0x7ff100010000ULL;
    const std::uint64_t base_b = 0x7ff100030000ULL;
    const auto headers_a =
        build_image(0x200, 0x1000, {section_entry(".text", 0x800, 0x1000, 0x60000020)});
    const auto headers_b =
        build_image(0x200, 0x1000, {section_entry(".text", 0x800, 0x1000, 0x60000020)});
    std::vector<mem::UnknownImageCandidate> candidates{
        {base_b, 0x1000, sheller::engine::kMemImage, headers_b},
        {base_b + 0x1000, 0x2000, sheller::engine::kMemImage, {}},
        {base_a, 0x1000, sheller::engine::kMemImage, headers_a},
        {base_a + 0x1000, 0x2000, sheller::engine::kMemImage, {}},
    };
    const auto synthesized = mem::synthesize_unknown_images({}, candidates);
    ASSERT_EQ(synthesized.size(), 2U);
    EXPECT_EQ(synthesized[0].module.base, base_a);
    EXPECT_EQ(synthesized[0].module.size, 0x3000U); // union, below SizeOfImage
    EXPECT_STREQ(synthesized[0].module.name.data(), "unknown-image-00007ff100010000");
    EXPECT_EQ(synthesized[1].module.base, base_b);
    EXPECT_STREQ(synthesized[1].module.name.data(), "unknown-image-00007ff100030000");
}

TEST(UnknownImageSynthesis, PartialLdrOverlapAbandonsWholeChain)
{
    // The chain's tail page runs into a real Ldr module's first page: the
    // whole chain is abandoned - no same-base pseudo-module, no synthesis
    // of the still-clean head page either.
    const std::uint64_t ldr_base = 0x7ff200000000ULL;
    const auto headers =
        build_image(0x200, 0x1000, {section_entry(".text", 0x800, 0x1000, 0x60000020)});
    std::vector<mem::UnknownImageCandidate> candidates{
        {ldr_base - 0x1000, 0x1000, sheller::engine::kMemImage, headers},
        {ldr_base, 0x1000, sheller::engine::kMemImage, {}},
    };
    const auto ldr = synth::ldr_image("real.dll", ldr_base, 0x10000);
    const auto synthesized = mem::synthesize_unknown_images({&ldr, 1}, candidates);
    EXPECT_TRUE(synthesized.empty());
}

TEST(UnknownImageSynthesis, IsolatedUnalignedFragmentStaysRegionLevel)
{
    // instoll's other endpoint: one MEM_IMAGE page, base not 64KB-aligned,
    // no chain, header bytes without MZ.
    const std::vector<std::uint8_t> garbage(0x1000, 0xCC);
    std::vector<mem::UnknownImageCandidate> candidates{
        {0x7ff89e0e7000ULL, 0x1000, sheller::engine::kMemImage, garbage},
    };
    EXPECT_TRUE(mem::synthesize_unknown_images({}, candidates).empty());

    // content-absent variant: the span is empty
    candidates[0].content = {};
    EXPECT_TRUE(mem::synthesize_unknown_images({}, candidates).empty());
}

TEST(UnknownImageSynthesis, UnparsableHeaderContentStaysRegionLevel)
{
    // An aligned anchor without a parseable image: no MZ, then MZ but a
    // truncated section table.
    const std::vector<std::uint8_t> garbage(0x1000, 0xCC);
    std::vector<mem::UnknownImageCandidate> candidates{
        {0x7ff100010000ULL, 0x1000, sheller::engine::kMemImage, garbage},
    };
    EXPECT_TRUE(mem::synthesize_unknown_images({}, candidates).empty());

    auto truncated =
        build_image(0x200, 0x1000, {section_entry(".text", 0x800, 0x1000, 0x60000020)});
    truncated.resize(0x150); // section table cut short
    candidates[0].content = truncated;
    EXPECT_TRUE(mem::synthesize_unknown_images({}, candidates).empty());
}

TEST(UnknownImageSynthesis, CapacitySelfClampsSkippingCandidates)
{
    // 62 Ldr modules leave room for 2 products; three synthesizable chains
    // shed their highest base, the Ldr set is never skipped.
    std::vector<mem::ModuleImage> ldr;
    for (std::size_t i = 0; i < 62; ++i) {
        ldr.push_back(synth::ldr_image("m62.dll", 0x100000ULL + i * 0x10000ULL, 0x1000));
    }
    const auto headers =
        build_image(0x200, 0x1000, {section_entry(".text", 0x800, 0x1000, 0x60000020)});
    std::vector<mem::UnknownImageCandidate> candidates;
    for (std::size_t n = 0; n < 3; ++n) {
        const std::uint64_t base = 0x7ff300010000ULL + n * 0x10000ULL;
        candidates.push_back({base, 0x1000, sheller::engine::kMemImage, headers});
        candidates.push_back({base + 0x1000, 0x1000, sheller::engine::kMemImage, {}});
    }
    const auto synthesized = mem::synthesize_unknown_images(ldr, candidates);
    ASSERT_EQ(synthesized.size(), 2U);
    EXPECT_EQ(synthesized[0].module.base, 0x7ff300010000ULL);
    EXPECT_EQ(synthesized[1].module.base, 0x7ff300020000ULL);
}

TEST(UnknownImageSynthesis, SameInputSameOutputBytes)
{
    auto header_page = build_image(
        0x200, 0x1000, {section_entry(".text", 0x1a8000, 0x1000, 0x60000020)}, 0x402000);
    header_page.resize(0x1000, 0);
    const auto candidates = synth::instoll_shape_candidates(header_page);
    const auto first = mem::synthesize_unknown_images({}, candidates);
    const auto second = mem::synthesize_unknown_images({}, candidates);
    ASSERT_EQ(first.size(), second.size());
    for (std::size_t i = 0; i < first.size(); ++i) {
        EXPECT_EQ(first[i].module.base, second[i].module.base);
        EXPECT_EQ(first[i].module.size, second[i].module.size);
        EXPECT_EQ(first[i].module.synthesized, second[i].module.synthesized);
        EXPECT_EQ(first[i].module.name, second[i].module.name);
        EXPECT_EQ(first[i].header_bytes, second[i].header_bytes);
    }
}

TEST(MemRegionMap, ModuleLookupByName)
{
    auto module = synthetic_module("ntdll.dll", 0x7ff800000000, 0x200000);
    mem::ModuleImage image;
    image.module = module;
    image.header_bytes = synthetic_two_section_image();
    const std::vector<mem::RegionRecord> no_regions;
    const mem::MemRegionMap map({&image, 1}, no_regions);

    EXPECT_EQ(map.module_index_by_name("ntdll.dll").value_or(1), 0U);
    EXPECT_FALSE(map.module_index_by_name("kernel32.dll").has_value());
}

} // namespace
