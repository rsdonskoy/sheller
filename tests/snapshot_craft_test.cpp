// Crafted-container tests: construction from a prepared guest, the record
// fidelity the replay route depends on, attribution visibility, determinism,
// the synthetic-world reattach tables and their exact-base predicate, the
// LdrLoadDll handle answer, and the machine-derived size bound.
//
// The suite runs on every host that has the generated synthetic modules; it
// needs no capture. `packed.exe` supplies the real-world sample shape (image
// above 4GB relocates to kLoaderSampleBase under the synthetic directory).

#include "container_size_bound.h"
#include "craft.h"
#include "intercept.h"
#include "loader_route.h"
#include "minimal_pe.h"
#include "rebuild_probe.h"
#include "test_temp.hpp"

#include "behavior_fact.h"
#include <sheller/snapshot.h>
#include <sheller/syscallrun.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <span>
#include <spanstream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

namespace fs = std::filesystem;
namespace engine = sheller::engine;
namespace snapshot = sheller::snapshot;

constexpr std::uint64_t kSampleMappedBase = 0x400000;
constexpr std::size_t kModulesInSynthDir = 8; // ...user32 joined later

fs::path synth_dir()
{
    return SYNTH_MODULE_DIR;
}

std::vector<std::uint8_t> read_file(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void write_file(const fs::path& path, const std::vector<std::uint8_t>& bytes)
{
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    ASSERT_TRUE(out) << path;
}

struct ParsedContainer {
    snapshot::Header header{};
    snapshot::Registers registers{};
    snapshot::Metadata metadata{};
    std::vector<snapshot::Region> regions;
    std::optional<snapshot::PendingModule> pending{};
    std::size_t bytes{};
};

ParsedContainer parse_container(const std::vector<std::uint8_t>& bytes)
{
    ParsedContainer parsed;
    std::ispanstream in{std::span<char>{
        reinterpret_cast<char*>(const_cast<std::uint8_t*>(bytes.data())), bytes.size()}};
    snapshot::Reader reader{in};
    const auto header = reader.read_header();
    EXPECT_TRUE(header.has_value());
    if (!header.has_value()) {
        return parsed;
    }
    parsed.header = *header;
    const auto registers = reader.read_registers();
    EXPECT_TRUE(registers.has_value());
    if (!registers.has_value()) {
        return parsed;
    }
    parsed.registers = *registers;
    const auto metadata = reader.read_metadata();
    EXPECT_TRUE(metadata.has_value());
    if (!metadata.has_value()) {
        return parsed;
    }
    parsed.metadata = *metadata;
    for (std::uint32_t i = 0; i < parsed.header.region_count; ++i) {
        auto region = reader.read_region();
        EXPECT_TRUE(region.has_value());
        if (!region.has_value()) {
            return parsed;
        }
        parsed.regions.push_back(std::move(*region));
    }
    if (parsed.header.version == snapshot::kVersionV2) {
        auto pending = reader.read_pending();
        EXPECT_TRUE(pending.has_value());
        if (pending.has_value()) {
            parsed.pending = std::move(*pending);
        }
    }
    parsed.bytes = bytes.size();
    return parsed;
}

std::vector<std::uint8_t> serialize_container(const ParsedContainer& parsed)
{
    std::ostringstream out;
    snapshot::Writer writer{out};
    // The writer counts regions as they are written; seed the header with a
    // zero count so finalize_region_count lands the actual number.
    auto header = parsed.header;
    header.region_count = 0;
    EXPECT_TRUE(writer.write_header(header).has_value());
    EXPECT_TRUE(writer.write_registers(parsed.registers).has_value());
    EXPECT_TRUE(writer.write_metadata(parsed.metadata).has_value());
    for (const auto& region : parsed.regions) {
        const auto* content =
            region.header.content == snapshot::kContentPresent ? region.content.data() : nullptr;
        EXPECT_TRUE(writer.write_region(region.header, content).has_value());
    }
    EXPECT_TRUE(writer.finalize_region_count().has_value());
    const auto text = out.str();
    return {text.begin(), text.end()};
}

std::vector<std::uint8_t> craft_packed()
{
    auto container = engine::craft_sample_container(SHELLER_SAMPLE_PACKED_PATH, false, synth_dir());
    EXPECT_TRUE(container.has_value());
    return container.has_value() ? *container : std::vector<std::uint8_t>{};
}

std::vector<std::uint8_t> read_virtual(const ParsedContainer& parsed, const std::uint64_t address,
                                       const std::size_t size)
{
    std::vector<std::uint8_t> out(size, std::uint8_t{0});
    for (const auto& region : parsed.regions) {
        const auto end = region.header.base_address + region.header.size;
        if (address < region.header.base_address || address + size > end) {
            continue;
        }
        if (region.header.content == snapshot::kContentPresent) {
            const auto offset = static_cast<std::size_t>(address - region.header.base_address);
            std::memcpy(out.data(), region.content.data() + offset, size);
        }
        return out;
    }
    return out;
}

std::optional<std::uint64_t> ldr_entry_for(const ParsedContainer& parsed,
                                           const std::string_view name)
{
    const auto read64 = [&](const std::uint64_t address) {
        const auto bytes = read_virtual(parsed, address, 8);
        std::uint64_t value = 0;
        std::memcpy(&value, bytes.data(), sizeof value);
        return value;
    };
    const auto read16 = [&](const std::uint64_t address) {
        const auto bytes = read_virtual(parsed, address, 2);
        std::uint16_t value = 0;
        std::memcpy(&value, bytes.data(), sizeof value);
        return value;
    };
    const auto peb = parsed.metadata.peb_address;
    const auto ldr = read64(peb + 0x18);
    if (ldr == 0) {
        return std::nullopt;
    }
    const auto head = ldr + 0x10;
    auto node = read64(head);
    for (std::size_t i = 0; i < 64 && node != 0 && node != head; ++i) {
        const auto length = read16(node + 0x58);
        const auto buffer = read64(node + 0x60);
        std::string candidate;
        candidate.reserve(length);
        for (std::uint16_t c = 0; c < length; ++c) {
            candidate.push_back(static_cast<char>(read_virtual(parsed, buffer + c, 1)[0]));
        }
        if (candidate == name) {
            return node;
        }
        node = read64(node);
    }
    return std::nullopt;
}

std::expected<engine::SyscallRunStats, engine::SyscallRunFailure>
run_container(const std::vector<std::uint8_t>& container, engine::SyscallRunOptions options)
{
    options.synthetic_system_modules = true;
    options.synthetic_module_dir = synth_dir();
    options.timeout_ms = 120000;
    if (options.max_instructions == 1000000) {
        options.max_instructions = 0; // tests bound blocks, not instructions
    }
    const engine::FactChannel facts;
    return engine::detail::run_snapshot_syscalls_with_facts(container, options, facts);
}

// One raw x64 instruction stream builder for the LdrLoadDll probe.
struct CodeBuilder {
    std::vector<std::uint8_t> bytes;
    void u8(const std::uint8_t value)
    {
        bytes.push_back(value);
    }
    void u64(const std::uint64_t value)
    {
        for (unsigned i = 0; i < 8; ++i) {
            bytes.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
        }
    }
};

// ---- DLL-input fixtures (the craft DLL branch) --------------------------

namespace capture = sheller::capture;

// A minimal PE with the IMAGE_FILE_DLL flag and a static import directory
// naming the given modules/symbols. x64 (PE32+) carries 8-byte thunks; the
// x86 rejection fixture only needs headers valid enough to reach the
// bitness refusal, so it shares the layout shape with 4-byte thunks.
std::vector<std::uint8_t>
make_dll_pe(const std::vector<std::pair<std::string, std::vector<std::string>>>& imports,
            const bool x64 = true)
{
    std::vector<std::uint8_t> image(0x4000, std::uint8_t{0});
    auto* const base = image.data();
    const auto at = [&](const std::uint32_t rva) { return base + rva; };
    const auto put16 = [&](const std::uint32_t rva, const std::uint16_t value) {
        at(rva)[0] = static_cast<std::uint8_t>(value);
        at(rva)[1] = static_cast<std::uint8_t>(value >> 8);
    };
    const auto put32 = [&](const std::uint32_t rva, const std::uint32_t value) {
        for (unsigned i = 0; i < 4; ++i) {
            at(rva)[i] = static_cast<std::uint8_t>(value >> (8 * i));
        }
    };
    const auto put64 = [&](const std::uint32_t rva, const std::uint64_t value) {
        for (unsigned i = 0; i < 8; ++i) {
            at(rva)[i] = static_cast<std::uint8_t>(value >> (8 * i));
        }
    };
    const auto put_str = [&](const std::uint32_t rva, const std::string_view text) {
        std::memcpy(at(rva), text.data(), text.size());
        at(rva + static_cast<std::uint32_t>(text.size()))[0] = 0;
    };

    auto& dos = *reinterpret_cast<capture::DosHeader*>(base);
    dos.e_magic = capture::kMzSignature;
    dos.e_lfanew = 0x80;
    const std::uint32_t nt = static_cast<std::uint32_t>(dos.e_lfanew);
    put32(nt, capture::kPeSignature);
    put16(nt + 4, x64 ? capture::kMachineAmd64 : capture::kMachineI386);
    put16(nt + 6, 1);                  // one section
    put16(nt + 20, x64 ? 240u : 224u); // size_of_optional_header
    put16(nt + 22, 0x2002);            // EXECUTABLE_IMAGE | IMAGE_FILE_DLL

    const std::uint32_t opt = nt + 24;
    put16(opt, x64 ? capture::kPe32PlusMagic : capture::kPe32Magic);
    put32(opt + 16, 0x1000); // address_of_entry_point
    put32(opt + 20, 0x1000); // base_of_code
    if (x64) {
        put64(opt + 24, 0x140000000); // image_base
    } else {
        put32(opt + 28, 0x400000); // image_base
    }
    put32(opt + 32, 0x1000);           // section_alignment
    put32(opt + 36, 0x1000);           // file_alignment
    put32(opt + 56, 0x4000);           // size_of_image
    put32(opt + 60, 0x1000);           // size_of_headers
    put16(opt + 68, 3);                // subsystem console
    put32(opt + (x64 ? 108 : 92), 16); // number_of_rva_and_sizes

    // one RWX section at RVA 0x1000 (file offset 0x1000)
    const std::uint32_t sect = opt + (x64 ? 240u : 224u);
    put_str(sect, ".rdata");
    put32(sect + 8, 0x2000);  // virtual_size
    put32(sect + 12, 0x1000); // virtual_address
    put32(sect + 16, 0x2000); // size_of_raw_data
    put32(sect + 20, 0x1000); // pointer_to_raw_data
    put32(sect + 36, 0xE0000040);

    // Import directory inside the section: descriptors, thunk arrays,
    // module names and hint/name entries. All RVAs (the section fold makes
    // RVA == file offset there).
    constexpr std::uint32_t kDescRva = 0x1000;
    constexpr std::uint32_t kOftRva = 0x1100;
    constexpr std::uint32_t kFtRva = 0x1200;
    constexpr std::uint32_t kNameRva = 0x1400;
    constexpr std::uint32_t kHintRva = 0x1600;
    const std::size_t thunk_width = x64 ? 8u : 4u;
    const std::uint64_t ordinal_flag = x64 ? (1ULL << 63) : (1ULL << 31);

    std::uint32_t name_cursor = kNameRva;
    std::uint32_t hint_cursor = kHintRva;
    for (std::size_t m = 0; m <= imports.size(); ++m) {
        const std::uint32_t desc = kDescRva + static_cast<std::uint32_t>(20 * m);
        if (m == imports.size()) {
            break; // the null terminator stays zeroed
        }
        const auto& [module, symbols] = imports[m];
        const std::uint32_t oft = kOftRva + static_cast<std::uint32_t>(thunk_width * 8 * m);
        const std::uint32_t ft = kFtRva + static_cast<std::uint32_t>(thunk_width * 8 * m);
        put32(desc + 12, name_cursor); // Name
        put_str(name_cursor, module);
        name_cursor += static_cast<std::uint32_t>(module.size() + 1);
        put32(desc, oft);     // OriginalFirstThunk
        put32(desc + 16, ft); // FirstThunk
        for (std::size_t s = 0; s < symbols.size(); ++s) {
            const std::uint32_t entry = oft + static_cast<std::uint32_t>(thunk_width * s);
            const std::uint32_t mirror = ft + static_cast<std::uint32_t>(thunk_width * s);
            put16(hint_cursor, 0); // hint
            put_str(hint_cursor + 2, symbols[s]);
            const std::uint64_t by_name = hint_cursor;
            hint_cursor += static_cast<std::uint32_t>(2 + symbols[s].size() + 1);
            if (x64) {
                put64(entry, by_name);
                put64(mirror, by_name);
            } else {
                put32(entry, static_cast<std::uint32_t>(by_name));
                put32(mirror, static_cast<std::uint32_t>(by_name));
            }
        }
        const std::uint32_t tail = static_cast<std::uint32_t>(thunk_width * symbols.size());
        if (x64) {
            put64(oft + tail, ordinal_flag);
            put64(ft + tail, ordinal_flag);
        } else {
            put32(oft + tail, static_cast<std::uint32_t>(ordinal_flag));
            put32(ft + tail, static_cast<std::uint32_t>(ordinal_flag));
        }
    }
    const std::uint32_t dirs = opt + (x64 ? 112u : 96u);
    put32(dirs + 8, kDescRva); // DataDirectory[1] = imports
    put32(dirs + 12, 20 * static_cast<std::uint32_t>(imports.size() + 1));
    put32(dirs + 13 * 8, kFtRva); // DataDirectory[13] = IAT
    put32(dirs + 13 * 8 + 4, static_cast<std::uint32_t>(thunk_width * 8 * imports.size()));
    return image;
}

} // namespace

// ---- construction -------------------------------------------------------

TEST(SnapshotCraft, ContainerSelfSufficientReplay)
{
    const auto container = craft_packed();
    ASSERT_FALSE(container.empty());
    const auto parsed = parse_container(container);
    EXPECT_EQ(parsed.header.version, snapshot::kVersion);
    EXPECT_EQ(parsed.header.bitness, snapshot::kBitness64);
    EXPECT_NE(parsed.metadata.peb_address, 0U);
    EXPECT_NE(parsed.metadata.teb_address, 0U);
    EXPECT_EQ(parsed.metadata.image_base, kSampleMappedBase);
    EXPECT_EQ(parsed.registers.rip, parsed.metadata.entry_address);
    ASSERT_FALSE(parsed.regions.empty());

    // The container re-executes the unpack stub through the replay route up
    // to the first execution transfer; API entries answered by the
    // interception layer prove the IAT-facing surface is live.
    std::uint64_t apicalls = 0;
    engine::SyscallRunOptions options;
    options.xfer_number = 1;
    options.max_blocks = 4000000;
    options.event_sink = [&apicalls](const sheller::EventTypeId type, const sheller::EventPreamble&,
                                     const std::span<const std::uint8_t>) {
        if (type == sheller::EventTypeId::kApiCall) {
            ++apicalls;
        }
    };
    const auto stats = run_container(container, options);
    ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
    EXPECT_TRUE(stats->xfer_stop);
    EXPECT_GT(stats->blocks, 2700000U);
    EXPECT_GT(apicalls, 0U);
}

TEST(SnapshotCraft, MissingSyntheticDirectoryFailsConstruction)
{
    const auto container =
        engine::craft_sample_container(SHELLER_SAMPLE_PACKED_PATH, false, fs::path{});
    ASSERT_FALSE(container.has_value());
    EXPECT_EQ(container.error().error, engine::RebuildError::kSyntheticModulesMissing);

    // A container that carries the synthetic pages also refuses replay
    // without the directory instead of silently losing the tables.
    const auto crafted = craft_packed();
    ASSERT_FALSE(crafted.empty());
    std::ispanstream in{std::span<char>{
        reinterpret_cast<char*>(const_cast<std::uint8_t*>(crafted.data())), crafted.size()}};
    auto guest = engine::prepare_guest_stream(in);
    ASSERT_TRUE(guest.has_value()) << guest.error().detail;
    const auto attached = engine::reattach_synthetic_world(*guest, fs::path{});
    ASSERT_FALSE(attached.has_value());
    EXPECT_EQ(attached.error(), engine::SyscallRunError::kSyntheticModulesMissing);
}

// ---- record fidelity ----------------------------------------------------

TEST(SnapshotCraft, FidelityBaselineIsWritableAndBaseOrdered)
{
    const auto container = craft_packed();
    const auto parsed = parse_container(container);
    const auto roundtrip = serialize_container(parsed);
    EXPECT_EQ(roundtrip, container);
    ASSERT_FALSE(parsed.regions.empty());
    for (std::size_t i = 1; i < parsed.regions.size(); ++i) {
        EXPECT_LT(parsed.regions[i - 1].header.base_address, parsed.regions[i].header.base_address);
    }
    const auto image = std::find_if(
        parsed.regions.begin(), parsed.regions.end(), [&](const snapshot::Region& region) {
            return region.header.base_address == parsed.metadata.image_base;
        });
    ASSERT_NE(image, parsed.regions.end());
    EXPECT_TRUE(engine::snapshot_protection_writable(image->header.protection))
        << std::hex << image->header.protection;
}

TEST(SnapshotCraft, FidelityDrivesTheUnpackStubToTheOepTransfer)
{
    const auto container = craft_packed();
    engine::SyscallRunOptions options;
    options.xfer_number = 1;
    options.max_blocks = 4000000;
    const auto stats = run_container(container, options);
    ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
    EXPECT_TRUE(stats->xfer_stop);
    EXPECT_GT(stats->blocks, 2700000U);
}

TEST(SnapshotCraft, UnsortedRegionsBreakTheRun)
{
    auto parsed = parse_container(craft_packed());
    ASSERT_GT(parsed.regions.size(), 2U);
    // Move the image record to the end: every other record stays ascending,
    // so the only violated property is the base ordering the write ledger's
    // binary search requires.
    const auto image = std::find_if(
        parsed.regions.begin(), parsed.regions.end(), [&](const snapshot::Region& region) {
            return region.header.base_address == parsed.metadata.image_base;
        });
    ASSERT_NE(image, parsed.regions.end());
    auto moved = *image;
    parsed.regions.erase(image);
    parsed.regions.push_back(std::move(moved));
    const auto unsorted = serialize_container(parsed);

    engine::SyscallRunOptions options;
    options.max_blocks = 3000000;
    const auto stats = run_container(unsorted, options);
    ASSERT_FALSE(stats.has_value());
    EXPECT_EQ(stats.error().error, engine::SyscallRunError::kUnhandledException);
    EXPECT_EQ(stats.error().stats.blocks, 2U);
}

TEST(SnapshotCraft, ReadonlyImageProtectionBreaksTheRun)
{
    auto parsed = parse_container(craft_packed());
    const auto image = std::find_if(
        parsed.regions.begin(), parsed.regions.end(), [&](const snapshot::Region& region) {
            return region.header.base_address == parsed.metadata.image_base;
        });
    ASSERT_NE(image, parsed.regions.end());
    image->header.protection = 0x20; // PAGE_EXECUTE_READ: no grant, no re-grant
    const auto readonly = serialize_container(parsed);

    engine::SyscallRunOptions options;
    options.max_blocks = 3000000;
    const auto stats = run_container(readonly, options);
    ASSERT_FALSE(stats.has_value());
    EXPECT_EQ(stats.error().error, engine::SyscallRunError::kUnhandledException);
    EXPECT_EQ(stats.error().stats.blocks, 2U);
}

// ---- attribution --------------------------------------------------------

TEST(SnapshotCraft, AttributionSeesSampleAndSyntheticModules)
{
    const auto container = craft_packed();
    const auto probe = engine::detail::attribute_snapshot_modules(container);
    ASSERT_TRUE(probe.has_value());
    EXPECT_GE(probe->images.size(), kModulesInSynthDir + 1);
    EXPECT_TRUE(probe->unknown_images.empty());
    EXPECT_EQ(probe->peb_address, parse_container(container).metadata.peb_address);
    EXPECT_NE(probe->peb_address, 0U);

    const auto sample = std::find_if(probe->images.begin(), probe->images.end(),
                                     [&](const engine::mem_region::ModuleImage& image) {
                                         return image.module.base == probe->image_base;
                                     });
    ASSERT_NE(sample, probe->images.end());
    EXPECT_EQ(std::string(sample->module.name.data()), "loader_image");

    engine::mem_region::ImageLayout layout;
    ASSERT_EQ(engine::mem_region::parse_section_table(sample->header_bytes.data(),
                                                      sample->header_bytes.size(), layout),
              engine::mem_region::PeParseError::kNone);
    ASSERT_FALSE(layout.sections.empty());

    // The attribution the judgment artifacts render: the entry PC belongs to
    // the sample's own image and to the section the container declares for
    // it, not to a synthesized unknown image.
    const auto entry_rva = 0x1000U;
    const auto owning_section =
        std::find_if(layout.sections.begin(), layout.sections.end(),
                     [entry_rva](const engine::mem_region::SectionRecord& section) {
                         return entry_rva >= section.rva && entry_rva < section.rva + section.span;
                     });
    ASSERT_NE(owning_section, layout.sections.end());
    EXPECT_FALSE(std::string(owning_section->name.data()).empty());
    engine::mem_region::MemRegionMap map(probe->images, probe->regions);
    const auto attribution = map.query(probe->image_base + entry_rva);
    ASSERT_TRUE(attribution.has_value());
    EXPECT_EQ(attribution->module_name, "loader_image");
    EXPECT_EQ(std::string(attribution->section_name), std::string(owning_section->name.data()));
    EXPECT_NE(attribution->section_name, "headers");
}

// ---- determinism --------------------------------------------------------

TEST(SnapshotCraft, TwoConstructionsAreByteIdentical)
{
    const auto first = craft_packed();
    const auto second = craft_packed();
    ASSERT_FALSE(first.empty());
    ASSERT_EQ(first.size(), second.size());
    EXPECT_TRUE(std::equal(first.begin(), first.end(), second.begin()));

    const auto dir = sheller_test::temp_path("sheller_snapshot_craft");
    fs::remove_all(dir);
    const auto first_path = dir / "first.snap";
    const auto second_path = dir / "second.snap";
    write_file(first_path, first);
    write_file(second_path, second);

    // The only fields in the container are the fixed header, the register
    // block, the metadata block and the region records; two constructions
    // have no other source, so the byte equality above excludes wall-clock
    // or host-random inputs by construction.
    EXPECT_EQ(read_file(first_path), read_file(second_path));

    engine::SyscallRunOptions options;
    options.max_instructions = 500000; // deterministic leg-bounded stop
    const auto a = run_container(read_file(first_path), options);
    const auto b = run_container(read_file(second_path), options);
    ASSERT_EQ(a.has_value(), b.has_value());
    if (a.has_value()) {
        EXPECT_EQ(a->blocks, b->blocks);
        EXPECT_EQ(a->terminated, b->terminated);
        EXPECT_EQ(a->exit_code, b->exit_code);
        EXPECT_EQ(a->syscalls, b->syscalls);
    } else {
        EXPECT_EQ(static_cast<int>(a.error().error), static_cast<int>(b.error().error));
        EXPECT_EQ(a.error().stats.blocks, b.error().stats.blocks);
        EXPECT_EQ(a.error().stats.syscalls, b.error().stats.syscalls);
        EXPECT_EQ(a.error().stats.terminated, b.error().stats.terminated);
        EXPECT_EQ(a.error().stats.exit_code, b.error().stats.exit_code);
    }
}

// ---- synthetic-world predicate and reattach ----------------------------

TEST(SnapshotCraft, SyntheticWorldPredicateIsExactEquality)
{
    const auto with_dir = engine::synthetic_world_bases(engine::GuestMode::kX64, synth_dir());
    EXPECT_NE(std::find(with_dir.begin(), with_dir.end(), 0x7FF800000000ULL), with_dir.end());
    EXPECT_NE(std::find(with_dir.begin(), with_dir.end(), 0x7FFB00000000ULL), with_dir.end());
    const auto without_dir = engine::synthetic_world_bases(engine::GuestMode::kX64, {});
    EXPECT_EQ(without_dir.size(), 3U);

    const auto image = [](const std::uint64_t base) {
        engine::mem_region::ModuleImage record;
        record.module.base = base;
        return record;
    };
    // Congruent with the series step but not a member: zero hits even in
    // pairs - the exact-equality rule and the two-hit floor are separate
    // gates, and neither can be satisfied by the other's input. The
    // counterexamples are derived from the FINAL base set (min - step,
    // max + step) and ASSERTED non-members first - a base extension
    // made the old hardcoded 0x7FFF a member, so future extensions must
    // re-derive, not assume.
    const auto step = 0x100000000ULL;
    const auto lo = *std::min_element(with_dir.begin(), with_dir.end());
    const auto hi = *std::max_element(with_dir.begin(), with_dir.end());
    const std::uint64_t below = lo - step;
    const std::uint64_t above = hi + step;
    EXPECT_EQ(std::find(with_dir.begin(), with_dir.end(), below), with_dir.end());
    EXPECT_EQ(std::find(with_dir.begin(), with_dir.end(), above), with_dir.end());
    const std::array<engine::mem_region::ModuleImage, 2> congruent{
        image(below), // one step below the lowest base: congruent, not a member
        image(above), // one step above the highest base: congruent, not a member
    };
    EXPECT_EQ(engine::count_synthetic_module_pages(congruent, with_dir), 0U);
    // A single exact hit is the capture-replay noise floor, not the
    // synthetic world: one coincidence must not re-hook a real capture.
    const std::array<engine::mem_region::ModuleImage, 1> lone{image(0x7FF900000000ULL)};
    EXPECT_EQ(engine::count_synthetic_module_pages(lone, with_dir), 1U);
    // Two distinct members are the construction's resident-core shape.
    const std::array<engine::mem_region::ModuleImage, 2> pair{image(0x7FF800000000ULL),
                                                              image(0x7FF900000000ULL)};
    EXPECT_EQ(engine::count_synthetic_module_pages(pair, with_dir), 2U);
    EXPECT_EQ(engine::count_synthetic_module_pages(pair, without_dir), 2U);
}

TEST(SnapshotCraft, ReattachRebuildsTheConstructionTables)
{
    auto construction = engine::prepare_pe_file(SHELLER_SAMPLE_PACKED_PATH, false, synth_dir());
    ASSERT_TRUE(construction.has_value());
    auto container = engine::craft_container_from_guest(*construction);
    ASSERT_TRUE(container.has_value());

    std::ispanstream in{std::span<char>{
        reinterpret_cast<char*>(const_cast<std::uint8_t*>(container->data())), container->size()}};
    auto replay = engine::prepare_guest_stream(in);
    ASSERT_TRUE(replay.has_value());
    const auto attached = engine::reattach_synthetic_world(*replay, synth_dir());
    ASSERT_TRUE(attached.has_value());
    EXPECT_TRUE(*attached);
    EXPECT_TRUE(replay->loader_route);

    ASSERT_EQ(replay->loader_modules.size(), construction->loader_modules.size());
    for (std::size_t i = 0; i < replay->loader_modules.size(); ++i) {
        EXPECT_EQ(replay->loader_modules[i].base, construction->loader_modules[i].base);
        EXPECT_EQ(replay->loader_modules[i].size, construction->loader_modules[i].size);
        EXPECT_EQ(std::string(replay->loader_modules[i].name.data()),
                  std::string(construction->loader_modules[i].name.data()));
    }
    ASSERT_EQ(replay->loader_exports.size(), construction->loader_exports.size());
    for (std::size_t i = 0; i < replay->loader_exports.size(); ++i) {
        EXPECT_EQ(replay->loader_exports[i].function_va,
                  construction->loader_exports[i].function_va);
        EXPECT_EQ(replay->loader_exports[i].name, construction->loader_exports[i].name);
    }
    EXPECT_EQ(replay->ldr_entry_vas, construction->ldr_entry_vas);
    EXPECT_EQ(replay->tls_callbacks, construction->tls_callbacks);

    // The reattached interception set is the construction's import-driven set
    // plus every interceptable export (a superset by design). Every
    // construction pair must survive; every extra must resolve to a handler.
    for (const auto& entry : construction->intercepts) {
        EXPECT_NE(std::find(replay->intercepts.begin(), replay->intercepts.end(), entry),
                  replay->intercepts.end());
    }
    std::size_t extras = 0;
    for (const auto& [va, id] : replay->intercepts) {
        const auto export_entry = std::find_if(
            replay->loader_exports.begin(), replay->loader_exports.end(),
            [va](const engine::LoaderExportEntry& entry) { return entry.function_va == va; });
        ASSERT_NE(export_entry, replay->loader_exports.end());
        const auto expected = engine::intercept_id_for(export_entry->name);
        ASSERT_TRUE(expected.has_value()) << export_entry->name;
        EXPECT_EQ(*expected, id);
        if (std::find(construction->intercepts.begin(), construction->intercepts.end(),
                      std::pair{va, id}) == construction->intercepts.end()) {
            ++extras;
        }
    }
    // Printed for the review record: the superset delta on this corpus.
    std::printf("reattach intercepts: construction=%zu replay=%zu extras=%zu\n",
                construction->intercepts.size(), replay->intercepts.size(), extras);

    // TLS callbacks are read from the container's sample image: the TLS
    // fixture's callback must survive the round trip.
    const auto dir = sheller_test::temp_path("sheller_snapshot_craft_tls");
    fs::create_directories(dir);
    const auto tls_pe = dir / "tls_sample.exe";
    write_file(tls_pe, sheller_test::make_minimal_pe(true));
    auto tls_construction = engine::prepare_pe_file(tls_pe, false, synth_dir());
    ASSERT_TRUE(tls_construction.has_value());
    ASSERT_EQ(tls_construction->tls_callbacks.size(), 1U);
    auto tls_container = engine::craft_container_from_guest(*tls_construction);
    ASSERT_TRUE(tls_container.has_value());
    std::ispanstream tls_in{
        std::span<char>{reinterpret_cast<char*>(const_cast<std::uint8_t*>(tls_container->data())),
                        tls_container->size()}};
    auto tls_replay = engine::prepare_guest_stream(tls_in);
    ASSERT_TRUE(tls_replay.has_value());
    ASSERT_TRUE(engine::reattach_synthetic_world(*tls_replay, synth_dir()).has_value());
    EXPECT_EQ(tls_replay->tls_callbacks, tls_construction->tls_callbacks);
}

// ---- LdrLoadDll handle answer ------------------------------------------

namespace {

// Loads one module name through the synthetic ntdll!LdrLoadDll called
// directly from patched entry code. `observe_status` terminates with the
// handler's NTSTATUS instead of the returned handle (the miss case).
struct LdrProbeResult {
    std::optional<engine::SyscallRunStats> stats;
    std::vector<std::uint8_t> container;
};

LdrProbeResult run_ldr_load_dll_probe(const std::string_view module_name, const bool observe_status)
{
    const auto dir = sheller_test::temp_path("sheller_snapshot_craft_ldr");
    fs::create_directories(dir);
    const auto pe_path = dir / "ldr_probe.exe";
    write_file(pe_path, sheller_test::make_minimal_pe(false));

    auto prepared = engine::prepare_pe_file(pe_path, false, synth_dir());
    EXPECT_TRUE(prepared.has_value());
    if (!prepared.has_value()) {
        return {};
    }
    const auto uc = prepared->unicorn.get();
    const auto image_base = prepared->metadata.image_base;
    EXPECT_EQ(image_base, kSampleMappedBase);

    const auto find_export = [&](const std::string_view name) -> std::uint64_t {
        for (const auto& entry : prepared->loader_exports) {
            if (entry.name == name) {
                return entry.function_va;
            }
        }
        return 0;
    };
    const auto ldr_load_dll = find_export("LdrLoadDll");
    EXPECT_NE(ldr_load_dll, 0U);
    if (ldr_load_dll == 0) {
        return {};
    }

    const auto unicode_va = image_base + sheller_test::kMarkerRva;  // 0x1100
    const auto string_va = image_base + sheller_test::kCallbackRva; // 0x1200
    const auto handle_va = image_base + 0x1400; // clear of the name bytes at 0x1200
    uint16_t length = static_cast<uint16_t>(module_name.size() * 2);
    std::vector<std::uint8_t> text;
    for (const char c : module_name) {
        text.push_back(static_cast<std::uint8_t>(c));
        text.push_back(0);
    }
    std::array<std::uint8_t, 16> unicode{};
    std::memcpy(unicode.data(), &length, sizeof length);
    const auto max_length = static_cast<std::uint16_t>(length + 2);
    std::memcpy(unicode.data() + 2, &max_length, sizeof max_length);
    std::memcpy(unicode.data() + 8, &string_va, sizeof string_va);
    const std::array<std::uint8_t, 8> zero_handle{};
    if (uc_mem_write(uc, unicode_va, unicode.data(), unicode.size()) != UC_ERR_OK ||
        uc_mem_write(uc, string_va, text.data(), text.size()) != UC_ERR_OK ||
        uc_mem_write(uc, handle_va, zero_handle.data(), zero_handle.size()) != UC_ERR_OK) {
        EXPECT_TRUE(false) << "guest writes failed";
        return {};
    }

    CodeBuilder code;
    code.u8(0x48);
    code.u8(0x31);
    code.u8(0xC9); // xor rcx, rcx
    code.u8(0x48);
    code.u8(0x31);
    code.u8(0xD2); // xor rdx, rdx
    code.u8(0x49);
    code.u8(0xB8);
    code.u64(unicode_va); // mov r8, &UNICODE_STRING
    code.u8(0x49);
    code.u8(0xB9);
    code.u64(handle_va); // mov r9, &handle
    code.u8(0x48);
    code.u8(0xB8);
    code.u64(ldr_load_dll); // mov rax, LdrLoadDll
    code.u8(0xFF);
    code.u8(0xD0); // call rax
    if (observe_status) {
        code.u8(0x89);
        code.u8(0xC2); // mov edx, eax
    } else {
        code.u8(0x49);
        code.u8(0x8B);
        code.u8(0x11); // mov rdx, [r9]
    }
    code.u8(0x48);
    code.u8(0xC7);
    code.u8(0xC1);
    code.u8(0xFF);
    code.u8(0xFF);
    code.u8(0xFF);
    code.u8(0xFF); // mov rcx, -1 (current process handle: only -1 ends the replay)
    code.u8(0x49);
    code.u8(0xC7);
    code.u8(0xC2);
    code.u8(0xFF);
    code.u8(0xFF);
    code.u8(0xFF);
    code.u8(0xFF); // mov r10, -1
    code.u8(0xB8);
    code.u8(0x02);
    code.u8(0x10);
    code.u8(0x00);
    code.u8(0x00); // mov eax, 1002h (terminate)
    code.u8(0x0F);
    code.u8(0x05); // syscall

    const auto entry = image_base + sheller_test::kEntryPointRva;
    if (uc_mem_write(uc, entry, code.bytes.data(), code.bytes.size()) != UC_ERR_OK) {
        EXPECT_TRUE(false) << "entry patch failed";
        return {};
    }
    std::copy_n(code.bytes.begin(), prepared->metadata.original_entry_bytes.size(),
                prepared->metadata.original_entry_bytes.begin());

    auto container = engine::craft_container_from_guest(*prepared);
    EXPECT_TRUE(container.has_value());
    if (!container.has_value()) {
        return {};
    }
    engine::SyscallRunOptions options;
    options.max_blocks = 10000;
    const auto stats = run_container(*container, options);
    if (!stats.has_value()) {
        std::printf("ldr probe error=%d uc=%x blocks=%llu syscalls=%llu rejects=%llu exit=%x |",
                    static_cast<int>(stats.error().error), stats.error().unicorn_code,
                    static_cast<unsigned long long>(stats.error().stats.blocks),
                    static_cast<unsigned long long>(stats.error().stats.syscalls),
                    static_cast<unsigned long long>(stats.error().stats.rejects),
                    stats.error().stats.exit_code);
    }
    EXPECT_TRUE(stats.has_value());
    return LdrProbeResult{stats.has_value() ? std::optional{*stats} : std::nullopt,
                          std::move(*container)};
}

} // namespace

TEST(SnapshotCraft, ReplayedLdrLoadDllWritesTheLdrEntryHandle)
{
    const auto result = run_ldr_load_dll_probe("kernel32.dll", false);
    ASSERT_TRUE(result.stats.has_value());
    EXPECT_TRUE(result.stats->terminated);

    // The expected handle comes from the container's own Ldr chain, not from
    // the construction table.
    const auto parsed = parse_container(result.container);
    const auto entry = ldr_entry_for(parsed, "kernel32.dll");
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(result.stats->exit_code, static_cast<std::uint32_t>(*entry));
}

TEST(SnapshotCraft, ReplayedLdrLoadDllAnswersNotFoundForResidentMiss)
{
    const auto result = run_ldr_load_dll_probe("absent-module.dll", true);
    ASSERT_TRUE(result.stats.has_value());
    EXPECT_TRUE(result.stats->terminated);
    EXPECT_EQ(result.stats->exit_code, 0xC0000135U); // STATUS_DLL_NOT_FOUND
}

// ---- DLL-input construction ---------------------------------------------

TEST(SnapshotCraft, CraftedDllContainerCarriesThePendingBlockAndRunnerWorld)
{
    const auto sample = read_file(SHELLER_SAMPLE_PACKED_DLL_PATH);
    ASSERT_FALSE(sample.empty());
    auto container =
        engine::craft_sample_container(SHELLER_SAMPLE_PACKED_DLL_PATH, false, synth_dir());
    ASSERT_TRUE(container.has_value()) << (container.has_value() ? "" : container.error().detail);

    const auto parsed = parse_container(*container);
    EXPECT_EQ(parsed.header.version, snapshot::kVersionV2);
    ASSERT_TRUE(parsed.pending.has_value());
    EXPECT_EQ(parsed.pending->name, "packed.dll");
    EXPECT_EQ(parsed.pending->bitness, snapshot::kBitness64);
    EXPECT_EQ(parsed.pending->bytes, sample);
    // The world is the runner's: the registered entry is the load stub, the
    // sample bytes ride the block alone.
    EXPECT_EQ(parsed.registers.rip, parsed.metadata.entry_address);
    EXPECT_NE(parsed.metadata.image_base, 0U);

    // No region of the constructed world carries a page of the sample: the
    // sample header bytes (64 bytes of the MZ block) appear nowhere.
    for (const auto& region : parsed.regions) {
        if (region.header.content != snapshot::kContentPresent) {
            continue;
        }
        EXPECT_EQ(std::search(region.content.begin(), region.content.end(), sample.begin(),
                              sample.begin() + 64),
                  region.content.end())
            << "sample header page inside the runner world at " << std::hex
            << region.header.base_address;
    }
}

TEST(SnapshotCraft, CraftedDllConstructionIsDeterministic)
{
    const auto first =
        engine::craft_sample_container(SHELLER_SAMPLE_PACKED_DLL_PATH, false, synth_dir());
    const auto second =
        engine::craft_sample_container(SHELLER_SAMPLE_PACKED_DLL_PATH, false, synth_dir());
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    ASSERT_EQ(first->size(), second->size());
    EXPECT_TRUE(std::equal(first->begin(), first->end(), second->begin()));
}

// Determinism: the same crafted container replayed twice produces
// byte-identical raw event streams - the whole synthetic-load chain (map,
// relocations, IAT, Ldr, TLS, ATTACH, DllMain verdict, ExitProcess) is a
// function of the input. Every guest-visible input of this world is
// deterministic (synthetic stubs, engine-published KUSD ticks, the virtual
// TSC), so the pin extends across processes by construction; the captured-
// world replay has its own cross-process pins (the CLI report in dll_e2e and
// the artifact chain through det_helper in dll_capture_e2e) over one fixed
// container.
TEST(SnapshotCraft, CraftedDllReplayEventStreamIsDeterministic)
{
    auto crafted =
        engine::craft_sample_container(SHELLER_SAMPLE_PACKED_DLL_PATH, false, synth_dir());
    ASSERT_TRUE(crafted.has_value());
    const auto container = *crafted;
    using Sink = std::vector<std::vector<std::uint8_t>>;
    const auto make = [](Sink& sink) {
        engine::SyscallRunOptions options;
        options.max_blocks = 6000000;
        options.event_sink = [&sink](const sheller::EventTypeId type,
                                     const sheller::EventPreamble& preamble,
                                     const std::span<const std::uint8_t> payload) {
            std::vector<std::uint8_t> record;
            record.push_back(static_cast<std::uint8_t>(type));
            const auto* seq = reinterpret_cast<const std::uint8_t*>(&preamble.seq);
            record.insert(record.end(), seq, seq + sizeof preamble.seq);
            const auto* pc = reinterpret_cast<const std::uint8_t*>(&preamble.pc);
            record.insert(record.end(), pc, pc + sizeof preamble.pc);
            record.insert(record.end(), payload.begin(), payload.end());
            sink.push_back(std::move(record));
        };
        return options;
    };
    Sink first;
    Sink second;
    const auto a = run_container(container, make(first));
    const auto b = run_container(container, make(second));
    ASSERT_EQ(a.has_value(), b.has_value());
    ASSERT_TRUE(a.has_value()) << static_cast<int>(a.error().error);
    ASSERT_EQ(first.size(), second.size());
    for (std::size_t i = 0; i < first.size(); ++i) {
        EXPECT_EQ(first[i], second[i]) << "event " << i;
        if (first[i] != second[i]) {
            break; // one diff is enough to fail; keep the log short
        }
    }
}

TEST(SnapshotCraft, CraftedDllReplayReachesTheRunnerFinishLine)
{
    auto container =
        engine::craft_sample_container(SHELLER_SAMPLE_PACKED_DLL_PATH, false, synth_dir());
    ASSERT_TRUE(container.has_value());
    engine::SyscallRunOptions options;
    options.max_blocks = 6000000;
    const auto stats = run_container(*container, options);
    ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
    // the designed finish: the runner stub's ExitProcess after a TRUE return
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x5aU);
}

// (The packed stub's esp/esp+xfer faces are a documented silent miss in both
// worlds: its DllMain opens with argument-shadow stores and a reason branch,
// so the contiguous-prefix scan finds no pushes at the entry. xfer=1 is the
// usable stop face there; the esp faces need a scan that tolerates the
// prologue.)

// Wiring regression: the same container with the pending block
// stripped and rewritten as v1 replays as a plain EXE world - the runner's
// LoadLibraryW misses (no pending module), no DllMain output reaches the
// sink, and the run still finishes its designed way. The block's presence is
// the only delta between the two executors; the v2 side's DllMain marker is
// pinned by the dll e2e suite's replay tests.
TEST(SnapshotCraft, StrippedBlockReplaysAsAPlainExeWorld)
{
    auto v2 = engine::craft_sample_container(SHELLER_SAMPLE_PACKED_DLL_PATH, false, synth_dir());
    ASSERT_TRUE(v2.has_value());
    const auto parsed = parse_container(*v2);
    ASSERT_TRUE(parsed.pending.has_value());
    auto stripped = parsed;
    stripped.header.version = snapshot::kVersion;
    stripped.pending.reset();
    const auto v1 = serialize_container(stripped);

    std::string output;
    engine::SyscallRunOptions options;
    options.max_blocks = 20000000;
    options.synthetic_system_modules = true;
    options.synthetic_module_dir = synth_dir();
    options.timeout_ms = 300000;
    options.write_sink = [&output](const std::uint8_t* data, const std::size_t size) {
        output.append(reinterpret_cast<const char*>(data), size);
    };
    const engine::FactChannel facts;
    const auto stats = engine::detail::run_snapshot_syscalls_with_facts(v1, options, facts);
    ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x5aU);
    EXPECT_EQ(output.find("hello world from dllmain"), std::string::npos)
        << "the stripped world must not run the sample";
}

// Admission negative faces: a missing module, an unknown export and an
// unresolvable x86 image each fail by name; nothing is pulled from outside
// the trusted directory.
TEST(SnapshotCraft, CraftedDllNamesAMissingSyntheticDependency)
{
    const auto dir = sheller_test::temp_path("sheller_snapshot_craft_dll");
    fs::create_directories(dir);
    const auto dll_path = dir / "needs_private.dll";
    write_file(dll_path,
               make_dll_pe({{"kernel32.dll", {"ExitProcess"}}, {"nosuchmod.dll", {"Whatever"}}}));

    const auto missing = engine::craft_sample_container(dll_path, false, synth_dir());
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().error, engine::RebuildError::kBadSnapshot);
    EXPECT_NE(missing.error().detail.find("nosuchmod.dll"), std::string::npos)
        << missing.error().detail;

    // An export that the frozen module does not carry fails by name. The
    // admission picks ONE verifiable symbol per module (the Windows rule);
    // the rest of the sample's IAT is the synthetic loader's named failure
    // at run time - so the fixture references only the bogus symbol.
    const auto bad_export = dir / "needs_export.dll";
    write_file(bad_export, make_dll_pe({{"USER32.dll", {"NotAUser32Export"}}}));
    const auto export_failure = engine::craft_sample_container(bad_export, false, synth_dir());
    ASSERT_FALSE(export_failure.has_value());
    EXPECT_NE(export_failure.error().detail.find("USER32.dll"), std::string::npos)
        << export_failure.error().detail;
}

TEST(SnapshotCraft, CraftedDllRejectsX86Input)
{
    const auto dir = sheller_test::temp_path("sheller_snapshot_craft_dll_x86");
    fs::create_directories(dir);
    const auto dll_path = dir / "x86_sample.dll";
    write_file(dll_path, make_dll_pe({{"kernel32.dll", {"ExitProcess"}}}, /*x64=*/false));

    const auto refused = engine::craft_sample_container(dll_path, false, synth_dir());
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().error, engine::RebuildError::kBitnessUnsupported);
}

// Determinism, dump clause: the same container run twice writes
// byte-identical dumps - the write ledger behind the exit-time dump is a
// function of the input. This test runs on every host with the synthetic
// directory, so the non-Windows path keeps the pin when CI runs it (the
// Windows unpack CLI re-captures per run and its live-loader noise sits
// upstream of the replay).
TEST(SnapshotCraft, CraftedDllDumpIsDeterministic)
{
    auto crafted =
        engine::craft_sample_container(SHELLER_SAMPLE_PACKED_DLL_PATH, false, synth_dir());
    ASSERT_TRUE(crafted.has_value());
    const auto container = *crafted;
    const auto dir = sheller_test::temp_path("sheller_snapshot_craft_dll_dump");
    fs::remove_all(dir);
    std::vector<std::map<std::string, std::vector<std::uint8_t>>> dumps;
    for (const unsigned run : {1u, 2u}) {
        const auto dump_dir = dir / std::to_string(run);
        engine::SyscallRunOptions options;
        options.max_blocks = 6000000;
        options.dump_directory = dump_dir;
        const auto stats = run_container(container, options);
        ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
        EXPECT_TRUE(stats->terminated);
        std::map<std::string, std::vector<std::uint8_t>> files;
        for (const auto& entry : fs::directory_iterator(dump_dir)) {
            files[entry.path().filename().string()] = read_file(entry.path());
        }
        ASSERT_FALSE(files.empty());
        dumps.push_back(std::move(files));
    }
    ASSERT_EQ(dumps[0].size(), dumps[1].size());
    for (const auto& [name, bytes] : dumps[0]) {
        const auto other = dumps[1].find(name);
        ASSERT_NE(other, dumps[1].end()) << name;
        EXPECT_EQ(bytes, other->second) << name;
    }
}

// ---- machine-derived size bound ----------------------------------------

TEST(SnapshotCraft, ContainerFitsTheDerivedSizeBound)
{
    const auto container = craft_packed();
    ASSERT_FALSE(container.empty());
    EXPECT_LE(container.size(), sheller::test::kContainerSizeBound);
    EXPECT_GE(container.size(), sheller::test::kContainerModuleBytes);

    // Reverse injection: one artificially enlarged content-present region
    // pushes the same predicate red, so the assertion has teeth.
    auto parsed = parse_container(container);
    snapshot::Region inflated;
    inflated.header = snapshot::RegionHeader{
        .base_address = 0x500000000ULL,
        .size = 0x2000000ULL,
        .protection = 0x04,
        .type = 0x20000,
        .content = snapshot::kContentPresent,
    };
    inflated.content.assign(static_cast<std::size_t>(inflated.header.size), std::uint8_t{0x41});
    parsed.regions.push_back(std::move(inflated));
    parsed.header.region_count = static_cast<std::uint32_t>(parsed.regions.size());
    const auto enlarged = serialize_container(parsed);
    EXPECT_GT(enlarged.size(), sheller::test::kContainerSizeBound);
}
