// Read-only run facts: the guest probes the
// syscall run's state assembly needs, taken before anything is written.
//
// Faces pinned here:
//  - the PEB-derived current directory: the happy path resolves against the
//    captured process's own directory, and every degradation (no PEB,
//    malformed UNICODE_STRING length, non-absolute path, not a directory)
//    keeps the guest's own relative_base value;
//  - the sample module's record in the region map: known/index/SizeOfImage on
//    a hit, and the "no such module" cell;
//  - the assembly-stage failure code: a container whose entry address is not
//    mapped fails the entry-byte restore, and the failure carries that
//    uc_err instead of a zero placeholder (the behavior pinned here).
//
// Portable by design: the facts cases build one guest by hand, and the
// failure case is a crafted v1 snapshot - no capture route, no corpus.

#include "../src/engine/mem_region_map.h"
#include "../src/engine/rebuild_state.h"
#include "../src/engine/run_facts.h"

#include "fake_ntdll.hpp"
#include "test_temp.hpp"

#include <sheller/snapshot.h>
#include <sheller/syscallrun.h>

#include <gtest/gtest.h>
#include <unicorn/unicorn.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

namespace {

namespace engine = sheller::engine;
namespace mem_region = sheller::engine::mem_region;
namespace snapshot = sheller::snapshot;

constexpr std::uint64_t kPebPage = 0x07F20000;
constexpr std::uint64_t kPebVa = kPebPage;
constexpr std::uint64_t kParamsVa = kPebPage + 0x100;
constexpr std::uint64_t kBufferVa = kPebPage + 0x200;
constexpr std::uint64_t kPageSize = 0x1000;

// A guest nobody else owns: one Unicorn instance, empty region map unless the
// case supplies modules.
engine::PreparedGuest make_guest(const snapshot::Metadata& metadata,
                                 std::vector<mem_region::ModuleImage> images = {},
                                 std::vector<mem_region::RegionRecord> regions = {})
{
    uc_engine* handle = nullptr;
    EXPECT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &handle), UC_ERR_OK);
    mem_region::MemRegionMap map(images, regions);
    return engine::PreparedGuest{engine::UnicornEngine{handle},
                                 engine::GuestMode::kX64,
                                 metadata,
                                 std::move(map),
                                 std::move(images),
                                 std::move(regions)};
}

snapshot::Metadata base_metadata()
{
    snapshot::Metadata metadata{};
    metadata.peb_address = kPebVa;
    metadata.teb_address = 0x07F10100;
    metadata.image_base = 0x00400000;
    metadata.entry_address = 0x00400000;
    return metadata;
}

// The PEB page and the CURDIR chain it points at. callers overwrite the
// UNICODE_STRING length/buffer per case.
void map_peb_page(uc_engine* const uc)
{
    ASSERT_EQ(uc_mem_map(uc, kPebPage, kPageSize, UC_PROT_ALL), UC_ERR_OK);
    const std::uint64_t params = kParamsVa;
    ASSERT_EQ(uc_mem_write(uc, kPebVa + 0x20, &params, sizeof params), UC_ERR_OK);
    const std::uint64_t buffer = kBufferVa;
    ASSERT_EQ(uc_mem_write(uc, kParamsVa + 0x48, &buffer, sizeof buffer), UC_ERR_OK);
}

void write_cwd_text(uc_engine* const uc, const std::u16string& text)
{
    std::vector<char16_t> chars{text.begin(), text.end()};
    ASSERT_FALSE(chars.empty());
    ASSERT_EQ(uc_mem_write(uc, kBufferVa, chars.data(), chars.size() * sizeof(char16_t)),
              UC_ERR_OK);
    const auto len = static_cast<std::uint16_t>(chars.size() * sizeof(char16_t));
    ASSERT_EQ(uc_mem_write(uc, kParamsVa + 0x40, &len, sizeof len), UC_ERR_OK);
}

void write_cwd_length(uc_engine* const uc, const std::uint16_t len)
{
    ASSERT_EQ(uc_mem_write(uc, kParamsVa + 0x40, &len, sizeof len), UC_ERR_OK);
}

// The guest's own base: what every degradation must preserve.
std::filesystem::path guest_base()
{
    return std::filesystem::path{"synthetic-base"};
}

engine::GuestFacts facts_for(engine::PreparedGuest& guest)
{
    return engine::snapshot_guest_facts(guest);
}

TEST(RunFacts, CwdDerivationResolvesTheCapturedProcessDirectory)
{
#ifndef _WIN32
    // The captured CURDIR separator is a Windows backslash (derived_cwd
    // appends u'\\' when the UNICODE_STRING lacks one), so a replayed capture
    // cannot resolve to a POSIX directory. The positive face is Windows-only;
    // the degradation faces below stay portable.
    GTEST_SKIP() << "the captured cwd separator is a backslash";
#endif
    const auto directory = sheller_test::temp_path("sheller_run_facts_cwd");
    std::error_code ec;
    std::filesystem::create_directories(directory, ec);
    ASSERT_FALSE(ec);

    auto guest = make_guest(base_metadata());
    guest.relative_base = guest_base();
    map_peb_page(guest.unicorn.get());
    // No trailing separator in the captured text: derived_cwd appends one, so
    // this case also exercises the append branch.
    auto text = directory.u16string();
    write_cwd_text(guest.unicorn.get(), text);

    const auto facts = facts_for(guest);
    std::u16string expected = text;
    expected.push_back(u'\\');
    EXPECT_EQ(facts.relative_base, std::filesystem::path{expected});
    EXPECT_NE(facts.relative_base, guest_base());
    std::filesystem::remove_all(directory, ec);
}

TEST(RunFacts, CwdDegradationWithoutProcessParametersKeepsTheGuestBase)
{
    auto guest = make_guest(base_metadata());
    guest.relative_base = guest_base();
    map_peb_page(guest.unicorn.get());
    const std::uint64_t no_params = 0;
    ASSERT_EQ(uc_mem_write(guest.unicorn.get(), kPebVa + 0x20, &no_params, sizeof no_params),
              UC_ERR_OK);

    const auto facts = facts_for(guest);
    EXPECT_EQ(facts.relative_base, guest_base());
}

TEST(RunFacts, CwdDegradationOnUnreadablePathBufferKeepsTheGuestBase)
{
    constexpr std::uint64_t kUnmappedBuffer = 0x123456780000;
    auto guest = make_guest(base_metadata());
    guest.relative_base = guest_base();
    map_peb_page(guest.unicorn.get());
    const auto len = static_cast<std::uint16_t>(8); // even, >= 2
    ASSERT_EQ(uc_mem_write(guest.unicorn.get(), kParamsVa + 0x40, &len, sizeof len), UC_ERR_OK);
    ASSERT_EQ(uc_mem_write(guest.unicorn.get(), kParamsVa + 0x48, &kUnmappedBuffer,
                           sizeof kUnmappedBuffer),
              UC_ERR_OK);

    const auto facts = facts_for(guest);
    EXPECT_EQ(facts.relative_base, guest_base());
}

TEST(RunFacts, CwdDegradationWithoutPebKeepsTheGuestBase)
{
    auto metadata = base_metadata();
    metadata.peb_address = 0;
    auto guest = make_guest(metadata);
    guest.relative_base = guest_base();

    const auto facts = facts_for(guest);
    EXPECT_EQ(facts.relative_base, guest_base());
}

TEST(RunFacts, CwdDegradationOnOddUnicodeLengthKeepsTheGuestBase)
{
    auto guest = make_guest(base_metadata());
    guest.relative_base = guest_base();
    map_peb_page(guest.unicorn.get());
    write_cwd_text(guest.unicorn.get(), u"abc");
    write_cwd_length(guest.unicorn.get(), 3); // odd: an impossible UTF-16 length

    const auto facts = facts_for(guest);
    EXPECT_EQ(facts.relative_base, guest_base());
}

TEST(RunFacts, CwdDegradationOnRelativePathKeepsTheGuestBase)
{
    auto guest = make_guest(base_metadata());
    guest.relative_base = guest_base();
    map_peb_page(guest.unicorn.get());
    write_cwd_text(guest.unicorn.get(), u"relative\\dir");

    const auto facts = facts_for(guest);
    EXPECT_EQ(facts.relative_base, guest_base());
}

TEST(RunFacts, CwdDegradationOnNonDirectoryKeepsTheGuestBase)
{
    auto guest = make_guest(base_metadata());
    guest.relative_base = guest_base();
    map_peb_page(guest.unicorn.get());
#ifdef _WIN32
    write_cwd_text(guest.unicorn.get(), u"C:\\sheller_run_facts_missing_dir");
#else
    write_cwd_text(guest.unicorn.get(), u"/sheller_run_facts_missing_dir");
#endif

    const auto facts = facts_for(guest);
    EXPECT_EQ(facts.relative_base, guest_base());
}

TEST(RunFacts, SampleModuleRecordOnAHit)
{
    mem_region::ModuleImage image{};
    image.module.base = 0x00400000;
    image.module.size = 0x3000;
    std::memcpy(image.module.name.data(), "sample.exe", 10);

    auto guest = make_guest(base_metadata(), {image});
    const auto facts = facts_for(guest);
    EXPECT_TRUE(facts.sample_module_known);
    EXPECT_EQ(facts.sample_module_index, 0U);
    EXPECT_EQ(facts.sample_image_size, 0x3000U);
}

TEST(RunFacts, SampleModuleRecordWithoutAMatchingBase)
{
    mem_region::ModuleImage image{};
    image.module.base = 0x00500000;
    image.module.size = 0x3000;
    std::memcpy(image.module.name.data(), "other.exe", 9);

    auto guest = make_guest(base_metadata(), {image});
    const auto facts = facts_for(guest);
    EXPECT_FALSE(facts.sample_module_known);
    EXPECT_EQ(facts.sample_module_index, 0U);
    EXPECT_EQ(facts.sample_image_size, 0U);
}

// The number -> name map and its inverse
// are built together from the target ntdll's decodable Nt* stubs; a non-Nt
// export never enters either table.
TEST(RunFacts, SyscallNumberAndNameTablesAreInverse)
{
    uc_engine* handle = nullptr;
    ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &handle), UC_ERR_OK);
    ASSERT_EQ(
        uc_mem_map(handle, sheller_test::kNtdllBase, sheller_test::kNtdllImageSize, UC_PROT_ALL),
        UC_ERR_OK);
    const auto image = sheller_test::build_fake_ntdll();
    ASSERT_EQ(uc_mem_write(handle, sheller_test::kNtdllBase, image.data(), image.size()),
              UC_ERR_OK);

    mem_region::ModuleImage module{};
    module.module.base = sheller_test::kNtdllBase;
    module.module.size = sheller_test::kNtdllImageSize;
    std::memcpy(module.module.name.data(), "ntdll", 6);
    std::vector<mem_region::ModuleImage> images{module};
    std::vector<mem_region::RegionRecord> regions{};
    mem_region::MemRegionMap map(images, regions);
    engine::PreparedGuest guest{engine::UnicornEngine{handle},
                                engine::GuestMode::kX64,
                                sheller::snapshot::Metadata{},
                                std::move(map),
                                std::move(images),
                                std::move(regions)};
    // push_back rather than initializer-list assignment: GCC's array-bounds
    // analysis mis-sizes the one-element temporary under ASan and rejects the
    // build with -Werror.
    guest.loader_modules.push_back(module.module);

    const auto facts = facts_for(guest);
    ASSERT_EQ(facts.syscall_numbers_by_name.size(), 2U);
    ASSERT_EQ(facts.syscall_names.size(), 2U);
    const auto terminate = facts.syscall_numbers_by_name.find("NtTerminateProcess");
    ASSERT_NE(terminate, facts.syscall_numbers_by_name.end());
    EXPECT_EQ(terminate->second, 0x1234U);
    const auto protect = facts.syscall_numbers_by_name.find("NtProtectVirtualMemory");
    ASSERT_NE(protect, facts.syscall_numbers_by_name.end());
    EXPECT_EQ(protect->second, 0x5678U);
    EXPECT_EQ(facts.syscall_numbers_by_name.count("RtlIdle"), 0U);
    for (const auto& [name, number] : facts.syscall_numbers_by_name) {
        const auto inverse = facts.syscall_names.find(number);
        ASSERT_NE(inverse, facts.syscall_names.end()) << name;
        EXPECT_EQ(inverse->second, name);
    }
}

// A v1 container whose entry address is mapped nowhere: rebuild succeeds (the
// region table is legal and RIP equals the metadata entry), and the run's
// entry-byte restore is the first write, so it fails with
// UC_ERR_WRITE_UNMAPPED before any state or hook exists.
constexpr std::uint64_t kImageBase = 0x00400000;
constexpr std::uint64_t kStackRegionBase = 0x07F00000;
constexpr std::uint64_t kStackVa = kStackRegionBase + 0x800;
constexpr std::uint64_t kTebRegionBase = 0x07F10000;
constexpr std::uint64_t kUnmappedEntry = 0x00A00000;
constexpr std::uint32_t kPageReadwrite = 0x04;
constexpr std::uint32_t kPageExecuteReadwrite = 0x40;
constexpr std::uint32_t kMemImage = 0x1000000;
constexpr std::uint32_t kMemPrivate = 0x20000;

std::vector<std::uint8_t> craft_unmapped_entry_snapshot()
{
    std::vector<std::uint8_t> page(kPageSize, 0x90);
    std::vector<std::uint8_t> stack(kPageSize, 0x5A);
    std::vector<std::uint8_t> teb(kPageSize, 0x00);

    snapshot::Metadata metadata{};
    metadata.peb_address = kPebPage; // unmapped in this container
    metadata.teb_address = kTebRegionBase + 0x100;
    metadata.image_base = kImageBase;
    metadata.entry_address = kUnmappedEntry;
    std::fill(metadata.original_entry_bytes.begin(), metadata.original_entry_bytes.end(),
              std::uint8_t{0x90});

    snapshot::Registers registers{};
    registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRsp)] = kStackVa;
    registers.rip = kUnmappedEntry;
    registers.rflags = 0x202; // reserved one + interrupt enable

    std::ostringstream out;
    snapshot::Writer writer{out};
    if (!writer.write_header(
            snapshot::Header{.version = snapshot::kVersion, .bitness = snapshot::kBitness64}) ||
        !writer.write_registers(registers) || !writer.write_metadata(metadata) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = kImageBase,
                                                    .size = kPageSize,
                                                    .protection = kPageExecuteReadwrite,
                                                    .type = kMemImage,
                                                    .content = snapshot::kContentPresent},
                             page.data()) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = kStackRegionBase,
                                                    .size = kPageSize,
                                                    .protection = kPageReadwrite,
                                                    .type = kMemPrivate,
                                                    .content = snapshot::kContentPresent},
                             stack.data()) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = kTebRegionBase,
                                                    .size = kPageSize,
                                                    .protection = kPageReadwrite,
                                                    .type = kMemPrivate,
                                                    .content = snapshot::kContentPresent},
                             teb.data()) ||
        !writer.finalize_region_count()) {
        EXPECT_TRUE(false) << "crafted snapshot serialization failed";
    }
    const auto bytes = out.str();
    return {bytes.begin(), bytes.end()};
}

TEST(RunFacts, AssemblyFailureCarriesTheRawUnicornCode)
{
    const auto bytes = craft_unmapped_entry_snapshot();
    engine::SyscallRunOptions options;
    options.max_instructions = 16;

    const auto run = engine::run_snapshot_syscalls(bytes, options);
    ASSERT_FALSE(run.has_value()) << "a run whose entry is unmapped cannot assemble";
    EXPECT_EQ(run.error().error, engine::SyscallRunError::kUnicornFailure);
    // The old placeholder initializer ({}) dropped this code; the raw uc_err of
    // the failed entry-byte restore has to reach the failure. The exact code is
    // pinned too: the assembly stage never ran, so it is that store's error.
    EXPECT_EQ(run.error().unicorn_code, static_cast<std::uint32_t>(UC_ERR_WRITE_UNMAPPED));
    // No execution happened: every statistic is still the initialization value.
    EXPECT_TRUE(run.error().stats.terminated == false);
    EXPECT_EQ(run.error().stats.exit_code, 0U);
    EXPECT_EQ(run.error().stats.blocks, 0U);
    EXPECT_EQ(run.error().stats.syscalls, 0U);
    EXPECT_EQ(run.error().stats.rejects, 0U);
    EXPECT_EQ(run.error().stats.exceptions, 0U);
    EXPECT_EQ(run.error().stats.xfers, 0U);
}

} // namespace
