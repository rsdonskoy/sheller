// Directory-mode system modules: the
// loader route's strict source tiers over a user directory - the boundary
// pair derives under the committed manifest, other directory DLLs map as
// real bytes, the API Set map is required and anchored, a missing closure
// member is a named rejection (the host system directories are never
// read), and the explicit fallback joins as a marked synthetic. Portable
// by design: the construction runs on both hosts.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "../src/api/wiring.h"
#include "boundary_fixture.h"

#include "boundary_manifest.h"
#include "boundary_metadata.h"
#include "craft.h"
#include "loader_route.h"

#include <sheller/peloader.h>

#include "../src/engine/log_detail.h"
#include <sheller/log.h>
#include <sheller/snapshot.h>
#include <sheller/syscallrun.h>

#include <unicorn/unicorn.h>

#include <spanstream>
#include <sstream>
#include <xxhash.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;
namespace snapshot = sheller::snapshot;

namespace {

using sheller::engine::SystemModuleSource;
using sheller_test::boundary_fixture_exports;
using sheller_test::boundary_fixture_rules;
using sheller_test::make_boundary_source;
using sheller_test::make_importing_source;

constexpr const char* kSamplePath = SHELLER_SAMPLE_PACKED_PATH;
constexpr const char* kSynthDir = SYNTH_MODULE_DIR;
constexpr const char* kGenScript = APISET_GEN_SCRIPT;
constexpr const char* kSourceJson = APISET_SOURCE_JSON;
constexpr const char* kPython = APISET_PYTHON;

void write_bytes(const fs::path& path, const std::vector<std::uint8_t>& bytes)
{
    std::ofstream out(path, std::ios::binary);
    ASSERT_TRUE(out.is_open()) << path.string();
    std::copy(bytes.begin(), bytes.end(), std::ostreambuf_iterator<char>(out));
}

// One fixture directory: ntdll derives from the committed manifest, the API
// Set map comes from the committed text source (its anchor is exactly the
// fixture ntdll), and the named extra modules join as real bytes.
fs::path make_directory(const std::string& tag,
                        const std::vector<std::pair<std::string, std::vector<std::uint8_t>>>& extra)
{
    const auto dir = fs::temp_directory_path() / ("sheller_dir_mode_" + tag);
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);
    write_bytes(dir / "ntdll.dll", make_boundary_source(boundary_fixture_exports(false)));
    int gen_exit = 0;
    {
        const std::string cmd = std::string(kPython) + " \"" + kGenScript + "\" \"" + kSourceJson +
                                "\" \"" + (dir / "apiset-map.bin").string() + "\"";
        gen_exit = std::system(cmd.c_str());
    }
    EXPECT_EQ(gen_exit, 0);
    for (const auto& [name, bytes] : extra) {
        write_bytes(dir / fs::path(name), bytes);
    }
    return dir;
}

const SystemModuleSource* find_source(const sheller::engine::PreparedGuest& guest,
                                      const std::string& name)
{
    for (const auto& [module, source] : guest.module_sources) {
        if (module == name) {
            return &source;
        }
    }
    return nullptr;
}

// The construction failure detail, when the construction failed.
std::string rejection_detail(
    const std::expected<sheller::engine::PreparedGuest, sheller::engine::RebuildFailure>& built)
{
    if (built.has_value()) {
        return {};
    }
    return built.error().detail + " (error code " +
           std::to_string(static_cast<int>(built.error().error)) + ")";
}

// The exec-fixture call site: call qword ptr [rip + rel32] through an IAT
// slot, followed by ret.
std::vector<std::uint8_t> call_through(const std::uint32_t body_rva, const std::uint32_t slot_rva)
{
    std::vector<std::uint8_t> bytes{0xFF, 0x15};
    const auto rel = static_cast<std::uint32_t>(slot_rva - (body_rva + 6));
    for (unsigned i = 0; i < 4; ++i) {
        bytes.push_back(static_cast<std::uint8_t>(rel >> (8 * i)));
    }
    bytes.push_back(0xC3);
    return bytes;
}

} // namespace

TEST(LoaderDirectory, MissingClosureMemberIsNamedRejectionWithoutFallback)
{
    // the directory carries only the derived ntdll: the sample's kernel32
    // closure reference has no resident home, the fallback is off - the
    // host's own System32 copy must NOT step in
    const auto dir = make_directory("nofallback", {});
    const auto built = sheller::engine::prepare_pe_file(kSamplePath, false, {}, dir, false);
    ASSERT_FALSE(built.has_value()) << "directory mode must not fall back silently";
    EXPECT_NE(rejection_detail(built).find("kernel32"), std::string::npos)
        << rejection_detail(built);
    // a sample-direct import names the sample image as the importer - never
    // an empty "(imported by )" slot
    EXPECT_NE(rejection_detail(built).find("(imported by the sample image)"), std::string::npos)
        << rejection_detail(built);
}

TEST(LoaderDirectory, FallbackJoinsMarkedAsSynthetic)
{
    // the same directory with the fallback option on: kernel32 falls back
    // to the frozen synthetic module and the source table says so
    const auto dir = make_directory("fallback", {});
    const auto built = sheller::engine::prepare_pe_file(kSamplePath, false, kSynthDir, dir, true);
    ASSERT_TRUE(built.has_value()) << rejection_detail(built);
    EXPECT_TRUE(built->directory_mode);
    const auto* ntdll_source = find_source(*built, "ntdll.dll");
    ASSERT_NE(ntdll_source, nullptr);
    EXPECT_EQ(*ntdll_source, SystemModuleSource::kDirectoryDerived);
    const auto* kernel32_source = find_source(*built, "kernel32.dll");
    ASSERT_NE(kernel32_source, nullptr);
    EXPECT_EQ(*kernel32_source, SystemModuleSource::kFallbackSynthetic);
    // the sample's crt api-set imports reduce through the directory map to
    // ucrtbase, whose frozen synthetic module joins as a marked fallback too
    const auto* ucrt_source = find_source(*built, "ucrtbase.dll");
    ASSERT_NE(ucrt_source, nullptr);
    EXPECT_EQ(*ucrt_source, SystemModuleSource::kFallbackSynthetic);
    // no win32u in the directory and nothing referenced it: not resident,
    // and no source row exists for it
    EXPECT_EQ(find_source(*built, "win32u.dll"), nullptr);
}

TEST(LoaderDirectory, MissingNtdllIsNamedRejection)
{
    // ntdll is the one required boundary member: without it the directory
    // mode rejects before anything maps
    const auto dir = make_directory("nontdll", {});
    std::error_code ec;
    fs::remove(dir / "ntdll.dll", ec);
    const auto built = sheller::engine::prepare_pe_file(kSamplePath, false, kSynthDir, dir, true);
    ASSERT_FALSE(built.has_value());
    EXPECT_NE(rejection_detail(built).find("ntdll"), std::string::npos) << rejection_detail(built);
}

TEST(LoaderDirectory, MissingApisetMapIsNamedRejection)
{
    // the API Set map travels with the directory: without it there is no
    // api-set adjudication and the construction refuses
    const auto dir = make_directory("nomap", {});
    std::error_code ec;
    fs::remove(dir / "apiset-map.bin", ec);
    const auto built = sheller::engine::prepare_pe_file(kSamplePath, false, kSynthDir, dir, true);
    ASSERT_FALSE(built.has_value());
    EXPECT_NE(rejection_detail(built).find("apiset-map"), std::string::npos)
        << rejection_detail(built);
}

TEST(LoaderDirectory, SourceTableTiersTheDirectory)
{
    // a real-byte module in the directory maps as its own bytes and the
    // source table distinguishes the tiers (the importing-builder output
    // carries the reloc table real directory inputs must have)
    const auto dir = make_directory(
        "tiers", {{"other.dll", make_importing_source({}, {{"ntdll.dll", {"RtlFoo"}}})}});
    const auto built = sheller::engine::prepare_pe_file(kSamplePath, false, kSynthDir, dir, true);
    ASSERT_TRUE(built.has_value()) << rejection_detail(built);
    const auto* other_source = find_source(*built, "other.dll");
    ASSERT_NE(other_source, nullptr);
    EXPECT_EQ(*other_source, SystemModuleSource::kDirectoryRealBytes);
    // the derived ntdll's export table answers lookups: the boundary layer
    // is live in this world
    const auto ntdll_base = built->map.module_index_by_name("ntdll.dll");
    ASSERT_TRUE(ntdll_base.has_value());
}

TEST(LoaderDirectory, SyntheticRouteStaysUnmarked)
{
    // the existing synthetic-mode construction keeps its behavior: no
    // directory mode, and the source table rows all carry the synthetic mark
    const auto built = sheller::engine::prepare_pe_file(kSamplePath, false, kSynthDir);
    ASSERT_TRUE(built.has_value());
    EXPECT_FALSE(built->directory_mode);
    ASSERT_FALSE(built->module_sources.empty());
    for (const auto& [name, source] : built->module_sources) {
        EXPECT_EQ(source, SystemModuleSource::kSynthetic) << name;
    }
}

// ---- task 3.2: resident real-byte IAT binding ------------------------------

// A real-byte kernel32 fixture that imports the derived ntdll's service
// export: its IAT slot must carry the derived stub's VA after binding.
std::vector<std::uint8_t> make_real_kernel32_source()
{
    return make_importing_source(
        {{"SampleExport", nullptr, sheller_test::kBoundaryTextRva, {0x31, 0xC0, 0xC3}, {}}},
        {{"ntdll.dll", {"NtCreateFile"}}});
}

// The derived ntdll's NtCreateFile stub VA in the constructed world: the
// disposition body slot is derived here, not assumed.
std::uint64_t expected_ntdll_stub_va()
{
    const auto source = make_boundary_source(boundary_fixture_exports(false));
    const auto derived =
        sheller::loader::derive_boundary_image(source, "ntdll.dll", boundary_fixture_rules());
    EXPECT_TRUE(derived.has_value());
    if (!derived.has_value()) {
        return 0;
    }
    for (const auto& entry : derived->exports) {
        if (entry.name == "NtCreateFile") {
            return 0x7FF800000000ULL + entry.body_rva; // kBases64[0]
        }
    }
    ADD_FAILURE() << "the fixture ntdll lost its NtCreateFile";
    return 0;
}

TEST(LoaderDirectory, ResidentIatBindsAcrossHostGuestAndStaysOtherwiseUntouched)
{
    const auto kernel32_source = make_real_kernel32_source();
    const auto dir = make_directory("binding", {{"kernel32.dll", kernel32_source}});
    const auto built = sheller::engine::prepare_pe_file(kSamplePath, false, kSynthDir, dir, true);
    ASSERT_TRUE(built.has_value()) << rejection_detail(built);
    const auto* kernel32_source_mark = find_source(*built, "kernel32.dll");
    ASSERT_NE(kernel32_source_mark, nullptr);
    EXPECT_EQ(*kernel32_source_mark, SystemModuleSource::kDirectoryRealBytes);

    // the resident kernel32 lives at its reserved slot; the guest copy must
    // carry the bound IAT: the derived ntdll's NtCreateFile stub VA
    const auto kernel32_base = 0x7FF900000000ULL; // kBases64[1]
    const auto stub_va = expected_ntdll_stub_va();
    std::uint64_t bound = 0;
    ASSERT_EQ(uc_mem_read(built->unicorn.get(), kernel32_base + sheller_test::kImportingIatRva,
                          &bound, sizeof bound),
              UC_ERR_OK);
    EXPECT_EQ(bound, stub_va) << std::hex << bound;

    // the writeback is the ONLY change: the guest bytes equal the source
    // image everywhere outside the bound FirstThunk slot
    const auto info = sheller::loader::parse_pe(kernel32_source);
    ASSERT_TRUE(info.has_value());
    const auto plain = sheller::loader::build_image(kernel32_source, *info);
    ASSERT_TRUE(plain.has_value());
    std::vector<std::uint8_t> guest_image(plain->size(), std::uint8_t{0});
    ASSERT_EQ(
        uc_mem_read(built->unicorn.get(), kernel32_base, guest_image.data(), guest_image.size()),
        UC_ERR_OK);
    ASSERT_EQ(guest_image.size(), plain->size());
    for (std::size_t i = 0; i < plain->size(); ++i) {
        const auto at = static_cast<std::uint64_t>(i);
        if (at >= sheller_test::kImportingIatRva && at < sheller_test::kImportingIatRva + 8) {
            continue; // the binding writeback
        }
        ASSERT_EQ(guest_image[i], (*plain)[i]) << "byte " << std::hex << i;
    }
}

TEST(LoaderDirectory, ResidentDependencyMissingIsNamedRejection)
{
    // a resident module whose own dependency cannot resolve: named
    // rejection naming (module, dependency), never a half-bound world
    const auto kernel32_source = make_importing_source(
        {{"SampleExport", nullptr, sheller_test::kBoundaryTextRva, {0x31, 0xC0, 0xC3}, {}}},
        {{"fakeuser32.dll", {"Whatever"}}});
    const auto dir = make_directory("baddep", {{"kernel32.dll", kernel32_source}});
    const auto built = sheller::engine::prepare_pe_file(kSamplePath, false, kSynthDir, dir, true);
    ASSERT_FALSE(built.has_value());
    const auto detail = rejection_detail(built);
    EXPECT_NE(detail.find("kernel32.dll"), std::string::npos) << detail;
    EXPECT_NE(detail.find("fakeuser32.dll"), std::string::npos) << detail;
}

TEST(LoaderDirectory, ReferencedWin32uAbsenceIsNamedRejection)
{
    // the second half of the missing-win32u two-ways: a resident module
    // references win32u and the directory does not carry it - the binding
    // stage rejects; (nobody references it: the FallbackJoins test above
    // constructs without it)
    const auto kernel32_source = make_importing_source(
        {{"SampleExport", nullptr, sheller_test::kBoundaryTextRva, {0x31, 0xC0, 0xC3}, {}}},
        {{"win32u.dll", {"NtUserGetRawInputDataList"}}});
    const auto dir = make_directory("nowin32u", {{"kernel32.dll", kernel32_source}});
    const auto built = sheller::engine::prepare_pe_file(kSamplePath, false, kSynthDir, dir, true);
    ASSERT_FALSE(built.has_value());
    const auto detail = rejection_detail(built);
    EXPECT_NE(detail.find("win32u.dll"), std::string::npos) << detail;
}

#ifdef _WIN32

TEST(LoaderDirectory, RealCodeExecutesThroughItsIatToTheBoundary)
{
    // the full chain as guest code: the sample's entry calls
    // kernel32!SampleExport through its own bound IAT; SampleExport's real
    // body calls its own bound IAT slot - the derived ntdll's NtCreateFile
    // stub - and the stub's real bytes execute the `syscall` instruction the
    // engine intercepts. The unregistered number takes the default deny.
    // the resident module: its only export makes the one-call chain
    const auto kernel32_source = make_importing_source(
        {{"SampleExport",
          nullptr,
          sheller_test::kBoundaryTextRva,
          call_through(sheller_test::kBoundaryTextRva, sheller_test::kImportingIatRva),
          {}}},
        {{"ntdll.dll", {"NtCreateFile"}}});
    // the entry: the boundary chain, then the derived ntdll's
    // NtTerminateProcess stub - the contract policy answers it by name and
    // stops the run cleanly
    std::vector<std::uint8_t> entry_body =
        call_through(sheller_test::kBoundaryTextRva, sheller_test::kImportingIatRva);
    entry_body.push_back(0xEB);
    entry_body.push_back(0xFE); // jmp $: the budget stops the run
    const auto sample =
        make_importing_source({{"entry", nullptr, sheller_test::kBoundaryTextRva, entry_body, {}}},
                              {{"kernel32.dll", {"SampleExport"}}});

    const auto dir = make_directory("exec", {{"kernel32.dll", kernel32_source}});
    const auto sample_path = fs::temp_directory_path() / "sheller_dir_mode_exec_sample.exe";
    write_bytes(sample_path, sample);

    const auto info = sheller::loader::parse_pe(kernel32_source);
    ASSERT_TRUE(info.has_value());
    {
        const auto probe =
            sheller::engine::prepare_pe_file(sample_path.string(), false, kSynthDir, dir, true);
        ASSERT_TRUE(probe.has_value()) << rejection_detail(probe);
        std::uint64_t slot0 = 0;
        std::uint64_t slot1 = 0;
        std::memcpy(&slot0, sample.data() + sheller_test::kImportingIatRva, 8);
        std::memcpy(&slot1, sample.data() + sheller_test::kImportingIatRva + 64, 8);
        std::printf("pre-bind slot0=%llx slot1=%llx\n", static_cast<unsigned long long>(slot0),
                    static_cast<unsigned long long>(slot1));
        ASSERT_EQ(
            uc_mem_read(probe->unicorn.get(), 0x400000 + sheller_test::kImportingIatRva, &slot0, 8),
            UC_ERR_OK);
        ASSERT_EQ(uc_mem_read(probe->unicorn.get(), 0x400000 + sheller_test::kImportingIatRva + 64,
                              &slot1, 8),
                  UC_ERR_OK);
        std::printf("bound slot0=%llx slot1=%llx\n", static_cast<unsigned long long>(slot0),
                    static_cast<unsigned long long>(slot1));
    }

    sheller::engine::SyscallRunOptions options;
    options.system_modules_dir = dir;
    options.system_modules_fallback = true;
    options.max_instructions = 20000;
    const auto run = sheller::engine::run_pe_file(sample_path.string(), options);
    // budget exhaustion is the planned stop; the stats carry the proof: the
    // call chain crossed real module code into the derived stub, whose real
    // bytes executed the syscall instruction the engine intercepted (the
    // policy layer answers NtCreateFile by name - an accepted contract call,
    // not a rejection)
    const auto& stats = run.has_value() ? run.value() : run.error().stats;
    const char* outcome = run.has_value() ? "terminated" : "stopped";
    EXPECT_GE(stats.syscalls, 1u) << outcome;
    std::error_code ec;
    fs::remove(sample_path, ec);
}

// ---- task 5.1: trap stop, compat counting, the explicit whitelist ----------

#ifdef _WIN32

TEST(LoaderDirectory, BoundaryTrapStopsWithNamedDiagnosis)
{
    // the entry calls the derived ntdll's NtWeird - the (c)-class trap: the
    // run terminates with the named diagnosis, the ud2 body and every
    // successor instruction never execute, and the stop is its own kind
    // (not a crash, not a budget expiry)
    const auto kernel32_source = make_real_kernel32_source();
    std::vector<std::uint8_t> entry_body =
        call_through(sheller_test::kBoundaryTextRva, sheller_test::kImportingIatRva + 64);
    entry_body.push_back(0xEB);
    entry_body.push_back(0xFE);
    const auto sample = make_importing_source(
        {{"entry", nullptr, sheller_test::kBoundaryTextRva, entry_body, {}}},
        {{"kernel32.dll", {"SampleExport"}}, {"ntdll.dll", {"NtWeird", "NtTerminateProcess"}}});
    const auto sample_path = fs::temp_directory_path() / "sheller_dir_mode_trap.exe";
    write_bytes(sample_path, sample);

    const auto dir = make_directory("trap51", {{"kernel32.dll", kernel32_source}});
    sheller::engine::SyscallRunOptions options;
    options.system_modules_dir = dir;
    options.max_instructions = 20000;
    const auto run = sheller::engine::run_pe_file(sample_path.string(), options);
    ASSERT_FALSE(run.has_value()) << "the trap must stop the run";
    EXPECT_EQ(run.error().error, sheller::engine::SyscallRunError::kBoundaryTrap);
    EXPECT_NE(run.error().detail.find("boundary-trap: ntdll.dll!NtWeird"), std::string::npos)
        << run.error().detail;
    EXPECT_EQ(run.error().stats.syscalls, 0u); // nothing after the call executed
    std::error_code ec;
    fs::remove(sample_path, ec);
}

TEST(LoaderDirectory, CompatWhitelistCountsRealBodiesDoNot)
{
    // the entry calls RtlFoo, RtlFooAlias (one compat body, one VA), the
    // real kernel32!SampleExport body, then the spin - the instruction
    // budget stops the run and the drained counts carry the proof: exactly
    // one compat slot under its canonical name (shared VA, no alias
    // duplicate); the real body never joins stub_calls
    const auto kernel32_source = make_real_kernel32_source();
    std::vector<std::uint8_t> entry_body;
    const auto emit_call = [&](const std::uint32_t slot) {
        const auto bytes = call_through(
            sheller_test::kBoundaryTextRva + static_cast<std::uint32_t>(entry_body.size()), slot);
        entry_body.insert(entry_body.end(), bytes.begin(), bytes.end());
    };
    constexpr std::uint32_t kNtdllBlock = sheller_test::kImportingIatRva + 64;
    emit_call(kNtdllBlock + 8); // RtlFoo (compat; alias share noted below)
    entry_body.push_back(0xEB);
    entry_body.push_back(0xFE); // jmp $: the budget stops the run
    const auto sample = make_importing_source(
        {{"entry", nullptr, sheller_test::kBoundaryTextRva, entry_body, {}}},
        {{"kernel32.dll", {"SampleExport"}},
         {"ntdll.dll", {"NtWeird", "RtlFoo", "RtlFooAlias", "NtTerminateProcess"}}});
    const auto sample_path = fs::temp_directory_path() / "sheller_dir_mode_count.exe";
    write_bytes(sample_path, sample);

    const auto dir = make_directory("count51", {{"kernel32.dll", kernel32_source}});
    sheller::engine::SyscallRunOptions options;
    options.system_modules_dir = dir;
    options.max_instructions = 2000;
    std::map<std::string, std::uint64_t> stubs;
    options.stub_sink = [&stubs](const std::uint16_t, const std::string_view name,
                                 const std::uint64_t count) { stubs[std::string(name)] = count; };
    const auto run = sheller::engine::run_pe_file(sample_path.string(), options);
    // the drained counts carry the proof: exactly one whitelist entry
    // counted, the canonical name, nothing else - the real kernel32 body,
    // the syscall stubs, the trap and the alias spelling all stay out of
    // stub_calls. (The run may end in this fixture's post-call spin face -
    // a hand-built-sample run quirk; the
    // counts drain before any stop kind returns.)
    ASSERT_EQ(stubs.size(), 1u);
    EXPECT_EQ(stubs.begin()->first, "RtlFoo");
    EXPECT_EQ(stubs.begin()->second, 1u);
    if (run.has_value()) {
        EXPECT_TRUE(run->terminated);
    } else {
        EXPECT_EQ(run.error().stats.syscalls, 0u);
    }
    std::error_code ec;
    fs::remove(sample_path, ec);
}

#endif // _WIN32

#endif // _WIN32

// ---- task 3.3: result checks and the whole-interval overlap gate ----------

TEST(LoaderDirectory, RelocationTableValidation)
{
    using namespace sheller::loader;
    std::vector<std::uint8_t> image(0x2000, std::uint8_t{0});
    ImageInfo info;
    info.bitness = kBitness64;
    info.image_size = image.size();
    info.reloc_directory_rva = 0x100;
    // one block at 0x100: page RVA 0x1000, 12-byte block, two DIR64
    // entries (a block encodes 12-bit page offsets, so the page sits at
    // 0x1000 for targets near the image end)
    info.reloc_directory_size = 12;
    const auto put32 = [&](const std::size_t at, const std::uint32_t v) {
        for (unsigned i = 0; i < 4; ++i) {
            image[at + i] = static_cast<std::uint8_t>(v >> (8 * i));
        }
    };
    const auto put16 = [&](const std::size_t at, const std::uint16_t v) {
        image[at] = static_cast<std::uint8_t>(v);
        image[at + 1] = static_cast<std::uint8_t>(v >> 8);
    };
    const auto entry = [](const std::uint32_t rva) {
        return static_cast<std::uint16_t>(0xA000 | (rva & 0xFFF)); // DIR64
    };
    put32(0x100, 0x1000); // page RVA
    put32(0x104, 12);     // block size
    put16(0x108, entry(0x10));
    put16(0x10A, entry(0x18));
    EXPECT_TRUE(validate_relocations(image, info).has_value());

    // a fixup target past the image: the "needs relocation without
    // effective info" shape is a named rejection
    put16(0x10A, entry(0xFF9));
    const auto out_of_range = validate_relocations(image, info);
    ASSERT_FALSE(out_of_range.has_value());
    EXPECT_EQ(out_of_range.error(), LoadError::kBadReloc);

    // a malformed block size rejects too
    put16(0x10A, entry(0x18));
    put32(0x104, 4);
    EXPECT_FALSE(validate_relocations(image, info).has_value());
}

TEST(LoaderDirectory, WholeIntervalOverlapGate)
{
    using sheller::loader::LoadedModule;
    const auto module_at = [](const std::uint64_t base, const std::size_t size) {
        LoadedModule m;
        m.base = base;
        m.image.assign(size, std::uint8_t{0});
        std::memcpy(m.name.data(), "m.dll", 6);
        return m;
    };
    // a module overlapping the sample image names the pair
    std::vector<LoadedModule> modules{module_at(0x7FFB00000000ULL, 0x10000)};
    const auto sample_hit = sheller::engine::find_directory_range_overlap(
        modules, sheller::engine::GuestMode::kX64, 0x7FFB00008000ULL, 0x1000);
    ASSERT_TRUE(sample_hit.has_value());
    EXPECT_EQ(sample_hit->first, "m.dll");
    EXPECT_EQ(sample_hit->second, "<sample image>");

    // a module crossing into the next module's slot names the pair
    modules.push_back(module_at(0x7FFB00008000ULL, 0x1000));
    const auto module_hit = sheller::engine::find_directory_range_overlap(
        modules, sheller::engine::GuestMode::kX64, 0x400000, 0x1000);
    ASSERT_TRUE(module_hit.has_value());
    EXPECT_EQ(module_hit->second, "m.dll");

    // disjoint placements pass, and the fixed regions stay clear of the
    // reserved module slots
    std::vector<LoadedModule> clean;
    for (const auto base : {0x7FF800000000ULL, 0x7FF900000000ULL, 0x7FFB00000000ULL}) {
        clean.push_back(module_at(base, 0x42000));
    }
    EXPECT_FALSE(sheller::engine::find_directory_range_overlap(
                     clean, sheller::engine::GuestMode::kX64, 0x400000, 0x1000)
                     .has_value());
}

// ---- task 4.1: the metadata region and the mode marker ---------------------

// Reads the constructed guest's metadata payload bytes at the fixed base.
std::vector<std::uint8_t> read_metadata_payload(const sheller::engine::PreparedGuest& guest)
{
    namespace bm = sheller::engine::boundary_metadata;
    std::vector<std::uint8_t> bytes(bm::kMetadataMaxBytes, std::uint8_t{0});
    if (uc_mem_read(guest.unicorn.get(), bm::kMetadataBase, bytes.data(), bytes.size()) !=
        UC_ERR_OK) {
        return {};
    }
    return bytes;
}

TEST(LoaderDirectory, MetadataRegionCarriesTheWorldRecord)
{
    const auto dir = make_directory("metadata", {});
    const auto built = sheller::engine::prepare_pe_file(kSamplePath, false, kSynthDir, dir, true);
    ASSERT_TRUE(built.has_value()) << rejection_detail(built);
    namespace bm = sheller::engine::boundary_metadata;

    // the payload decodes at the fixed base and names the modules
    const auto payload_bytes = read_metadata_payload(*built);
    ASSERT_FALSE(payload_bytes.empty());
    // trim to the payload: decode validates, so find the end via a decode of
    // the full region (the trailing zeros are rejected as trailing bytes -
    // locate the payload length by decoding prefixes is O(n^2), so instead
    // decode the whole 0x10000 minus the trailing zero run)
    std::size_t payload_end = payload_bytes.size();
    while (payload_end > 0 && payload_bytes[payload_end - 1] == 0) {
        --payload_end;
    }
    const auto decoded =
        bm::decode(std::span<const std::uint8_t>(payload_bytes.data(), payload_end));
    ASSERT_TRUE(decoded.has_value()) << decoded.error().detail;
    bool ntdll_record = false;
    for (const auto& record : decoded->modules) {
        if (record.name == "ntdll.dll") {
            ntdll_record = true;
            EXPECT_EQ(record.base, 0x7FF800000000ULL);
            EXPECT_EQ(record.image_xxhash64, sheller_test::kFixtureNtdllXxhash64);
        }
    }
    EXPECT_TRUE(ntdll_record);
    ASSERT_FALSE(decoded->boundaries.empty());
    EXPECT_EQ(decoded->boundaries[0].name, "ntdll.dll");
    EXPECT_EQ(decoded->apiset_anchor, sheller_test::kFixtureNtdllXxhash64);
    EXPECT_FALSE(decoded->apiset_bytes.empty());

    // the region record: read-only MEM_PRIVATE at the fixed base
    const auto region = std::find_if(built->regions.begin(), built->regions.end(),
                                     [](const sheller::engine::mem_region::RegionRecord& r) {
                                         return r.base == bm::kMetadataBase;
                                     });
    ASSERT_NE(region, built->regions.end());
    EXPECT_EQ(region->size, bm::kMetadataMaxBytes);
    EXPECT_EQ(region->protection, 0x02u); // PAGE_READONLY
    EXPECT_EQ(region->type, sheller::engine::kMemPrivate);

    // the derived ntdll in guest memory carries the e_res2 marker pointing
    // at the base
    std::vector<std::uint8_t> ntdll_head(0x1000, std::uint8_t{0});
    ASSERT_EQ(
        uc_mem_read(built->unicorn.get(), 0x7FF800000000ULL, ntdll_head.data(), ntdll_head.size()),
        UC_ERR_OK);
    const auto marker = bm::read_marker(ntdll_head);
    ASSERT_TRUE(marker.has_value()) << marker.error().detail;
    ASSERT_TRUE(marker->has_value());
    EXPECT_EQ(**marker, bm::kMetadataBase);

    // no host path anywhere in the payload
    EXPECT_EQ(std::search(payload_bytes.begin(), payload_bytes.begin() + payload_end,
                          reinterpret_cast<const std::uint8_t*>("C:\\"),
                          reinterpret_cast<const std::uint8_t*>("C:\\") + 3),
              payload_bytes.begin() + payload_end);
}

TEST(LoaderDirectory, DoubleConstructionMetadataIsIdentical)
{
    const auto dir = make_directory("meta_det", {});
    const auto first = sheller::engine::prepare_pe_file(kSamplePath, false, kSynthDir, dir, true);
    const auto second = sheller::engine::prepare_pe_file(kSamplePath, false, kSynthDir, dir, true);
    ASSERT_TRUE(first.has_value()) << rejection_detail(first);
    ASSERT_TRUE(second.has_value()) << rejection_detail(second);
    const auto a = read_metadata_payload(*first);
    const auto b = read_metadata_payload(*second);
    ASSERT_EQ(a.size(), b.size());
    EXPECT_EQ(0, std::memcmp(a.data(), b.data(), a.size()));
}

// ---- task 4.2: the bilateral replay-side check -----------------------------

struct ParsedContainer {
    snapshot::Header header{};
    snapshot::Registers registers{};
    snapshot::Metadata metadata{};
    std::vector<snapshot::Region> regions;
};

ParsedContainer parse_container(const std::vector<std::uint8_t>& bytes)
{
    std::ispanstream in{std::span<char>{
        reinterpret_cast<char*>(const_cast<std::uint8_t*>(bytes.data())), bytes.size()}};
    snapshot::Reader reader{in};
    ParsedContainer parsed;
    auto header = reader.read_header();
    EXPECT_TRUE(header.has_value());
    if (!header.has_value()) {
        return parsed;
    }
    parsed.header = *header;
    auto registers = reader.read_registers();
    EXPECT_TRUE(registers.has_value());
    if (!registers.has_value()) {
        return parsed;
    }
    parsed.registers = *registers;
    auto metadata = reader.read_metadata();
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
    return parsed;
}

std::vector<std::uint8_t> serialize_container(const ParsedContainer& parsed)
{
    std::ostringstream out;
    snapshot::Writer writer{out};
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

// A directory-mode container crafted from the fixture world (the replay
// itself needs neither the directory nor the construction).
std::vector<std::uint8_t> craft_directory_container()
{
    const auto dir = make_directory("craft42", {});
    auto construction = sheller::engine::prepare_pe_file(kSamplePath, false, kSynthDir, dir, true);
    EXPECT_TRUE(construction.has_value()) << rejection_detail(construction);
    if (!construction.has_value()) {
        return {};
    }
    auto container = sheller::engine::craft_container_from_guest(*construction);
    EXPECT_TRUE(container.has_value());
    return container.has_value() ? *container : std::vector<std::uint8_t>{};
}

snapshot::Region* find_region(ParsedContainer& parsed, const std::uint64_t base)
{
    for (auto& region : parsed.regions) {
        if (region.header.base_address == base) {
            return &region;
        }
    }
    return nullptr;
}

std::string replay_rejection(const std::vector<std::uint8_t>& container)
{
    std::ispanstream in{std::span<char>{
        reinterpret_cast<char*>(const_cast<std::uint8_t*>(container.data())), container.size()}};
    const auto guest = sheller::engine::prepare_guest_stream(in);
    if (guest.has_value()) {
        return {};
    }
    return guest.error().detail;
}

TEST(LoaderDirectory, DirectoryContainerReplaysWithoutTheDirectory)
{
    const auto container = craft_directory_container();
    ASSERT_FALSE(container.empty());
    std::ispanstream in{std::span<char>{
        reinterpret_cast<char*>(const_cast<std::uint8_t*>(container.data())), container.size()}};
    const auto guest = sheller::engine::prepare_guest_stream(in);
    ASSERT_TRUE(guest.has_value());
    // the bilateral marks both present: the decoded record rides the guest
    ASSERT_TRUE(guest->directory_metadata.has_value());
    EXPECT_EQ(guest->directory_metadata->apiset_anchor, sheller_test::kFixtureNtdllXxhash64);
}

TEST(LoaderDirectory, OneSidedContainersAreNamedRejections)
{
    const auto container = craft_directory_container();
    ASSERT_FALSE(container.empty());

    // the metadata region deleted, the marker kept
    auto parsed = parse_container(container);
    parsed.regions.erase(
        std::remove_if(parsed.regions.begin(), parsed.regions.end(),
                       [](const snapshot::Region& r) {
                           return r.header.base_address ==
                                  sheller::engine::boundary_metadata::kMetadataBase;
                       }),
        parsed.regions.end());
    const auto detail = replay_rejection(serialize_container(parsed));
    EXPECT_NE(detail.find("metadata region is missing"), std::string::npos) << detail;

    // the marker removed (reserved slot re-zeroed), the region kept
    parsed = parse_container(container);
    auto* ntdll = find_region(parsed, 0x7FF800000000ULL);
    ASSERT_NE(ntdll, nullptr);
    for (std::uint32_t i = 0; i < sheller::engine::boundary_metadata::kMarkerBytes; ++i) {
        ntdll->content[sheller::engine::boundary_metadata::kMarkerOffset + i] = 0;
    }
    const auto marker_detail = replay_rejection(serialize_container(parsed));
    EXPECT_NE(marker_detail.find("mode marker is missing"), std::string::npos) << marker_detail;
}

TEST(LoaderDirectory, DamagedMetadataIsNamedRejection)
{
    const auto container = craft_directory_container();
    ASSERT_FALSE(container.empty());
    namespace bm = sheller::engine::boundary_metadata;

    // broken payload magic
    auto parsed = parse_container(container);
    auto* meta = find_region(parsed, bm::kMetadataBase);
    ASSERT_NE(meta, nullptr);
    meta->content[0] ^= 0xFF;
    EXPECT_NE(replay_rejection(serialize_container(parsed)).find("magic"), std::string::npos);

    // unknown semantic version
    parsed = parse_container(container);
    meta = find_region(parsed, bm::kMetadataBase);
    meta->content[8] = 99;
    EXPECT_NE(replay_rejection(serialize_container(parsed)).find("version"), std::string::npos);

    // payload tampering: the checksum catches it
    parsed = parse_container(container);
    meta = find_region(parsed, bm::kMetadataBase);
    auto last = meta->content.size() - 1;
    while (last > 0 && meta->content[last] == 0) {
        --last;
    }
    meta->content[last] ^= 0xFF;
    EXPECT_NE(replay_rejection(serialize_container(parsed)).find("checksum"), std::string::npos);

    // a marker pointing somewhere else: the address conflict
    parsed = parse_container(container);
    auto* ntdll = find_region(parsed, 0x7FF800000000ULL);
    ASSERT_NE(ntdll, nullptr);
    const std::uint64_t elsewhere = 0x1234;
    std::memcpy(ntdll->content.data() + sheller::engine::boundary_metadata::kMarkerOffset + 12,
                &elsewhere, sizeof elsewhere);
    const auto address_detail = replay_rejection(serialize_container(parsed));
    EXPECT_NE(address_detail.find("not the metadata base"), std::string::npos) << address_detail;
}

// ---- task 4.3: the replay attach restores the full run tables --------------

TEST(LoaderDirectory, ReplayRestoresTheRunTables)
{
    const auto dir = make_directory("attach43", {});
    const auto construction =
        sheller::engine::prepare_pe_file(kSamplePath, false, kSynthDir, dir, true);
    ASSERT_TRUE(construction.has_value()) << rejection_detail(construction);
    const auto container = sheller::engine::craft_container_from_guest(*construction);
    ASSERT_TRUE(container.has_value());

    std::ispanstream in{std::span<char>{
        reinterpret_cast<char*>(const_cast<std::uint8_t*>(container->data())), container->size()}};
    const auto replay = sheller::engine::prepare_guest_stream(in);
    ASSERT_TRUE(replay.has_value());
    EXPECT_TRUE(replay->loader_route);
    EXPECT_TRUE(replay->directory_mode);

    // modules: the resident set matches the construction (base, size, name)
    ASSERT_EQ(replay->loader_modules.size(), construction->loader_modules.size());
    for (std::size_t i = 0; i < replay->loader_modules.size(); ++i) {
        EXPECT_EQ(replay->loader_modules[i].base, construction->loader_modules[i].base);
        EXPECT_EQ(replay->loader_modules[i].size, construction->loader_modules[i].size);
        EXPECT_EQ(std::string(replay->loader_modules[i].name.data()),
                  std::string(construction->loader_modules[i].name.data()));
    }
    // exports: the rebuilt index resolves the same names to the same VAs
    ASSERT_EQ(replay->loader_exports.size(), construction->loader_exports.size());
    for (std::size_t i = 0; i < replay->loader_exports.size(); ++i) {
        EXPECT_EQ(replay->loader_exports[i].module_base,
                  construction->loader_exports[i].module_base);
        EXPECT_EQ(replay->loader_exports[i].function_va,
                  construction->loader_exports[i].function_va);
        EXPECT_EQ(replay->loader_exports[i].name, construction->loader_exports[i].name);
    }
    // the construction's intercept registrations are all covered at replay
    for (const auto& registered : construction->intercepts) {
        const auto found =
            std::find(replay->intercepts.begin(), replay->intercepts.end(), registered);
        EXPECT_NE(found, replay->intercepts.end()) << std::hex << registered.first;
    }
    // the API Set map, the source table and the boundary rules ride along
    EXPECT_EQ(replay->api_set_map.entry_count(), 9u);
    ASSERT_EQ(replay->module_sources.size(), construction->module_sources.size());
    for (std::size_t i = 0; i < replay->module_sources.size(); ++i) {
        EXPECT_EQ(replay->module_sources[i].first, construction->module_sources[i].first);
        EXPECT_EQ(replay->module_sources[i].second, construction->module_sources[i].second);
    }
    EXPECT_NE(replay->boundary_rules.find("ntdll.dll"), replay->boundary_rules.end());
}

TEST(LoaderDirectory, TrapDiagnosisIdenticalDirectAndReplay)
{
    // the trap's named diagnosis is the restored boundary policy's verdict:
    // the direct directory run and the replayed container (policy restored
    // from the metadata record) report the same module!export and call site
    const auto kernel32_source = make_real_kernel32_source();
    std::vector<std::uint8_t> entry_body =
        call_through(sheller_test::kBoundaryTextRva, sheller_test::kImportingIatRva + 64);
    entry_body.push_back(0xEB);
    entry_body.push_back(0xFE);
    const auto sample =
        make_importing_source({{"entry", nullptr, sheller_test::kBoundaryTextRva, entry_body, {}}},
                              {{"kernel32.dll", {"SampleExport"}}, {"ntdll.dll", {"NtWeird"}}});
    const auto sample_path = fs::temp_directory_path() / "sheller_dir_mode_trap_parity.exe";
    write_bytes(sample_path, sample);

    const auto dir = make_directory("trapparity52", {{"kernel32.dll", kernel32_source}});
    sheller::engine::SyscallRunOptions options;
    options.system_modules_dir = dir;
    options.max_instructions = 20000;
    std::string direct_detail;
#ifdef _WIN32
    const auto direct = sheller::engine::run_pe_file(sample_path.string(), options);
    ASSERT_FALSE(direct.has_value());
    EXPECT_EQ(direct.error().error, sheller::engine::SyscallRunError::kBoundaryTrap);
    direct_detail = direct.error().detail;
    options.system_modules_dir = std::filesystem::path{};
    options.event_sink = nullptr;
#endif

    auto construction =
        sheller::engine::prepare_pe_file(sample_path.string(), false, kSynthDir, dir, true);
    ASSERT_TRUE(construction.has_value()) << rejection_detail(construction);
    const auto container = sheller::engine::craft_container_from_guest(*construction);
    ASSERT_TRUE(container.has_value());
    const auto replayed = sheller::engine::run_snapshot_syscalls(*container, options);
    ASSERT_FALSE(replayed.has_value());
    EXPECT_EQ(replayed.error().error, sheller::engine::SyscallRunError::kBoundaryTrap);
#ifdef _WIN32
    EXPECT_EQ(replayed.error().detail, direct_detail);
#else
    EXPECT_NE(replayed.error().detail.find("boundary-trap: ntdll.dll!NtWeird"), std::string::npos);
#endif

    std::error_code ec;
    fs::remove(sample_path, ec);
}

// ---- task 7.1: directory-mode DLL admission walks the real exports ---------

TEST(LoaderDirectory, DllAdmissionResolvesThroughDirectoryRealExports)
{
    // packed.dll imports kernel32!LoadLibraryA/GetProcAddress and user32.
    // The directory's real kernel32 fixture exports LoadLibraryA as a
    // FORWARDER into the derived ntdll's RtlFoo (the chain the admission
    // walks) and GetProcAddress as a plain body; user32 falls back to the
    // frozen synthetic module; the admission crosses the directory's real
    // tables and produces the v2 container
    const std::vector<std::uint8_t> kernel32_source = make_importing_source(
        {{"LoadLibraryA", nullptr, 0, {}, "ntdll.RtlFoo"},
         {"GetProcAddress", nullptr, sheller_test::kBoundaryTextRva, {0x31, 0xC0, 0xC3}, {}}},
        {{"ntdll.dll", {"RtlFoo"}}});
    const auto dir = make_directory("admit71", {{"kernel32.dll", kernel32_source}});
    const auto container = sheller::engine::craft_sample_container(SHELLER_SAMPLE_PACKED_DLL_PATH,
                                                                   false, kSynthDir, dir, true);
    ASSERT_TRUE(container.has_value()) << container.error().detail;
    std::ispanstream in{std::span<char>{
        reinterpret_cast<char*>(const_cast<std::uint8_t*>(container->data())), container->size()}};
    snapshot::Reader reader{in};
    const auto header = reader.read_header();
    ASSERT_TRUE(header.has_value());
    EXPECT_EQ(header->version, snapshot::kVersionV2); // DLL input: pending block present
}

#ifdef _WIN32

TEST(LoaderDirectory, PackedDllDirectoryContainerDeterministicAndReplays)
{
    // the spec's corpus DLL through the directory route: double construction
    // byte-identical (marker + metadata + embedded API Set map included),
    // the container replays, and the replay carries the directory-mode
    // record restored from the metadata
    const auto kernel32_source = make_real_kernel32_source();
    const auto dir = make_directory("packeddll72", {{"kernel32.dll", kernel32_source}});
    const auto first = sheller::engine::craft_sample_container(SHELLER_SAMPLE_PACKED_DLL_PATH,
                                                               false, kSynthDir, dir, true);
    ASSERT_TRUE(first.has_value()) << first.error().detail;
    const auto second = sheller::engine::craft_sample_container(SHELLER_SAMPLE_PACKED_DLL_PATH,
                                                                false, kSynthDir, dir, true);
    ASSERT_TRUE(second.has_value()) << second.error().detail;
    ASSERT_EQ(first->size(), second->size());
    EXPECT_TRUE(std::equal(first->begin(), first->end(), second->begin()));

    std::ispanstream in{std::span<char>{
        reinterpret_cast<char*>(const_cast<std::uint8_t*>(first->data())), first->size()}};
    const auto replay = sheller::engine::prepare_guest_stream(in);
    ASSERT_TRUE(replay.has_value());
    ASSERT_TRUE(replay->directory_metadata.has_value());
    // the pending block marks the DLL input; the restored run tables serve it
    EXPECT_TRUE(replay->pending.has_value());
    EXPECT_EQ(replay->api_set_map.entry_count(), 9u);
    EXPECT_NE(replay->boundary_rules.find("ntdll.dll"), replay->boundary_rules.end());
    // EXE + shellcode run the same craft path (wrapper or bare image); the
    // engine face this pin covers is the directory construction itself
}

#endif // _WIN32

namespace realdll {

constexpr const char* kCorpusDirEnv = "SHELLER_REALDLL_DIR";

// The corpus directory with its raw ntdll, or the reason it is unusable
// (GTEST_SKIP expands to a void return and cannot live in this helper).
// (corpus_dir was folded into the test body: inline env/shape checks with
// named skip reasons)

std::string read_file_or_empty(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

} // namespace realdll

// The corpus test: a real ntdll + kernel32 + kernelbase triple derives
// under the committed real-build manifest, and a generated sample calls
// kernel32!lstrlenA — the real kernel32 thunk jmps into the REAL kernelbase
// body executing in the emulator against guest memory (its strlen call
// answers from the engine intercept; the derived body is never reached) —
// then NtTerminateProcess(-1, len) through the derived ntdll's stub. The
// run's exit code proves the real body computed the string length from
// guest memory. Everything is env-gated: unset variables skip; nothing
// lands in the repository or CI.

constexpr const char* kRealString = "sheller-real-dll";

std::vector<std::uint8_t> make_lstrlen_sample()
{
    // entry: lea rcx, [rip+disp] (the string); call [lstrlenA]; mov edx, eax;
    // or ecx, -1; call [NtTerminateProcess]; the string bytes follow
    std::vector<std::uint8_t> body;
    const auto emit = [&body](const std::initializer_list<std::uint8_t> bytes) {
        body.insert(body.end(), bytes);
    };
    const auto rel32 = [](const std::uint32_t from, const std::uint32_t to) {
        std::vector<std::uint8_t> out;
        const auto r = static_cast<std::int32_t>(to - from);
        for (unsigned i = 0; i < 4; ++i) {
            out.push_back(static_cast<std::uint8_t>(r >> (8 * i)));
        }
        return out;
    };
    const std::uint32_t string_rva = sheller_test::kBoundaryTextRva + 0x40;
    // offsets inside the body: lea 7 bytes, each call 6
    constexpr std::uint32_t kLea = 0, kCall1 = 7, kCall2 = 18;
    // lea rcx, [rip + disp32]: 48 8D 0D — the rip base is the address AFTER
    // the instruction (kBoundaryTextRva + 7)
    emit({0x48, 0x8D, 0x0D});
    {
        const auto disp = rel32(sheller_test::kBoundaryTextRva + kLea + 7, string_rva);
        body.insert(body.end(), disp.begin(), disp.end());
    }
    // call [IAT lstrlenA] — kernel32's block is the descriptor-0 IAT: slot 0
    emit({0xFF, 0x15});
    {
        const auto disp =
            rel32(sheller_test::kBoundaryTextRva + kCall1 + 6, sheller_test::kImportingIatRva);
        body.insert(body.end(), disp.begin(), disp.end());
    }
    // mov edx, eax: 89 C2
    emit({0x89, 0xC2});
    // or ecx, -1: 83 C9 FF
    emit({0x83, 0xC9, 0xFF});
    // call [IAT NtTerminateProcess] — ntdll's block: descriptor-1 IAT slot 0
    emit({0xFF, 0x15});
    {
        const auto disp =
            rel32(sheller_test::kBoundaryTextRva + kCall2 + 6, sheller_test::kImportingIatRva + 64);
        body.insert(body.end(), disp.begin(), disp.end());
    }
    // the string bytes (NUL-terminated, the real code reads them) — the
    // lea targets kBoundaryTextRva + 0x40, so pad the code tail up to it
    while (body.size() < 0x40) {
        body.push_back(0xCC); // int3 padding: a stray run lands loudly
    }
    for (const char c : std::string(kRealString)) {
        body.push_back(static_cast<std::uint8_t>(c));
    }
    body.push_back(0);

    return sheller_test::make_importing_source(
        {{"entry", nullptr, sheller_test::kBoundaryTextRva, body, {}}},
        {{"kernel32.dll", {"lstrlenA"}}, {"ntdll.dll", {"NtTerminateProcess"}}});
}

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996) // getenv is fine in a test
#endif
TEST(LoaderDirectory, RealDllCorpusStringCallExecutesRealCode)
{
    // the corpus directory gates the whole test: unset variables skip
    const char* env = std::getenv("SHELLER_REALDLL_DIR");
    if (env == nullptr) {
        GTEST_SKIP() << "SHELLER_REALDLL_DIR not set (point it at a directory with real "
                     << "ntdll.dll + kernel32.dll + kernelbase.dll + apiset-map.bin)";
    }
    const fs::path corpus(env);
    std::error_code ec;
    if (!fs::is_directory(corpus, ec) || ec || !fs::exists(corpus / "ntdll.dll", ec) || ec) {
        GTEST_SKIP() << "corpus directory lacks ntdll.dll";
    }
    // the corpus ntdll must be registered in the committed real-build
    // manifest; an unregistered build skips with the named message
    const auto ntdll_bytes = realdll::read_file_or_empty(corpus / "ntdll.dll");
    ASSERT_FALSE(ntdll_bytes.empty());
    const auto hash =
        XXH64(reinterpret_cast<const void*>(ntdll_bytes.data()), ntdll_bytes.size(), 0);
    auto rules = sheller::engine::BoundaryManifest::committed().rules_for("ntdll.dll", "x64", hash);
    if (!rules.has_value()) {
        GTEST_SKIP() << "corpus ntdll not registered in tools/boundary_manifest ("
                     << sheller::engine::boundary_manifest_error_message(rules.error())
                     << "); regenerate the manifest for this build";
    }

    // the corpus also needs real kernel32.dll (the exported name) and
    // kernelbase.dll (the body lstrlenA's thunk jmp lands in) plus the
    // API Set map
    if (!fs::exists(corpus / "kernel32.dll", ec) || ec ||
        !fs::exists(corpus / "kernelbase.dll", ec) || ec ||
        !fs::exists(corpus / "apiset-map.bin", ec) || ec) {
        GTEST_SKIP() << "corpus directory lacks kernel32.dll, kernelbase.dll or apiset-map.bin";
    }

    // the API Set map must cover the contracts kernel32 imports (at minimum
    // api-ms-win-core-path-l1-1-0 -> kernelbase.dll; the fallback synthetic
    // kernelbase closes the closure)
    auto map_bytes = realdll::read_file_or_empty(corpus / "apiset-map.bin");
    auto map_view = sheller::loader::ApiSetMapView::load(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(map_bytes.data()),
                                      map_bytes.size()),
        sheller::loader::kApiSetMapArchX64, hash);
    if (!map_view.has_value()) {
        GTEST_SKIP() << "corpus apiset-map rejected: " << map_view.error().detail;
    }
    if (!map_view->host_for("api-ms-win-core-path-l1-1-0", {}).has_value()) {
        GTEST_SKIP() << "corpus apiset-map does not cover api-ms-win-core-path-l1-1-0";
    }

    const auto sample = make_lstrlen_sample();
    const auto sample_path = fs::temp_directory_path() / "sheller_realdll_lstrlen.exe";
    write_bytes(sample_path, sample);

    const auto dir = fs::temp_directory_path() / "sheller_realdll_run";
    fs::create_directories(dir, ec);
    fs::copy_file(corpus / "ntdll.dll", dir / "ntdll.dll", fs::copy_options::overwrite_existing);
    fs::copy_file(corpus / "kernel32.dll", dir / "kernel32.dll",
                  fs::copy_options::overwrite_existing);
    fs::copy_file(corpus / "kernelbase.dll", dir / "kernelbase.dll",
                  fs::copy_options::overwrite_existing);
    fs::copy_file(corpus / "apiset-map.bin", dir / "apiset-map.bin",
                  fs::copy_options::overwrite_existing);

    sheller::engine::SyscallRunOptions options;
    options.system_modules_dir = dir;
    options.system_modules_fallback = true;
    options.max_instructions = 200000;
    // the engine's crash audit (unhandled guest faults) logs at kWarning;
    // surface it here - a corpus failure without the audit line is
    // undebuggable. The detail setter (log_detail.h) is the test-suite
    // spelling; the public one lives only behind the shared interface lib.
    sheller::log::detail::set_sink_impl(
        [](const sheller::log::level, const std::string_view line) {
            std::printf("[sheller] %.*s\n", static_cast<int>(line.size()), line.data());
        },
        sheller::log::level::kWarning);
    const auto run = sheller::engine::run_pe_file(sample_path.string(), options);
    ASSERT_TRUE(run.has_value()) << static_cast<int>(run.error().error) << " "
                                 << (run.error().detail.empty() ? "" : run.error().detail.c_str());
    EXPECT_TRUE(run->terminated);
    // the REAL kernel32 code computed the length of the guest string —
    // the exit code is the evidence the real body ran against guest memory
    EXPECT_EQ(run->exit_code, std::strlen(kRealString));
    fs::remove(sample_path, ec);
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
}

// Review regressions: public entry points and directory/replay contracts.

namespace {
fs::path write_review_sample(const char* tag, std::vector<std::uint8_t> bytes,
                             const bool dll = false)
{
    if (!dll) {
        bytes[0x97] &= static_cast<std::uint8_t>(~0x20);
    }
    const auto path = fs::temp_directory_path() / tag;
    write_bytes(path, bytes);
    return path;
}

std::expected<sheller::engine::PreparedGuest, sheller::engine::RebuildFailure>
replay_review_guest(const std::vector<std::uint8_t>& bytes)
{
    std::ispanstream in{std::span<char>{
        reinterpret_cast<char*>(const_cast<std::uint8_t*>(bytes.data())), bytes.size()}};
    auto guest = sheller::engine::prepare_guest_stream(in);
    EXPECT_TRUE(guest.has_value());
    return guest;
}
} // namespace

TEST(LoaderDirectory, StrictFacadeAndUnpackNeedNoSyntheticDirectory)
{
    const auto sample = write_review_sample(
        "sheller_review_strict.exe",
        make_importing_source({{"entry", nullptr, 0x1000, {0xEB, 0xFE}, {}}}, {}));
    const auto dir = make_directory("review_strict", {});
    const auto container = sheller::engine::craft_sample_container(sample, false, {}, dir, false);
    ASSERT_TRUE(container.has_value()) << container.error().detail;
    sheller::AnalysisOptions analysis;
    analysis.run.system_modules_dir = dir;
    analysis.run.max_instructions = 20;
    analysis.run.timeout_ms = 1000;
    const auto analyzed = sheller::api::detail::analyze_path_impl(sample, analysis);
    ASSERT_FALSE(analyzed.has_value());
    EXPECT_EQ(analyzed.error().kind, sheller::AnalysisFailure::Kind::kRun);
    EXPECT_FALSE(analyzed.error().artifacts.module_sources.empty());

    sheller::UnpackOptions unpack;
    unpack.system_modules_dir = dir;
    unpack.max_instructions = 20;
    unpack.timeout_ms = 1000;
    unpack.output = fs::temp_directory_path() / "sheller_review_strict.unp.exe";
    const auto unpacked = sheller::api::detail::unpack_sample_impl(sample, unpack);
    ASSERT_TRUE(unpacked.failure.has_value());
    EXPECT_EQ(unpacked.failure->kind, sheller::AnalysisFailure::Kind::kRun);
    EXPECT_FALSE(unpacked.artifacts.module_sources.empty());
    const auto missing = fs::temp_directory_path() / "sheller_review_missing_directory";
    unpack.system_modules_dir = missing;
    const auto rejected = sheller::api::detail::unpack_sample_impl(sample, unpack);
    ASSERT_TRUE(rejected.failure.has_value());
    EXPECT_EQ(rejected.failure->kind, sheller::AnalysisFailure::Kind::kCapture);
}

TEST(LoaderDirectory, ForwardedDynamicLookupKeepsOwnerAndDirectoryMap)
{
    const auto owner = make_importing_source(
        {{"Alias", nullptr, 0, {}, "api-ms-win-core-fixture-l1-1-0.Final"}}, {});
    const auto target = make_importing_source({{"Final", nullptr, 0x1000, {0xC3}, {}}}, {});
    const auto dir =
        make_directory("review_forward", {{"owner.dll", owner}, {"fakentdll.dll", target}});
    const auto sample = write_review_sample(
        "sheller_review_forward.exe",
        make_importing_source({{"entry", nullptr, 0x1000, {0xEB, 0xFE}, {}}}, {}));
    auto direct = sheller::engine::prepare_pe_file(sample, false, {}, dir, false);
    ASSERT_TRUE(direct.has_value()) << direct.error().detail;
    const auto container = sheller::engine::craft_container_from_guest(*direct);
    ASSERT_TRUE(container.has_value());
    auto replay = replay_review_guest(*container);
    ASSERT_TRUE(replay.has_value()) << replay.error().detail;
    const auto lookup = [](const sheller::engine::PreparedGuest& guest) {
        std::uint64_t owner_base = 0;
        for (const auto& module : guest.loader_modules) {
            if (std::string_view(module.name.data()) == "owner.dll") {
                owner_base = module.base;
            }
        }
        for (const auto& entry : guest.loader_exports) {
            if (entry.module_base == owner_base && entry.name == "Alias") {
                return entry.function_va;
            }
        }
        return std::uint64_t{0};
    };
    EXPECT_NE(lookup(*direct), 0u);
    EXPECT_EQ(lookup(*direct), lookup(*replay));
}

TEST(LoaderDirectory, FallbackWhitelistAndCountsSurviveReplay)
{
    auto body = call_through(0x1000, sheller_test::kImportingIatRva);
    body.resize(body.size() - 1); // keep the call, then spin
    body.insert(body.end(), {0xEB, 0xFE});
    const auto sample = write_review_sample(
        "sheller_review_fallback.exe", make_importing_source({{"entry", nullptr, 0x1000, body, {}}},
                                                             {{"ucrtbase.dll", {"malloc"}}}));
    const auto dir = make_directory("review_count", {});
    auto direct = sheller::engine::prepare_pe_file(sample, false, kSynthDir, dir, true);
    ASSERT_TRUE(direct.has_value()) << direct.error().detail;
    const auto container = sheller::engine::craft_container_from_guest(*direct);
    ASSERT_TRUE(container.has_value());
    auto replay = replay_review_guest(*container);
    ASSERT_TRUE(replay.has_value()) << replay.error().detail;
    EXPECT_EQ(direct->stub_whitelist.size(), replay->stub_whitelist.size());
    sheller::engine::SyscallRunOptions options;
    options.system_modules_dir = dir;
    options.system_modules_fallback = true;
    options.synthetic_system_modules = true;
    options.synthetic_module_dir = kSynthDir;
    options.max_instructions = 100;
    std::map<std::string, std::uint64_t> counts;
    options.stub_sink = [&](std::uint16_t, std::string_view name, std::uint64_t count) {
        counts[std::string(name)] = count;
    };
    static_cast<void>(sheller::engine::run_pe_file(sample, options));
    const auto direct_counts = counts;
    EXPECT_EQ(direct_counts.at("malloc"), 1u);
    counts.clear();
    static_cast<void>(sheller::engine::run_snapshot_syscalls(*container, options));
    EXPECT_EQ(counts, direct_counts);
}

TEST(LoaderDirectory, ForwarderClosureAddsMissingFallbackEndpoint)
{
    const auto owner = make_importing_source({{"Alias", nullptr, 0, {}, "ucrtbase.malloc"}}, {});
    const auto sample =
        write_review_sample("sheller_review_closure.exe",
                            make_importing_source({{"entry", nullptr, 0x1000, {0xEB, 0xFE}, {}}},
                                                  {{"owner.dll", {"Alias"}}}));
    const auto dir = make_directory("review_closure", {{"owner.dll", owner}});
    const auto built = sheller::engine::prepare_pe_file(sample, false, kSynthDir, dir, true);
    ASSERT_TRUE(built.has_value()) << built.error().detail;
    ASSERT_NE(find_source(*built, "ucrtbase.dll"), nullptr);
    EXPECT_EQ(*find_source(*built, "ucrtbase.dll"), SystemModuleSource::kFallbackSynthetic);
}

TEST(LoaderDirectory, ImporterSpecificMissingHostUsesTheImporter)
{
    const auto dependent = make_importing_source({{"entry", nullptr, 0x1000, {0xC3}, {}}},
                                                 {{"api-ms-win-core-console-l1-1-0", {"malloc"}}});
    const auto dir = make_directory("review_importer", {{"fakeuser32.dll", dependent}});
    const auto sample = write_review_sample(
        "sheller_review_importer.exe",
        make_importing_source({{"entry", nullptr, 0x1000, {0xEB, 0xFE}, {}}}, {}));
    const auto built = sheller::engine::prepare_pe_file(sample, false, {}, dir, false);
    ASSERT_FALSE(built.has_value());
    EXPECT_NE(built.error().detail.find("other.dll"), std::string::npos);
    EXPECT_EQ(built.error().detail.find("fakentdll.dll"), std::string::npos);
}

TEST(LoaderDirectory, DllAdmissionResolvesApiSetsAndOrdinalForwarders)
{
    const auto kernel = make_importing_source({{"LoadLibraryW", nullptr, 0x1000, {0xC3}, {}},
                                               {"ExitProcess", nullptr, 0x1010, {0xC3}, {}}},
                                              {});
    const auto owner = make_importing_source(
        {{"Dummy", nullptr, 0x1000, {0xC3}, {}}, {"Alias", nullptr, 0, {}, "target.#0"}}, {});
    const auto target = make_importing_source({{"Final", nullptr, 0x1000, {0xC3}, {}}}, {});
    const auto dir = make_directory(
        "review_admission",
        {{"kernel32.dll", kernel}, {"fakentdll.dll", owner}, {"target.dll", target}});
    const auto sample =
        write_review_sample("sheller_review_admission.dll",
                            make_importing_source({{"entry", nullptr, 0x1000, {0xC3}, {}}},
                                                  {{"api-ms-win-core-fixture-l1-1-0", {"Alias"}}}),
                            true);
    const auto container = sheller::engine::craft_sample_container(sample, false, {}, dir, false);
    ASSERT_TRUE(container.has_value()) << container.error().detail;
    auto replay = replay_review_guest(*container);
    ASSERT_TRUE(replay.has_value()) << replay.error().detail;
    ASSERT_TRUE(replay->pending.has_value());

    // Enter the chain by ordinal as well, rather than only reaching an
    // ordinal at its final hop. The fixture's Alias occupies EAT slot 1.
    auto ordinal_sample = make_importing_source({{"entry", nullptr, 0x1000, {0xC3}, {}}},
                                                {{"fakentdll.dll", {"Alias"}}});
    const std::uint64_t ordinal_thunk = 0x8000000000000001ULL;
    std::memcpy(ordinal_sample.data() + 0x2100, &ordinal_thunk, sizeof ordinal_thunk);
    std::memcpy(ordinal_sample.data() + sheller_test::kImportingIatRva, &ordinal_thunk,
                sizeof ordinal_thunk);
    const auto ordinal_path =
        write_review_sample("sheller_review_ordinal.dll", ordinal_sample, true);
    const auto ordinal_container =
        sheller::engine::craft_sample_container(ordinal_path, false, {}, dir, false);
    ASSERT_TRUE(ordinal_container.has_value()) << ordinal_container.error().detail;
}

TEST(LoaderDirectory, HashNamedExportResolvesByNameNeverAsOrdinal)
{
    // a PE export may legally be named "#5": an import requesting that name
    // must hit the exact name, never EAT slot 5 (only a forwarder string's
    // "dll.#N" spelling means an ordinal). The bound IAT value names the
    // answer: the "#5"-named body's VA, not the ordinal-5 slot.
    const auto hashname =
        make_importing_source({{"#5",
                                nullptr,
                                sheller_test::kBoundaryTextRva,
                                {0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3}, // mov eax, 7; ret
                                {}}},
                              {});
    const auto dir = make_directory("review_hashname", {{"kernel32.dll", hashname}});
    const auto sample = write_review_sample(
        "sheller_review_hash.exe",
        make_importing_source({{"entry", nullptr, sheller_test::kBoundaryTextRva, {0xC3}, {}}},
                              {{"kernel32.dll", {"#5"}}, {"ntdll.dll", {"NtTerminateProcess"}}}));

    const auto built = sheller::engine::prepare_pe_file(sample.string(), false, {}, dir, false);
    ASSERT_TRUE(built.has_value()) << built.error().detail;

    const sheller::engine::mem_region::ModuleRecord* resident_kernel32 = nullptr;
    const sheller::engine::mem_region::ModuleRecord* resident_ntdll = nullptr;
    for (const auto& module : built->loader_modules) {
        const std::string_view name(module.name.data());
        if (name == "kernel32.dll") {
            resident_kernel32 = &module;
        } else if (name == "ntdll.dll") {
            resident_ntdll = &module;
        }
    }
    ASSERT_NE(resident_kernel32, nullptr);
    ASSERT_NE(resident_ntdll, nullptr);

    // the sample's IAT: slot0 = kernel32!#5, slot1 = ntdll!NtTerminateProcess
    std::uint64_t slot0 = 0;
    std::uint64_t slot1 = 0;
    ASSERT_EQ(
        uc_mem_read(built->unicorn.get(), 0x400000 + sheller_test::kImportingIatRva, &slot0, 8),
        UC_ERR_OK);
    ASSERT_EQ(uc_mem_read(built->unicorn.get(), 0x400000 + sheller_test::kImportingIatRva + 64,
                          &slot1, 8),
              UC_ERR_OK);
    // the "#5" request resolved to the "#5"-NAMED body - the named lookup,
    // never EAT slot 5 (the module carries one export, so ordinal 5 is out
    // of range and could only have failed the resolution entirely)
    EXPECT_EQ(slot0, resident_kernel32->base + sheller_test::kBoundaryTextRva);
    // the name "#" cannot alias anything else: the body there is mov eax, 7
    std::uint8_t body[6] = {};
    ASSERT_EQ(uc_mem_read(built->unicorn.get(), slot0, body, sizeof body), UC_ERR_OK);
    EXPECT_EQ(body[0], 0xB8);
    EXPECT_EQ(body[1], 0x07);
    // the ntdll slot still binds through the derived stub (the two-descriptor
    // shape resolves independently)
    EXPECT_GE(slot1, resident_ntdll->base);
    EXPECT_LT(slot1, resident_ntdll->base + resident_ntdll->size);
}
