// API Set map (change real-dll-module-dir, task 2.3): the offline generator
// is deterministic (same JSON in, byte-identical .bin out), the bounded
// reader rejects magic/version/architecture/anchor/range defects and
// conflicting entries by name, and the explicit API-set context resolves
// directory maps without the synthetic prefix fallbacks while the
// synthetic route stays byte-for-byte unchanged. Portable by design.

#include "boundary_fixture.h"

#include "apiset_map.h"
#include "imports.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

namespace {

using namespace sheller::loader;
using sheller_test::boundary_fixture_exports;
using sheller_test::boundary_fixture_rules;
using sheller_test::kFixtureNtdllXxhash64;
using sheller_test::make_boundary_source;
using BoundaryExport = sheller_test::BoundaryFixtureExport;

constexpr const char* kGenScript = APISET_GEN_SCRIPT;
constexpr const char* kSourceJson = APISET_SOURCE_JSON;
constexpr const char* kPython = APISET_PYTHON;

std::vector<std::uint8_t> read_file(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

int run_generator(const fs::path& out_file)
{
    const std::string cmd = std::string(kPython) + " \"" + kGenScript + "\" \"" + kSourceJson +
                            "\" \"" + out_file.string() + "\"";
    return std::system(cmd.c_str());
}

// A minimal resident module view: the derived fixture ntdll plus one other
// module hosting a named export.
struct WorldModules {
    std::vector<LoadedModule> modules;

    explicit WorldModules(const std::vector<std::uint8_t>& derived_ntdll)
    {
        modules.resize(2);
        modules[0].base = 0x7FF800000000ULL;
        modules[0].image = derived_ntdll;
        std::memcpy(modules[0].name.data(), "fakentdll.dll", 13);
        modules[1].base = 0x7FF900000000ULL;
        // the second host module comes from the fixture builder too (one
        // export, xor eax,eax; ret) so its image carries real PE headers
        const auto source = make_boundary_source(std::vector<BoundaryExport>{
            {"FakeExport", nullptr, sheller_test::kBoundaryInterceptRva, {0x31, 0xC0, 0xC3}, {}}});
        const auto info = parse_pe(source);
        auto image = build_image(source, *info);
        modules[1].image = std::move(*image);
        std::memcpy(modules[1].name.data(), "other.dll", 9);
        static_cast<void>(index_exports(modules[0]));
        static_cast<void>(index_exports(modules[1]));
    }
};

} // namespace

TEST(ApiSetMap, GenerationIsDeterministic)
{
    const auto dir = fs::temp_directory_path() / "sheller_apiset_det";
    fs::create_directories(dir);
    ASSERT_EQ(run_generator(dir / "a.bin"), 0);
    ASSERT_EQ(run_generator(dir / "b.bin"), 0);
    const auto a = read_file(dir / "a.bin");
    const auto b = read_file(dir / "b.bin");
    ASSERT_FALSE(a.empty());
    EXPECT_EQ(a, b);
}

TEST(ApiSetMap, ReaderRejectsDefectsByName)
{
    const auto dir = fs::temp_directory_path() / "sheller_apiset_det";
    auto bytes = read_file(dir / "a.bin");
    ASSERT_FALSE(bytes.empty());

    // the good case: the map loads against its anchor
    auto good = ApiSetMapView::load(bytes, kApiSetMapArchX64, kFixtureNtdllXxhash64);
    ASSERT_TRUE(good.has_value()) << good.error().detail;
    EXPECT_EQ(good->entry_count(), 9u);

    // wrong anchor: the directory's ntdll is not the map's anchor
    const auto anchor = ApiSetMapView::load(bytes, kApiSetMapArchX64, 0xdeadbeefULL);
    ASSERT_FALSE(anchor.has_value());
    EXPECT_EQ(anchor.error().code, ApiSetMapError::kAnchorMismatch);

    // wrong architecture
    const auto arch = ApiSetMapView::load(bytes, kApiSetMapArchX64 + 1, kFixtureNtdllXxhash64);
    ASSERT_FALSE(arch.has_value());
    EXPECT_EQ(arch.error().code, ApiSetMapError::kArchMismatch);

    // broken magic
    auto bad_magic = bytes;
    bad_magic[0] ^= 0xFF;
    const auto magic = ApiSetMapView::load(bad_magic, kApiSetMapArchX64, kFixtureNtdllXxhash64);
    ASSERT_FALSE(magic.has_value());
    EXPECT_EQ(magic.error().code, ApiSetMapError::kBadMagic);

    // unknown version
    auto bad_version = bytes;
    bad_version[8] = 9;
    const auto version = ApiSetMapView::load(bad_version, kApiSetMapArchX64, kFixtureNtdllXxhash64);
    ASSERT_FALSE(version.has_value());
    EXPECT_EQ(version.error().code, ApiSetMapError::kUnknownVersion);

    // a string range beyond the pool (entry 0's contract offset high byte)
    auto bad_range = bytes;
    bad_range[43] = 0xFF;
    const auto range = ApiSetMapView::load(bad_range, kApiSetMapArchX64, kFixtureNtdllXxhash64);
    ASSERT_FALSE(range.has_value());
    EXPECT_EQ(range.error().code, ApiSetMapError::kOutOfBounds);

    // truncated file
    const auto truncated = ApiSetMapView::load(std::span<const std::uint8_t>(bytes).subspan(0, 20),
                                               kApiSetMapArchX64, kFixtureNtdllXxhash64);
    ASSERT_FALSE(truncated.has_value());
    EXPECT_EQ(truncated.error().code, ApiSetMapError::kTooSmall);
}

TEST(ApiSetMap, ReaderRejectsConflictingEntries)
{
    // hand-built map: one contract mapped to two hosts - the reader catches
    // what the generator refuses to emit
    std::vector<std::uint8_t> bin(40 + 2 * 24 + 64, std::uint8_t{0});
    const auto put32 = [&](const std::size_t at, const std::uint32_t v) {
        for (unsigned i = 0; i < 4; ++i) {
            bin[at + i] = static_cast<std::uint8_t>(v >> (8 * i));
        }
    };
    std::memcpy(bin.data(), "APSMMAP1", 8);
    put32(8, 1); // version
    bin[12] = kApiSetMapArchX64;
    const auto anchor = kFixtureNtdllXxhash64;
    for (unsigned i = 0; i < 8; ++i) {
        bin[16 + i] = static_cast<std::uint8_t>(anchor >> (8 * i));
    }
    put32(24, 2);           // two entries
    put32(28, 64);          // pool size
    put32(32, 2 * 24);      // entry bytes
    put32(36, 40 + 2 * 24); // pool offset
    const auto put_string = [&](const std::size_t at, const std::string& text,
                                const std::size_t pool_at) {
        std::memcpy(bin.data() + 40 + 48 + pool_at, text.data(), text.size());
        put32(at, static_cast<std::uint32_t>(pool_at));
        put32(at + 4, static_cast<std::uint32_t>(text.size()));
    };
    put_string(40, "api-ms-win-core-dup-l1-1-0", 0);
    put_string(48, "", 0); // no importer
    put_string(56, "hosta.dll", 28);
    put_string(64, "api-ms-win-core-dup-l1-1-0", 0);
    put_string(72, "", 0);
    put_string(80, "hostb.dll", 38);
    const auto conflict = ApiSetMapView::load(bin, kApiSetMapArchX64, kFixtureNtdllXxhash64);
    ASSERT_FALSE(conflict.has_value());
    EXPECT_EQ(conflict.error().code, ApiSetMapError::kConflict);
}

TEST(ApiSetMap, ContextResolvesMapsAndKeepsSyntheticRoute)
{
    const auto dir = fs::temp_directory_path() / "sheller_apiset_det";
    const auto map_bytes = read_file(dir / "a.bin");
    ASSERT_FALSE(map_bytes.empty());
    const auto loaded = ApiSetMapView::load(map_bytes, kApiSetMapArchX64, kFixtureNtdllXxhash64);
    ASSERT_TRUE(loaded.has_value()) << loaded.error().detail;

    const auto source = make_boundary_source(boundary_fixture_exports(false));
    const auto derived = derive_boundary_image(source, "ntdll.dll", boundary_fixture_rules());
    ASSERT_TRUE(derived.has_value()) << derived.error().detail;
    WorldModules world(derived->image);
    const auto& modules = world.modules;

    ApiSetContext map_ctx;
    map_ctx.mode = ApiSetContext::Mode::kDirectoryMap;
    map_ctx.directory_map = &*loaded;

    // a mapped contract reduces to its host inside the map
    const auto mapped =
        resolve_export(modules, "api-ms-win-core-fixture-l1-1-0.dll", "NtCreateFile", map_ctx);
    ASSERT_TRUE(mapped.ok);
    EXPECT_EQ(mapped.module, &modules[0]);
    EXPECT_EQ(mapped.final_name, "NtCreateFile");
    EXPECT_FALSE(mapped.unmapped_api_set);

    // an api-set name the map does not cover is the named unmapped failure -
    // it never falls back to the synthetic kernelbase rule
    const auto unmapped =
        resolve_export(modules, "api-ms-win-core-nothing-l1-1-0.dll", "NtCreateFile", map_ctx);
    EXPECT_FALSE(unmapped.ok);
    EXPECT_TRUE(unmapped.unmapped_api_set);

    // a plain missing module keeps the ordinary failure path
    const auto absent = resolve_export(modules, "nowhere.dll", "NtCreateFile", map_ctx);
    EXPECT_FALSE(absent.ok);
    EXPECT_FALSE(absent.unmapped_api_set);

    // importer-conditional entries win over the unconditional one
    const auto conditional = resolve_export(modules, "api-ms-win-core-console-l1-1-0.dll",
                                            "FakeExport", map_ctx, "fakeuser32.dll");
    ASSERT_TRUE(conditional.ok);
    EXPECT_EQ(conditional.module, &modules[1]);
    const auto unconditional = resolve_export(modules, "api-ms-win-core-console-l1-1-0.dll",
                                              "NtCreateFile", map_ctx, "someone-else.dll");
    ASSERT_TRUE(unconditional.ok);
    EXPECT_EQ(unconditional.module, &modules[0]);

    // the synthetic route answers exactly as before: the crt prefix rule
    // reduces to ucrtbase, the rest to kernelbase - no map involved
    std::vector<LoadedModule> synthetic(1);
    synthetic[0].base = 0x7FFA00000000ULL;
    const auto crt_source = make_boundary_source(std::vector<BoundaryExport>{
        {"Anything", nullptr, sheller_test::kBoundaryInterceptRva, {0x31, 0xC0, 0xC3}, {}}});
    synthetic[0].image = *build_image(crt_source, *parse_pe(crt_source));
    std::memcpy(synthetic[0].name.data(), "ucrtbase.dll", 12);
    static_cast<void>(index_exports(synthetic[0]));
    const auto crt = resolve_export(synthetic, "api-ms-win-crt-heap-l1-1-0.dll", "Anything");
    ASSERT_TRUE(crt.ok);
    EXPECT_EQ(crt.module, &synthetic[0]);
    EXPECT_FALSE(crt.unmapped_api_set);
    const auto core = resolve_export(modules, "api-ms-win-core-something-l1-1-0.dll", "Anything");
    EXPECT_FALSE(core.ok);
    EXPECT_FALSE(core.unmapped_api_set); // synthetic mode: plain module-absence
}
