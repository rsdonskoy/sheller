// Boundary manifest binding: the
// committed seed's applicability verdicts are named rejections (unknown
// module/arch, image-hash mismatch), the seed rows drive the derive
// end-to-end (an export outside the seed coverage is a named rejection),
// and forwarded exports classify along their resolution chain to the
// target's disposition. Portable by design.

#include "boundary_fixture.h"

#include "boundary_manifest.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace {

using namespace sheller::engine;
using sheller_test::boundary_fixture_exports;
using sheller_test::boundary_fixture_rules;
using sheller_test::boundary_x64_stub;
using sheller_test::kBoundaryInterceptRva;
using sheller_test::kBoundaryStubRva;
using sheller_test::kFixtureNtdllXxhash64;
using sheller_test::make_boundary_source;
using BoundaryExport = sheller_test::BoundaryFixtureExport;

// The committed seed's first row binds exactly this fixture image.
static_assert(kFixtureNtdllXxhash64 == 0x6c806f42b18c5f46ULL,
              "the fixture hash drifted - re-pin tools/boundary_manifest/ntdll.x64.json");

TEST(BoundaryManifest, ApplicabilityVerdictsAreNamed)
{
    const auto& manifest = BoundaryManifest::committed();

    // unknown module: nothing is covered for this (module, arch) pair
    const auto unknown_module = manifest.rules_for("win32u.dll", "x64", kFixtureNtdllXxhash64);
    ASSERT_FALSE(unknown_module.has_value());
    EXPECT_EQ(unknown_module.error(), BoundaryManifestError::kUnknownModule);

    // unknown architecture: the x86 rows simply do not exist
    const auto unknown_arch = manifest.rules_for("ntdll.dll", "x86", kFixtureNtdllXxhash64);
    ASSERT_FALSE(unknown_arch.has_value());
    EXPECT_EQ(unknown_arch.error(), BoundaryManifestError::kUnknownModule);

    // hash mismatch: the module is manifested, these bytes are not its
    const auto hash_mismatch = manifest.rules_for("ntdll.dll", "x64", 0xdeadbeefcafeULL);
    ASSERT_FALSE(hash_mismatch.has_value());
    EXPECT_EQ(hash_mismatch.error(), BoundaryManifestError::kHashMismatch);
    EXPECT_STREQ(boundary_manifest_error_message(BoundaryManifestError::kHashMismatch),
                 "image content hash is not in the boundary manifest's applicability list");

    EXPECT_TRUE(manifest.covers("ntdll.dll", "x64"));
    EXPECT_FALSE(manifest.covers("ntdll.dll", "x86"));
}

TEST(BoundaryManifest, SeedRowsDriveTheDerive)
{
    const auto& manifest = BoundaryManifest::committed();
    auto rules = manifest.rules_for("ntdll.dll", "x64", kFixtureNtdllXxhash64);
    ASSERT_TRUE(rules.has_value());
    // the seed spells the same classification the hand-written fixture rule
    // set carries - the two stay in lockstep
    ASSERT_EQ(rules->size(), boundary_fixture_rules().size());
    for (std::size_t i = 0; i < rules->size(); ++i) {
        EXPECT_EQ((*rules)[i].name, boundary_fixture_rules()[i].name);
        EXPECT_EQ((*rules)[i].kind, boundary_fixture_rules()[i].kind);
    }

    // the seed-derived rules derive the fixture end-to-end, data layout
    // included
    const auto source = make_boundary_source(boundary_fixture_exports(false));
    const auto derived = sheller::loader::derive_boundary_image(source, "ntdll.dll", *rules);
    ASSERT_TRUE(derived.has_value()) << derived.error().detail;
    const auto data = std::find_if(derived->exports.begin(), derived->exports.end(),
                                   [](const auto& e) { return e.name == "DataExport"; });
    ASSERT_NE(data, derived->exports.end());
    EXPECT_EQ(data->kind, sheller::loader::BoundaryKind::kData);
    const auto slot = std::span<const std::uint8_t>(derived->image)
                          .subspan(static_cast<std::size_t>(data->body_rva), 8);
    const std::vector<std::uint8_t> expected_bytes{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    EXPECT_EQ(0, std::memcmp(slot.data(), expected_bytes.data(), 8));

    // an export the seed does not cover rejects by name - the committed
    // manifest is the whole coverage, never a prefix of it
    const auto unknown_source = make_boundary_source(boundary_fixture_exports(true));
    const auto unknown =
        sheller::loader::derive_boundary_image(unknown_source, "ntdll.dll", *rules);
    ASSERT_FALSE(unknown.has_value());
    EXPECT_EQ(unknown.error().code, sheller::loader::BoundaryDeriveError::kUnknownExport);
    EXPECT_NE(unknown.error().detail.find("NtUnknown"), std::string::npos);
}

TEST(BoundaryManifest, ForwardedExportsClassifyAlongTheChain)
{
    const auto& manifest = BoundaryManifest::committed();
    const auto rules = manifest.rules_for("ntdll.dll", "x64", kFixtureNtdllXxhash64);
    ASSERT_TRUE(rules.has_value());

    const auto source_a = make_boundary_source(boundary_fixture_exports(false));
    const auto derived_a = sheller::loader::derive_boundary_image(source_a, "ntdll.dll", *rules);
    ASSERT_TRUE(derived_a.has_value()) << derived_a.error().detail;

    std::vector<BoundaryExport> exports_b{
        {"DirectCall", nullptr, kBoundaryStubRva, boundary_x64_stub(0x77), {}},
        {"ForwardedCall", nullptr, 0, {}, "fakentdll.NtCreateFile"},
        {"ToTrap", nullptr, 0, {}, "fakentdll.NtWeird"},
    };
    const auto source_b = make_boundary_source(exports_b);
    const std::vector<sheller::loader::BoundaryRule> rules_b{
        {"DirectCall", 0, sheller::loader::BoundaryKind::kSyscallStub, 0, "", 0, 0, {}},
    };
    const auto derived_b = sheller::loader::derive_boundary_image(source_b, "other.dll", rules_b);
    ASSERT_TRUE(derived_b.has_value()) << derived_b.error().detail;

    std::vector<sheller::loader::LoadedModule> modules(2);
    modules[0].base = 0x7FF800000000ULL;
    modules[0].image = derived_a->image;
    std::memcpy(modules[0].name.data(), "fakentdll.dll", 13);
    modules[1].base = 0x7FF900000000ULL;
    modules[1].image = derived_b->image;
    std::memcpy(modules[1].name.data(), "other.dll", 9);
    ASSERT_TRUE(sheller::loader::index_exports(modules[0]).has_value());
    ASSERT_TRUE(sheller::loader::index_exports(modules[1]).has_value());

    // only manifested boundary modules join the classification set
    std::map<std::string, std::vector<sheller::loader::BoundaryRule>> boundary_rules;
    boundary_rules.emplace("fakentdll.dll", *rules);

    // a chain into the manifested module lands on the target's disposition
    const auto chained = classify_export_chain(modules, boundary_rules, "other", "ForwardedCall");
    ASSERT_TRUE(chained.resolved);
    ASSERT_TRUE(chained.boundary);
    EXPECT_EQ(chained.kind, sheller::loader::BoundaryKind::kSyscallStub);
    EXPECT_EQ(chained.syscall_number, 0x55u);
    EXPECT_EQ(chained.final_name, "NtCreateFile");

    // a chain onto a trap export keeps the trap disposition
    const auto trapped = classify_export_chain(modules, boundary_rules, "other", "ToTrap");
    ASSERT_TRUE(trapped.resolved);
    ASSERT_TRUE(trapped.boundary);
    EXPECT_EQ(trapped.kind, sheller::loader::BoundaryKind::kTrap);

    // a direct hit in a non-manifested module is real-byte code: no
    // boundary disposition, executed as-is
    const auto real_code = classify_export_chain(modules, boundary_rules, "other", "DirectCall");
    ASSERT_TRUE(real_code.resolved);
    EXPECT_FALSE(real_code.boundary);

    // a dangling chain resolves to nothing
    const auto dangling = classify_export_chain(modules, boundary_rules, "other", "Missing");
    EXPECT_FALSE(dangling.resolved);
    EXPECT_FALSE(dangling.boundary);
}

} // namespace
