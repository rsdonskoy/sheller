// Boundary derivation (change real-dll-module-dir, tasks 1.1/1.2): the pure
// byte-level function from a directory file to the stub image - syscall
// numbers validated in the source body (never by name prefix), names,
// ordinals, aliases and forwarders preserved, EAT addresses rebuilt, the
// ntdll weld-slot layout and the reserved DOS e_res2 marker slot in place,
// double derivation byte-identical, and the derived images walked by the
// existing loader-side index/forwarder resolver. Portable by design.

#include "boundary_fixture.h"

#include "boundary_derive.h"
#include "imports.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

using namespace sheller::loader;
using sheller_test::boundary_fixture_exports;
using sheller_test::boundary_fixture_rules;
using sheller_test::boundary_x64_stub;
using sheller_test::kBoundaryInterceptRva;
using sheller_test::kBoundaryStubRva;
using sheller_test::kBoundaryUnnamedStubRva;
using sheller_test::kBoundaryZwStubRva;
using sheller_test::make_boundary_source;
using BoundaryExport = sheller_test::BoundaryFixtureExport;

const DerivedBoundaryExport* find_export(const DerivedBoundary& derived, const std::string& name)
{
    for (const auto& entry : derived.exports) {
        if (entry.name == name) {
            return &entry;
        }
    }
    return nullptr;
}

// ---- tests ------------------------------------------------------------------

TEST(BoundaryDerive, DerivedSyscallNumbersMatchSource)
{
    const auto source = make_boundary_source(boundary_fixture_exports(false));
    const auto derived = derive_boundary_image(source, "ntdll.dll", boundary_fixture_rules());
    ASSERT_TRUE(derived.has_value()) << derived.error().detail;

    // the numbers the dispositions carry equal the source bodies' numbers
    for (const auto* name : {"NtCreateFile", "ZwCreateFile"}) {
        const auto* entry = find_export(*derived, name);
        ASSERT_NE(entry, nullptr);
        EXPECT_EQ(entry->kind, BoundaryKind::kSyscallStub);
        EXPECT_EQ(entry->syscall_number, 0x55u);
        // ...and equal what the source body itself decodes to
        EXPECT_EQ(
            syscall_stub_number_from_bytes(std::span<const std::uint8_t>(source).subspan(
                name == std::string("NtCreateFile") ? kBoundaryStubRva : kBoundaryZwStubRva, 16)),
            entry->syscall_number);
    }
    // the unnamed ordinal-5 stub keeps its own number
    const auto* unnamed = find_export(*derived, "");
    ASSERT_NE(unnamed, nullptr);
    EXPECT_EQ(unnamed->ordinal, 5u);
    EXPECT_EQ(unnamed->syscall_number, 0x66u);
    // the derived bodies carry the canonical shape with the same immediates
    for (const auto* entry_name : {"NtCreateFile", "ZwCreateFile"}) {
        const auto* entry = find_export(*derived, entry_name);
        const auto body = std::span<const std::uint8_t>(derived->image)
                              .subspan(static_cast<std::size_t>(entry->body_rva), 16);
        EXPECT_EQ(syscall_stub_number_from_bytes(body), 0x55u);
        EXPECT_EQ(body[8], 0x0F);
        EXPECT_EQ(body[9], 0x05);
    }
}

TEST(BoundaryDerive, NamePrefixDoesNotImplySyscall)
{
    const auto source = make_boundary_source(boundary_fixture_exports(false));
    // a manifest syscallstub rule cannot promote a non-stub body either -
    // the bytes are the verdict, the Nt prefix is nothing
    auto rules = boundary_fixture_rules();
    for (auto& rule : rules) {
        if (rule.name == "NtWeird") {
            rule.kind = BoundaryKind::kSyscallStub;
        }
    }
    const auto mismatch = derive_boundary_image(source, "ntdll.dll", rules);
    ASSERT_FALSE(mismatch.has_value());
    EXPECT_EQ(mismatch.error().code, BoundaryDeriveError::kManifestMismatch);
    EXPECT_NE(mismatch.error().detail.find("NtWeird"), std::string::npos);

    // classified by the manifest as a trap, the Nt-prefixed export derives
    // an ud2 body and no syscall number
    const auto derived = derive_boundary_image(source, "ntdll.dll", boundary_fixture_rules());
    ASSERT_TRUE(derived.has_value()) << derived.error().detail;
    const auto* weird = find_export(*derived, "NtWeird");
    ASSERT_NE(weird, nullptr);
    EXPECT_EQ(weird->kind, BoundaryKind::kTrap);
    EXPECT_EQ(weird->syscall_number, 0u);
    const auto body = std::span<const std::uint8_t>(derived->image)
                          .subspan(static_cast<std::size_t>(weird->body_rva), 2);
    EXPECT_EQ(body[0], 0x0F);
    EXPECT_EQ(body[1], 0x0B);
}

TEST(BoundaryDerive, DeterministicDoubleDerive)
{
    const auto source = make_boundary_source(boundary_fixture_exports(false));
    const auto first = derive_boundary_image(source, "ntdll.dll", boundary_fixture_rules());
    const auto second = derive_boundary_image(source, "ntdll.dll", boundary_fixture_rules());
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    ASSERT_EQ(first->image.size(), second->image.size());
    EXPECT_EQ(0, std::memcmp(first->image.data(), second->image.data(), first->image.size()));
    ASSERT_EQ(first->exports.size(), second->exports.size());
    for (std::size_t i = 0; i < first->exports.size(); ++i) {
        EXPECT_EQ(first->exports[i].name, second->exports[i].name);
        EXPECT_EQ(first->exports[i].ordinal, second->exports[i].ordinal);
        EXPECT_EQ(first->exports[i].kind, second->exports[i].kind);
        EXPECT_EQ(first->exports[i].body_rva, second->exports[i].body_rva);
        EXPECT_EQ(first->exports[i].syscall_number, second->exports[i].syscall_number);
    }
}

TEST(BoundaryDerive, NamesOrdinalsAliasesAndLayoutSurvive)
{
    const auto source = make_boundary_source(boundary_fixture_exports(false));
    const auto derived = derive_boundary_image(source, "ntdll.dll", boundary_fixture_rules());
    ASSERT_TRUE(derived.has_value()) << derived.error().detail;

    // the derived image is a parseable PE
    const auto info = parse_pe(derived->image);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->bitness, kBitness64);

    // aliases share one body slot (same ordinal, one RVA)
    const auto* foo = find_export(*derived, "RtlFoo");
    const auto* alias = find_export(*derived, "RtlFooAlias");
    ASSERT_NE(foo, nullptr);
    ASSERT_NE(alias, nullptr);
    EXPECT_EQ(foo->ordinal, 2u);
    EXPECT_EQ(alias->ordinal, 2u);
    EXPECT_EQ(foo->body_rva, alias->body_rva);

    // the compat recipe is the manifest's per-function answer (aliases
    // carry the same disposition - they share the one body slot)
    auto rules = boundary_fixture_rules();
    for (auto& rule : rules) {
        if (rule.name == "RtlFoo" || rule.name == "RtlFooAlias") {
            rule.kind = BoundaryKind::kCompat;
            rule.compat_return = 0xC0000001;
        }
    }
    const auto compat = derive_boundary_image(source, "ntdll.dll", rules);
    ASSERT_TRUE(compat.has_value()) << compat.error().detail;
    const auto* compat_foo = find_export(*compat, "RtlFoo");
    ASSERT_NE(compat_foo, nullptr);
    const auto body = std::span<const std::uint8_t>(compat->image)
                          .subspan(static_cast<std::size_t>(compat_foo->body_rva), 6);
    EXPECT_EQ(body[0], 0xB8);
    EXPECT_EQ(body[5], 0xC3);

    // a manifest giving the alias pair different dispositions is rejected:
    // they share one target and one body slot
    for (auto& rule : rules) {
        if (rule.name == "RtlFooAlias") {
            rule.kind = BoundaryKind::kTrap;
        }
    }
    const auto alias_mismatch = derive_boundary_image(source, "ntdll.dll", rules);
    ASSERT_FALSE(alias_mismatch.has_value());
    EXPECT_EQ(alias_mismatch.error().code, BoundaryDeriveError::kManifestMismatch);

    // the data slot carries the manifest's exact initial bytes
    const auto* data = find_export(*derived, "DataExport");
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(data->kind, BoundaryKind::kData);
    const auto slot = std::span<const std::uint8_t>(derived->image)
                          .subspan(static_cast<std::size_t>(data->body_rva), 8);
    EXPECT_EQ(0, std::memcmp(slot.data(), boundary_fixture_rules()[5].data_bytes.data(), 8));
}

TEST(BoundaryDerive, ForwarderRelationPreserved)
{
    std::vector<BoundaryExport> exports = boundary_fixture_exports(false);
    // turn EAT 4 into a forwarder for this file: the string lands in the
    // directory (the builder emits forwarder strings after the name pool)
    exports[4] = {"DataExport", nullptr, 0, {}, "other.dll.Func"};
    auto rules = boundary_fixture_rules();
    rules.erase(std::remove_if(rules.begin(), rules.end(),
                               [](const BoundaryRule& r) { return r.name == "DataExport"; }),
                rules.end());
    const auto source = make_boundary_source(exports);
    const auto derived = derive_boundary_image(source, "ntdll.dll", rules);
    ASSERT_TRUE(derived.has_value()) << derived.error().detail;
    const auto* forwarded = find_export(*derived, "DataExport");
    ASSERT_NE(forwarded, nullptr);
    EXPECT_TRUE(forwarded->forwarded);
    EXPECT_EQ(forwarded->forwarder_target, "other.dll.Func");
    // body_rva is the derived EAT value: the preserved string's RVA inside
    // this image, spelled exactly as the source had it
    ASSERT_NE(forwarded->body_rva, 0u);
    const auto spelled =
        std::string(reinterpret_cast<const char*>(derived->image.data() + forwarded->body_rva));
    EXPECT_EQ(spelled, "other.dll.Func");

    // a rule pinned onto a forwarder is a manifest/source disagreement
    rules.push_back({"DataExport", 4, BoundaryKind::kTrap, 0, "", 0, 0, {}});
    const auto mismatch = derive_boundary_image(source, "ntdll.dll", rules);
    ASSERT_FALSE(mismatch.has_value());
    EXPECT_EQ(mismatch.error().code, BoundaryDeriveError::kManifestMismatch);
}

TEST(BoundaryDerive, NtdllWeldSlotAndMarkerSlotLayout)
{
    const auto source = make_boundary_source(boundary_fixture_exports(false));
    const auto derived = derive_boundary_image(source, "ntdll.dll", boundary_fixture_rules());
    ASSERT_TRUE(derived.has_value());
    // ntdll: the engine's weld .data at the fixed RVA, zero-initialized
    EXPECT_EQ(derived->weld_data_rva, kBoundaryNtdllWeldDataRva);
    ASSERT_GE(derived->image.size(), kBoundaryNtdllWeldDataRva + 0x200u);
    for (std::size_t i = 0; i < 0x200; ++i) {
        ASSERT_EQ(derived->image[kBoundaryNtdllWeldDataRva + i], 0) << "weld byte " << i;
    }
    // the DOS e_res2 marker slot (0x28, 20 bytes) is reserved zero
    for (std::uint32_t i = 0; i < kBoundaryMarkerSize; ++i) {
        ASSERT_EQ(derived->image[kBoundaryMarkerOffset + i], 0) << "marker byte " << i;
    }
    // a non-ntdll boundary module carries no weld section
    const auto win32u = derive_boundary_image(source, "win32u.dll", boundary_fixture_rules());
    ASSERT_TRUE(win32u.has_value());
    EXPECT_EQ(win32u->weld_data_rva, 0u);
}

TEST(BoundaryDerive, NamedRejections)
{
    // unknown export: no rule covers it
    const auto unknown_source = make_boundary_source(boundary_fixture_exports(true));
    const auto unknown =
        derive_boundary_image(unknown_source, "ntdll.dll", boundary_fixture_rules());
    ASSERT_FALSE(unknown.has_value());
    EXPECT_EQ(unknown.error().code, BoundaryDeriveError::kUnknownExport);
    EXPECT_NE(unknown.error().detail.find("NtUnknown"), std::string::npos);

    // i386 boundary images are not derived in phase 1 (consistent PE32
    // headers: machine and magic flipped together)
    auto x86_source = make_boundary_source(boundary_fixture_exports(false));
    x86_source[0x84] = 0x4C; // machine i386
    x86_source[0x85] = 0x01;
    x86_source[0x98] = 0x0B; // PE32 optional magic
    x86_source[0x99] = 0x01;
    const auto x86 = derive_boundary_image(x86_source, "ntdll.dll", boundary_fixture_rules());
    ASSERT_FALSE(x86.has_value());
    EXPECT_EQ(x86.error().code, BoundaryDeriveError::kUnsupportedMachine);

    // a bad data rule (byte count != declared size) is a named rejection
    auto bad_data = boundary_fixture_rules();
    bad_data[5].data_bytes.pop_back();
    const auto source = make_boundary_source(boundary_fixture_exports(false));
    const auto bad = derive_boundary_image(source, "ntdll.dll", bad_data);
    ASSERT_FALSE(bad.has_value());
    EXPECT_EQ(bad.error().code, BoundaryDeriveError::kBadRule);

    // duplicate rules are a manifest defect
    auto duplicated = boundary_fixture_rules();
    duplicated.push_back({"NtCreateFile", 0, BoundaryKind::kTrap, 0, "", 0, 0, {}});
    const auto dup = derive_boundary_image(source, "ntdll.dll", duplicated);
    ASSERT_FALSE(dup.has_value());
    EXPECT_EQ(dup.error().code, BoundaryDeriveError::kBadRule);
}

TEST(BoundaryDerive, DerivedExportsIndexAndForwardChain)
{
    // module A: the boundary target (Nt stubs + one alias pair)
    const auto source_a = make_boundary_source(boundary_fixture_exports(false));
    const auto derived_a = derive_boundary_image(source_a, "ntdll.dll", boundary_fixture_rules());
    ASSERT_TRUE(derived_a.has_value()) << derived_a.error().detail;

    // module B: a direct stub, a forwarder into A, and an alias pair whose
    // rule is a compat disposition
    std::vector<BoundaryExport> exports_b{
        {"DirectCall", nullptr, kBoundaryStubRva, boundary_x64_stub(0x77), {}},
        {"ForwardedCall", nullptr, 0, {}, "fakentdll.NtCreateFile"},
        {"AliasB", "AliasB2", kBoundaryInterceptRva, {0x31, 0xC0, 0xC3}, {}},
    };
    const auto source_b = make_boundary_source(exports_b);
    const std::vector<BoundaryRule> rules_b{
        {"DirectCall", 0, BoundaryKind::kSyscallStub, 0, "", 0, 0, {}},
        {"AliasB", 2, BoundaryKind::kCompat, 5, "", 0, 0, {}},
        {"AliasB2", 2, BoundaryKind::kCompat, 5, "", 0, 0, {}},
    };
    const auto derived_b = derive_boundary_image(source_b, "other.dll", rules_b);
    ASSERT_TRUE(derived_b.has_value()) << derived_b.error().detail;

    // the existing loader-side index walks the derived images: every named
    // export is present with its rebuilt VA (base + derived body RVA)
    std::vector<LoadedModule> modules(2);
    modules[0].base = 0x7FF800000000ULL;
    modules[0].image = derived_a->image;
    std::memcpy(modules[0].name.data(), "fakentdll.dll", 13);
    modules[1].base = 0x7FF900000000ULL;
    modules[1].image = derived_b->image;
    std::memcpy(modules[1].name.data(), "other.dll", 9);
    ASSERT_TRUE(index_exports(modules[0]).has_value());
    ASSERT_TRUE(index_exports(modules[1]).has_value());
    const auto body_rva_of = [&](const DerivedBoundary& derived, const std::string& name) {
        for (const auto& entry : derived.exports) {
            if (entry.name == name) {
                return entry.body_rva;
            }
        }
        return std::uint64_t{0};
    };
    for (const auto* name : {"NtCreateFile", "ZwCreateFile", "RtlFoo"}) {
        const auto it = std::find_if(modules[0].exports.begin(), modules[0].exports.end(),
                                     [&](const auto& e) { return e.first == name; });
        ASSERT_NE(it, modules[0].exports.end()) << name;
        EXPECT_EQ(it->second, modules[0].base + body_rva_of(*derived_a, name));
    }
    // the derived RVAs are this image's own layout (base + derived slot);
    // the rebuild never carries a source RVA - the unnamed stub proves it,
    // its source slot (0x1050) and derived slot (0x1040) differ
    EXPECT_EQ(body_rva_of(*derived_a, ""), kBoundaryUnnamedStubRva - 0x10);

    // alias pairs resolve to one shared VA (one body slot per ordinal)
    const auto* foo = &*std::find_if(modules[0].exports.begin(), modules[0].exports.end(),
                                     [](const auto& e) { return e.first == "RtlFoo"; });
    const auto* foo_alias = &*std::find_if(modules[0].exports.begin(), modules[0].exports.end(),
                                           [](const auto& e) { return e.first == "RtlFooAlias"; });
    EXPECT_EQ(foo->second, foo_alias->second);
    const auto alias_b = resolve_export(modules, "other", "AliasB");
    const auto alias_b2 = resolve_export(modules, "other", "AliasB2");
    ASSERT_TRUE(alias_b.ok);
    ASSERT_TRUE(alias_b2.ok);
    EXPECT_EQ(alias_b.va, alias_b2.va);

    // the forwarder resolves along the chain into module A's stub
    const auto forwarded = resolve_export(modules, "other", "ForwardedCall");
    ASSERT_TRUE(forwarded.ok);
    EXPECT_TRUE(forwarded.forwarded);
    EXPECT_EQ(forwarded.module, &modules[0]);
    EXPECT_EQ(forwarded.final_name, "NtCreateFile");
    EXPECT_EQ(forwarded.va, modules[0].base + body_rva_of(*derived_a, "NtCreateFile"));

    // and the direct stub resolves to its own slot
    const auto direct = resolve_export(modules, "other", "DirectCall");
    ASSERT_TRUE(direct.ok);
    EXPECT_FALSE(direct.forwarded);
    EXPECT_EQ(direct.module, &modules[1]);
    EXPECT_EQ(direct.va, modules[1].base + body_rva_of(*derived_b, "DirectCall"));
}

} // namespace
