// Boundary derivation: the pure
// byte-level function from a directory file and a base to the guest image -
// the real file is the base (SizeOfImage and the section list are the
// source's, taken through the real relocation pipeline), syscall numbers
// validated in the source body (never by name prefix), names, ordinals,
// aliases and forwarders preserved at their source addresses, the image
// rewrite whitelist held (marker slot, free data slots, manifest stub
// bodies; everything else byte-identical to the loaded source), the
// synthetic-era weld layout retired, double derivation byte-identical, and
// the derived images walked by the existing loader-side index/forwarder
// resolver. Portable by design.

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
using sheller_test::kBoundaryDataRva;
using sheller_test::kBoundaryInterceptRva;
using sheller_test::kBoundaryNtWeirdRva;
using sheller_test::kBoundarySourceBase;
using sheller_test::kBoundarySourceFileSize;
using sheller_test::kBoundaryStubRva;
using sheller_test::kBoundaryUnnamedStubRva;
using sheller_test::kBoundaryZwStubRva;
using sheller_test::make_boundary_source;
using BoundaryExport = sheller_test::BoundaryFixtureExport;

// the base the directory mode maps ntdll at (kBases64[0]); win32u tests
// take the extras ladder's first slot (kBases64[2] + 0x100000000)
constexpr std::uint64_t kNtdllBase = 0x7FF800000000ULL;
constexpr std::uint64_t kWin32uBase = 0x7FFB00000000ULL;

const DerivedBoundaryExport* find_export(const DerivedBoundary& derived, const std::string& name)
{
    for (const auto& entry : derived.exports) {
        if (entry.name == name) {
            return &entry;
        }
    }
    return nullptr;
}

// The plain loaded image (build + the real relocation delta): the pin the
// whitelist writes are measured against.
std::expected<std::vector<std::uint8_t>, LoadError>
plain_loaded_image(const std::vector<std::uint8_t>& source, const std::uint64_t base)
{
    const auto info = parse_pe(source);
    if (!info.has_value()) {
        return std::unexpected(info.error());
    }
    auto image = build_image(source, *info);
    if (!image.has_value()) {
        return std::unexpected(image.error());
    }
    const auto delta = base - info->image_base;
    if (delta != 0) {
        if (const auto relocated = apply_relocations(*image, *info, delta);
            !relocated.has_value()) {
            return std::unexpected(relocated.error());
        }
    }
    return image;
}

// ---- tests ------------------------------------------------------------------

TEST(BoundaryDerive, DerivedSyscallNumbersMatchSource)
{
    const auto source = make_boundary_source(boundary_fixture_exports(false));
    const auto derived =
        derive_boundary_image(source, "ntdll.dll", boundary_fixture_rules(), kNtdllBase);
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
    // the stubs keep their source bytes at their source addresses: the
    // image bytes at the recorded body RVA decode to the same number
    for (const auto* entry_name : {"NtCreateFile", "ZwCreateFile"}) {
        const auto* entry = find_export(*derived, entry_name);
        ASSERT_NE(entry, nullptr);
        EXPECT_EQ(entry->body_rva, entry_name == std::string("NtCreateFile") ? kBoundaryStubRva
                                                                             : kBoundaryZwStubRva);
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
    const auto mismatch = derive_boundary_image(source, "ntdll.dll", rules, kNtdllBase);
    ASSERT_FALSE(mismatch.has_value());
    EXPECT_EQ(mismatch.error().code, BoundaryDeriveError::kManifestMismatch);
    EXPECT_NE(mismatch.error().detail.find("NtWeird"), std::string::npos);

    // classified by the manifest as a trap, the Nt-prefixed export carries
    // no syscall number and its source bytes stay untouched - the stop is
    // the runtime table's, never a rewritten body
    const auto derived =
        derive_boundary_image(source, "ntdll.dll", boundary_fixture_rules(), kNtdllBase);
    ASSERT_TRUE(derived.has_value()) << derived.error().detail;
    const auto* weird = find_export(*derived, "NtWeird");
    ASSERT_NE(weird, nullptr);
    EXPECT_EQ(weird->kind, BoundaryKind::kTrap);
    EXPECT_EQ(weird->syscall_number, 0u);
    EXPECT_EQ(weird->body_rva, kBoundaryNtWeirdRva);
    const auto body = std::span<const std::uint8_t>(derived->image)
                          .subspan(static_cast<std::size_t>(weird->body_rva), 3);
    EXPECT_EQ(body[0], 0x33); // the source bytes, not an ud2
    EXPECT_EQ(body[1], 0xC0);
    EXPECT_EQ(body[2], 0xC3);
}

TEST(BoundaryDerive, DeterministicDoubleDerive)
{
    const auto source = make_boundary_source(boundary_fixture_exports(false));
    const auto first =
        derive_boundary_image(source, "ntdll.dll", boundary_fixture_rules(), kNtdllBase);
    const auto second =
        derive_boundary_image(source, "ntdll.dll", boundary_fixture_rules(), kNtdllBase);
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
    const auto derived =
        derive_boundary_image(source, "ntdll.dll", boundary_fixture_rules(), kNtdllBase);
    ASSERT_TRUE(derived.has_value()) << derived.error().detail;

    // the derived image is the source's own folded shape
    const auto info = parse_pe(derived->image);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->bitness, kBitness64);
    EXPECT_EQ(info->image_size, kBoundarySourceFileSize);

    // aliases share one address (the source EAT slot they both name)
    const auto* foo = find_export(*derived, "RtlFoo");
    const auto* alias = find_export(*derived, "RtlFooAlias");
    ASSERT_NE(foo, nullptr);
    ASSERT_NE(alias, nullptr);
    EXPECT_EQ(foo->ordinal, 2u);
    EXPECT_EQ(alias->ordinal, 2u);
    EXPECT_EQ(foo->body_rva, kBoundaryInterceptRva);
    EXPECT_EQ(foo->body_rva, alias->body_rva);

    // the compat recipe is the manifest's per-function answer, written at
    // the export's own address (aliases share the one slot)
    const auto body = std::span<const std::uint8_t>(derived->image)
                          .subspan(static_cast<std::size_t>(foo->body_rva), 6);
    EXPECT_EQ(body[0], 0xB8);
    EXPECT_EQ(body[1], 0x01); // 0xC0000001, little-endian
    EXPECT_EQ(body[4], 0xC0);
    EXPECT_EQ(body[5], 0xC3);

    // a manifest giving the alias pair different dispositions is rejected:
    // they share one target and one address
    auto rules = boundary_fixture_rules();
    for (auto& rule : rules) {
        if (rule.name == "RtlFooAlias") {
            rule.kind = BoundaryKind::kTrap;
        }
    }
    const auto alias_mismatch = derive_boundary_image(source, "ntdll.dll", rules, kNtdllBase);
    ASSERT_FALSE(alias_mismatch.has_value());
    EXPECT_EQ(alias_mismatch.error().code, BoundaryDeriveError::kManifestMismatch);

    // the free data slot carries the manifest's exact initial bytes
    const auto* data = find_export(*derived, "DataExport");
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(data->kind, BoundaryKind::kData);
    EXPECT_EQ(data->body_rva, kBoundaryDataRva);
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
    const auto derived = derive_boundary_image(source, "ntdll.dll", rules, kNtdllBase);
    ASSERT_TRUE(derived.has_value()) << derived.error().detail;
    const auto* forwarded = find_export(*derived, "DataExport");
    ASSERT_NE(forwarded, nullptr);
    EXPECT_TRUE(forwarded->forwarded);
    EXPECT_EQ(forwarded->forwarder_target, "other.dll.Func");
    // body_rva is the source EAT value: the string's RVA inside the mapped
    // export directory, spelled exactly as the source had it
    ASSERT_NE(forwarded->body_rva, 0u);
    const auto spelled =
        std::string(reinterpret_cast<const char*>(derived->image.data() + forwarded->body_rva));
    EXPECT_EQ(spelled, "other.dll.Func");

    // a rule pinned onto a forwarder is a manifest/source disagreement
    rules.push_back({"DataExport", 4, BoundaryKind::kTrap, 0, "", 0, 0, {}});
    const auto mismatch = derive_boundary_image(source, "ntdll.dll", rules, kNtdllBase);
    ASSERT_FALSE(mismatch.has_value());
    EXPECT_EQ(mismatch.error().code, BoundaryDeriveError::kManifestMismatch);
}

// ---- the real-base contract: shape and the rewrite whitelist ----------------

TEST(BoundaryDerive, MappedShapeMatchesSourceOutsideTheWhitelist)
{
    const auto source = make_boundary_source(boundary_fixture_exports(false));
    // real content in the slack the old weld layout would have owned: the
    // derivation must not zero, pad or re-lay-out any of it
    auto marked = source;
    for (std::size_t i = 0x2100; i < 0x3000; ++i) {
        marked[i] = 0xAA;
    }
    const auto derived =
        derive_boundary_image(marked, "ntdll.dll", boundary_fixture_rules(), kNtdllBase);
    ASSERT_TRUE(derived.has_value()) << derived.error().detail;

    // the mapped shape is the source's own: SizeOfImage, the section list
    const auto source_info = parse_pe(marked);
    ASSERT_TRUE(source_info.has_value());
    const auto derived_info = parse_pe(derived->image);
    ASSERT_TRUE(derived_info.has_value());
    EXPECT_EQ(derived_info->image_size, source_info->image_size);
    ASSERT_EQ(derived_info->sections.size(), source_info->sections.size());
    for (std::size_t i = 0; i < source_info->sections.size(); ++i) {
        EXPECT_EQ(derived_info->sections[i].virtual_address,
                  source_info->sections[i].virtual_address);
        EXPECT_EQ(derived_info->sections[i].virtual_size, source_info->sections[i].virtual_size);
        EXPECT_EQ(derived_info->sections[i].raw_size, source_info->sections[i].raw_size);
        EXPECT_EQ(std::memcmp(derived->image.data() + derived_info->sections[i].virtual_address,
                              marked.data() + source_info->sections[i].virtual_address, 8),
                  0)
            << "section name " << i;
    }

    // outside the whitelist the image equals the plain loaded bytes (build +
    // the real relocation to the mapped base); the whitelist slots are
    // exactly: the compat body at its export address, the free data slot
    const auto plain = plain_loaded_image(marked, kNtdllBase);
    ASSERT_TRUE(plain.has_value());
    ASSERT_EQ(derived->image.size(), plain->size());
    bool whitelist_diff = false;
    for (std::size_t i = 0; i < plain->size(); ++i) {
        const auto at = static_cast<std::uint32_t>(i);
        if (at >= kBoundaryInterceptRva && at < kBoundaryInterceptRva + 6) {
            whitelist_diff = true; // the compat stub body
        } else if (at >= kBoundaryDataRva && at < kBoundaryDataRva + 8) {
            whitelist_diff = true; // the free data slot
        } else {
            ASSERT_EQ(derived->image[i], (*plain)[i])
                << "non-whitelist byte differs at 0x" << std::hex << i;
        }
    }
    EXPECT_TRUE(whitelist_diff) << "the whitelist slots never landed";
    // and the slack keeps the marked bytes
    for (std::size_t i = 0x2100; i < 0x3000; ++i) {
        ASSERT_EQ(derived->image[i], 0xAA) << "marked byte 0x" << std::hex << i;
    }

    // the reserved DOS e_res2 marker slot stays zero (the engine's marker
    // write lands there after the pipeline)
    for (std::uint32_t i = 0; i < kBoundaryMarkerSize; ++i) {
        ASSERT_EQ(derived->image[kBoundaryMarkerOffset + i], 0) << "marker byte " << i;
    }
}

TEST(BoundaryDerive, WeldSlotConflictKeepsRealBytes)
{
    // the synthetic era welded a .data section at the fixed RVA 0x41000 over
    // a 0x42000 image. On a real-shape source the retired slot must not
    // carve, resize or overwrite: a source whose mapped bytes at 0x41000 are
    // real non-zero content keeps them byte-for-byte.
    auto source = make_boundary_source(boundary_fixture_exports(false));
    // grow the .text section's spans so RVA 0x41000 is mapped, and put real
    // content there: file offset 0x42000 maps to RVA 0x41000
    constexpr std::uint32_t kWeldRva = 0x41000;
    constexpr std::uint32_t kNewImageSize = 0x43000;
    const auto put32 = [&source](const std::uint32_t at, const std::uint32_t v) {
        for (unsigned i = 0; i < 4; ++i) {
            source[at + i] = static_cast<std::uint8_t>(v >> (8 * i));
        }
    };
    put32(0x188 + 8, 0x42000);  // .text virtual size covers the weld RVA
    put32(0x188 + 16, 0x42000); // .text raw size reaches the content
    put32(0x98 + 56, kNewImageSize);
    source.resize(kNewImageSize, 0);
    const auto content_at = static_cast<std::size_t>(kWeldRva - 0x1000 + 0x1000);
    for (std::size_t i = 0; i < 0x200; ++i) {
        source[content_at + i] = static_cast<std::uint8_t>(0x5A + (i & 0x1F));
    }

    const auto derived =
        derive_boundary_image(source, "ntdll.dll", boundary_fixture_rules(), kNtdllBase);
    ASSERT_TRUE(derived.has_value()) << derived.error().detail;
    // no weld layout: the image keeps the source's own SizeOfImage, and the
    // retired slot's real bytes survive
    EXPECT_EQ(derived->image.size(), kNewImageSize);
    for (std::size_t i = 0; i < 0x200; ++i) {
        ASSERT_EQ(derived->image[content_at + i], source[content_at + i])
            << "weld-conflict byte 0x" << std::hex << i;
    }
}

TEST(BoundaryDerive, Win32uDerivesWithTheSameMechanism)
{
    // the second boundary-pair member runs the identical real-base
    // mechanism at its own ladder base: same shape contract, same whitelist
    const auto source = make_boundary_source(boundary_fixture_exports(false));
    const auto derived =
        derive_boundary_image(source, "win32u.dll", boundary_fixture_rules(), kWin32uBase);
    ASSERT_TRUE(derived.has_value()) << derived.error().detail;

    const auto info = parse_pe(derived->image);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->image_size, kBoundarySourceFileSize);

    // syscall numbers validated in the source bytes
    const auto* entry = find_export(*derived, "NtCreateFile");
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->kind, BoundaryKind::kSyscallStub);
    EXPECT_EQ(entry->syscall_number, 0x55u);
    EXPECT_EQ(entry->body_rva, kBoundaryStubRva);

    // the whitelist slots land at the export addresses, everything else is
    // the plain loaded image
    const auto plain = plain_loaded_image(source, kWin32uBase);
    ASSERT_TRUE(plain.has_value());
    ASSERT_EQ(derived->image.size(), plain->size());
    for (std::size_t i = 0; i < plain->size(); ++i) {
        const auto at = static_cast<std::uint32_t>(i);
        if ((at >= kBoundaryInterceptRva && at < kBoundaryInterceptRva + 6) ||
            (at >= kBoundaryDataRva && at < kBoundaryDataRva + 8)) {
            continue;
        }
        ASSERT_EQ(derived->image[i], (*plain)[i])
            << "non-whitelist byte differs at 0x" << std::hex << i;
    }
    const auto slot = std::span<const std::uint8_t>(derived->image).subspan(kBoundaryDataRva, 8);
    EXPECT_EQ(0, std::memcmp(slot.data(), boundary_fixture_rules()[5].data_bytes.data(), 8));

    // same input bytes and base twice: byte-identical
    const auto again =
        derive_boundary_image(source, "win32u.dll", boundary_fixture_rules(), kWin32uBase);
    ASSERT_TRUE(again.has_value());
    EXPECT_EQ(0, std::memcmp(derived->image.data(), again->image.data(), derived->image.size()));
}

TEST(BoundaryDerive, OccupiedDataSlotResolvesToTheRealAddress)
{
    // whitelist slot (b) the other way: the real image already provides the
    // slot's content - the manifest's bytes stay out, the disposition
    // resolves to the real address
    auto source = make_boundary_source(boundary_fixture_exports(false));
    for (unsigned i = 0; i < 8; ++i) {
        source[kBoundaryDataRva + i] = static_cast<std::uint8_t>(0x11 * (i + 1));
    }
    const auto derived =
        derive_boundary_image(source, "ntdll.dll", boundary_fixture_rules(), kNtdllBase);
    ASSERT_TRUE(derived.has_value()) << derived.error().detail;
    const auto* data = find_export(*derived, "DataExport");
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(data->body_rva, kBoundaryDataRva);
    for (unsigned i = 0; i < 8; ++i) {
        ASSERT_EQ(derived->image[kBoundaryDataRva + i], source[kBoundaryDataRva + i])
            << "real data byte " << i;
    }
}

TEST(BoundaryDerive, NamedRejections)
{
    // unknown export: no rule covers it
    const auto unknown_source = make_boundary_source(boundary_fixture_exports(true));
    const auto unknown =
        derive_boundary_image(unknown_source, "ntdll.dll", boundary_fixture_rules(), kNtdllBase);
    ASSERT_FALSE(unknown.has_value());
    EXPECT_EQ(unknown.error().code, BoundaryDeriveError::kUnknownExport);
    EXPECT_NE(unknown.error().detail.find("NtUnknown"), std::string::npos);

    // i386 boundary images are not derived (consistent PE32
    // headers: machine and magic flipped together)
    auto x86_source = make_boundary_source(boundary_fixture_exports(false));
    x86_source[0x84] = 0x4C; // machine i386
    x86_source[0x85] = 0x01;
    x86_source[0x98] = 0x0B; // PE32 optional magic
    x86_source[0x99] = 0x01;
    const auto x86 =
        derive_boundary_image(x86_source, "ntdll.dll", boundary_fixture_rules(), kNtdllBase);
    ASSERT_FALSE(x86.has_value());
    EXPECT_EQ(x86.error().code, BoundaryDeriveError::kUnsupportedMachine);

    // a bad data rule (byte count != declared size) is a named rejection
    auto bad_data = boundary_fixture_rules();
    bad_data[5].data_bytes.pop_back();
    const auto source = make_boundary_source(boundary_fixture_exports(false));
    const auto bad = derive_boundary_image(source, "ntdll.dll", bad_data, kNtdllBase);
    ASSERT_FALSE(bad.has_value());
    EXPECT_EQ(bad.error().code, BoundaryDeriveError::kBadRule);

    // duplicate rules are a manifest defect
    auto duplicated = boundary_fixture_rules();
    duplicated.push_back({"NtCreateFile", 0, BoundaryKind::kTrap, 0, "", 0, 0, {}});
    const auto dup = derive_boundary_image(source, "ntdll.dll", duplicated, kNtdllBase);
    ASSERT_FALSE(dup.has_value());
    EXPECT_EQ(dup.error().code, BoundaryDeriveError::kBadRule);

    // a base move with no relocation directory: the named rejection, no
    // half-fixed image (the fixture's reloc block erased)
    auto no_reloc = source;
    for (unsigned i = 0; i < 8; ++i) {
        no_reloc[0x98 + 112 + 5 * 8 + i] = 0;
    }
    const auto unrelocatable =
        derive_boundary_image(no_reloc, "ntdll.dll", boundary_fixture_rules(), kNtdllBase);
    ASSERT_FALSE(unrelocatable.has_value());
    EXPECT_EQ(unrelocatable.error().code, BoundaryDeriveError::kBadSource);
    EXPECT_NE(unrelocatable.error().detail.find("relocation directory"), std::string::npos);

    // a dirty reserved marker slot: the whitelist precondition fails by
    // name, before anything maps
    auto dirty = source;
    dirty[kBoundaryMarkerOffset] = 0x7F;
    const auto marked =
        derive_boundary_image(dirty, "ntdll.dll", boundary_fixture_rules(), kNtdllBase);
    ASSERT_FALSE(marked.has_value());
    EXPECT_EQ(marked.error().code, BoundaryDeriveError::kBadSource);
    EXPECT_NE(marked.error().detail.find("marker slot"), std::string::npos);
}

TEST(BoundaryDerive, WhitelistSlotAfterSectionEndIsNotMapped)
{
    auto source = make_boundary_source({{"Compat", nullptr, 0x3000, {}, {}}});
    // .text covers [0x1000, 0x2800); the export directory is still mapped,
    // but its compat target is in the trailing image gap.
    const std::uint32_t span = 0x1800;
    std::memcpy(source.data() + 0x188 + 8, &span, 4);
    std::memcpy(source.data() + 0x188 + 16, &span, 4);
    const std::vector<BoundaryRule> rules{{"Compat", 0, BoundaryKind::kCompat, 5, "", 0, 0, {}}};
    const auto derived = derive_boundary_image(source, "other.dll", rules, kWin32uBase);
    ASSERT_FALSE(derived.has_value());
    EXPECT_EQ(derived.error().code, BoundaryDeriveError::kBadSource);
}

TEST(BoundaryDerive, WhitelistCanUseTheFullyCopiedHeaderSpan)
{
    // SizeOfHeaders is 0x1000. The old 0x400 floor is not its upper bound.
    const auto source = make_boundary_source({{"Compat", nullptr, 0x500, {}, {}}});
    const std::vector<BoundaryRule> rules{{"Compat", 0, BoundaryKind::kCompat, 5, "", 0, 0, {}}};
    const auto derived = derive_boundary_image(source, "other.dll", rules, kWin32uBase);
    ASSERT_TRUE(derived.has_value()) << derived.error().detail;
    EXPECT_NE(derived->image[0x500], 0);
}

TEST(BoundaryDerive, DerivedExportsIndexAndForwardChain)
{
    // module A: the boundary target (Nt stubs + one alias pair)
    const auto source_a = make_boundary_source(boundary_fixture_exports(false));
    const auto derived_a =
        derive_boundary_image(source_a, "ntdll.dll", boundary_fixture_rules(), kNtdllBase);
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
    const auto derived_b = derive_boundary_image(source_b, "other.dll", rules_b, kWin32uBase);
    ASSERT_TRUE(derived_b.has_value()) << derived_b.error().detail;

    // the existing loader-side index walks the derived images: every named
    // export is present with its source address (base + source EAT RVA)
    std::vector<LoadedModule> modules(2);
    modules[0].base = kNtdllBase;
    modules[0].image = derived_a->image;
    std::memcpy(modules[0].name.data(), "fakentdll.dll", 13);
    modules[1].base = kWin32uBase;
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
    for (const auto* name : {"NtCreateFile", "ZwCreateFile"}) {
        const auto it = std::find_if(modules[0].exports.begin(), modules[0].exports.end(),
                                     [&](const auto& e) { return e.first == name; });
        ASSERT_NE(it, modules[0].exports.end()) << name;
        EXPECT_EQ(it->second, modules[0].base + body_rva_of(*derived_a, name));
    }
    // the EAT keeps the source addresses: the unnamed stub's recorded
    // address is its own source slot
    EXPECT_EQ(body_rva_of(*derived_a, ""), kBoundaryUnnamedStubRva);

    // alias pairs resolve to one shared VA (the source slot they both name)
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
