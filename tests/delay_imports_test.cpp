// Eager delayed-import binding unit tests: the
// construction-time policy over DataDirectory[13] - RVA-form descriptors
// resolve against the resident set and the IAT slots take the final VAs,
// and that is the whole write set (the capture corpus's .didat records:
// timestamp fields, module-handle slots, bound-IAT copies and unload
// tables stay at their file bytes). VA-form and out-of-range descriptors
// are the named rejection, name and ordinal thunks both bind, forwarders
// resolve along the chain, a missing delayed dependency lands in the
// unresolved record (the caller's named rejection), and the closure-mode
// walk (write=false) reports without touching the image. Portable by
// design: self-made fixtures, no host DLLs.

#include "imports.h"
#include "loader.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

namespace {

using namespace sheller::loader;

constexpr std::uint64_t kImageBase = 0x400000;
constexpr std::uint32_t kTextRva = 0x1000;
constexpr std::uint32_t kDirRva = 0x2000;   // export directory
constexpr std::uint32_t kDelayRva = 0x2800; // delay-import descriptors
constexpr std::uint32_t kNameRva = 0x2900;  // descriptor dll name
constexpr std::uint32_t kIntRva = 0x2980;   // INT thunks
constexpr std::uint32_t kIatRva = 0x2A00;   // delay IAT slots
constexpr std::uint32_t kHintRva = 0x2B00;  // hint/name entry
constexpr std::size_t kFileSize = 0x4000;

void put16(std::vector<std::uint8_t>& f, std::uint32_t at, std::uint16_t v)
{
    f[at] = static_cast<std::uint8_t>(v);
    f[at + 1] = static_cast<std::uint8_t>(v >> 8);
}

void put32(std::vector<std::uint8_t>& f, std::uint32_t at, std::uint32_t v)
{
    for (unsigned i = 0; i < 4; ++i) {
        f[at + i] = static_cast<std::uint8_t>(v >> (8 * i));
    }
}

void put64(std::vector<std::uint8_t>& f, std::uint32_t at, std::uint64_t v)
{
    for (unsigned i = 0; i < 8; ++i) {
        f[at + i] = static_cast<std::uint8_t>(v >> (8 * i));
    }
}

void put_string(std::vector<std::uint8_t>& f, std::uint32_t at, const std::string& text)
{
    std::memcpy(f.data() + at, text.data(), text.size());
    f[at + text.size()] = 0;
}

std::uint64_t read_le64(const std::vector<std::uint8_t>& f, std::uint32_t at)
{
    std::uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) {
        v |= static_cast<std::uint64_t>(f[at + i]) << (8 * i);
    }
    return v;
}

// The delay-importing image: one section (RVA == file offset), an export
// directory with a direct export and a forwarder, and one RVA-form delay
// descriptor naming "hostb.dll" with a by-name and a by-ordinal thunk.
std::vector<std::uint8_t> make_delay_importer()
{
    std::vector<std::uint8_t> f(kFileSize, std::uint8_t{0});
    put16(f, 0, 0x5A4D);
    put32(f, 0x3C, 0x80);
    put32(f, 0x80, 0x00004550);
    put16(f, 0x84, 0x8664);
    put16(f, 0x86, 1);
    put16(f, 0x94, 0xF0);
    put16(f, 0x96, 0x2022);
    put16(f, 0x98, 0x020B);
    put32(f, 0x98 + 24, kImageBase);
    put32(f, 0x98 + 32, 0x1000);
    put32(f, 0x98 + 36, 0x1000);
    put32(f, 0x98 + 56, kFileSize);
    put32(f, 0x98 + 60, 0x1000);
    put32(f, 0x98 + 108, 16);
    // section table at 0x188
    put32(f, 0x188 + 8, 0x3000);
    put32(f, 0x188 + 12, kTextRva);
    put32(f, 0x188 + 16, 0x3000);
    put32(f, 0x188 + 20, kTextRva);
    put32(f, 0x188 + 36, 0x60000020);

    // export directory: DirectExport -> 0x1000, ForwardedExport -> forwarder
    const std::uint32_t eat_rva = kDirRva + 40;
    const std::uint32_t names_rva = eat_rva + 8;
    const std::uint32_t ordinals_rva = names_rva + 8;
    std::uint32_t cursor = ordinals_rva + 4;
    const std::uint32_t module_name_rva = cursor;
    put_string(f, cursor, "hosta.dll");
    cursor += 8;
    const std::uint32_t direct_name_rva = cursor;
    put_string(f, cursor, "DirectExport");
    cursor += 14;
    const std::uint32_t fwd_name_rva = cursor;
    put_string(f, cursor, "ForwardedExport");
    cursor += 16;
    const std::uint32_t fwd_string_rva = cursor;
    put_string(f, cursor, "hostb.TargetExport");
    put32(f, kDirRva + 0x0C, module_name_rva);
    put32(f, kDirRva + 0x10, 0);
    put32(f, kDirRva + 0x14, 2);
    put32(f, kDirRva + 0x18, 2);
    put32(f, kDirRva + 0x1C, eat_rva);
    put32(f, kDirRva + 0x20, names_rva);
    put32(f, kDirRva + 0x24, ordinals_rva);
    put32(f, eat_rva, kTextRva);
    put32(f, eat_rva + 4, fwd_string_rva);
    put32(f, names_rva, direct_name_rva);
    put16(f, ordinals_rva, 0);
    put32(f, names_rva + 4, fwd_name_rva);
    put16(f, ordinals_rva + 2, 1);
    put32(f, 0x98 + 112, kDirRva);
    put32(f, 0x98 + 116, cursor + 22 - kDirRva);

    // the delay descriptor: RVA form, name/INT/IAT at their RVAs; the
    // timestamp and module-handle fields carry non-zero FILE bytes on
    // purpose - the evidence pin proves the binding leaves them alone
    put32(f, kDelayRva + 0, 1); // grAttrs: dlattrRva
    put32(f, kDelayRva + 4, kNameRva);
    put32(f, kDelayRva + 8, 0x2C00); // phmod: points at scratch bytes
    put32(f, kDelayRva + 12, kIatRva);
    put32(f, kDelayRva + 16, kIntRva);
    put32(f, kDelayRva + 20, 0x3000); // pBoundIAT scratch
    put32(f, kDelayRva + 24, 0);
    put32(f, kDelayRva + 28, 0xDEADBEEF); // dwTimeStamp file byte
    put_string(f, kNameRva, "hostb.dll");
    // INT: by-name thunk (the hint/name RVA - the name starts at +2),
    // by-ordinal thunk (ordinal 2)
    put64(f, kIntRva, kHintRva);
    put64(f, kIntRva + 8, 0x8000000000000000ULL | 2);
    put64(f, kIntRva + 16, 0);
    // IAT mirrors the INT until binding
    put64(f, kIatRva, kHintRva);
    put64(f, kIatRva + 8, 0x8000000000000000ULL | 2);
    put64(f, kIatRva + 16, 0);
    put16(f, kHintRva, 0); // the hint word
    put_string(f, kHintRva + 2, "TargetExport");
    put32(f, 0x98 + 112 + 13 * 8, kDelayRva);
    put32(f, 0x98 + 112 + 13 * 8 + 4, 0x40);
    // pre-fill the fields the binding must not touch
    put64(f, 0x2C00, 0x1111111111111111ULL); // the phmod slot scratch
    put64(f, 0x3000, 0x2222222222222222ULL); // bound-IAT scratch
    return f;
}

// The bound target: hostb.dll exporting TargetExport as EAT index 2 (the
// ordinal-2 thunk lands there) and under its name.
std::vector<std::uint8_t> make_target()
{
    std::vector<std::uint8_t> f(kFileSize, std::uint8_t{0});
    put16(f, 0, 0x5A4D);
    put32(f, 0x3C, 0x80);
    put32(f, 0x80, 0x00004550);
    put16(f, 0x84, 0x8664);
    put16(f, 0x86, 1);
    put16(f, 0x94, 0xF0);
    put16(f, 0x96, 0x2022);
    put16(f, 0x98, 0x020B);
    put32(f, 0x98 + 24, kImageBase);
    put32(f, 0x98 + 32, 0x1000);
    put32(f, 0x98 + 36, 0x1000);
    put32(f, 0x98 + 56, kFileSize);
    put32(f, 0x98 + 60, 0x1000);
    put32(f, 0x98 + 108, 16);
    put32(f, 0x188 + 8, 0x3000);
    put32(f, 0x188 + 12, kTextRva);
    put32(f, 0x188 + 16, 0x3000);
    put32(f, 0x188 + 20, kTextRva);
    put32(f, 0x188 + 36, 0x60000020);
    // three EAT slots so ordinal 2 exists; slot 2 is the body
    const std::uint32_t eat_rva = kDirRva + 40;
    const std::uint32_t names_rva = eat_rva + 12;
    const std::uint32_t ordinals_rva = names_rva + 4;
    std::uint32_t cursor = ordinals_rva + 2;
    const std::uint32_t module_name_rva = cursor;
    put_string(f, cursor, "hostb.dll");
    cursor += 9;
    const std::uint32_t name_rva = cursor;
    put_string(f, cursor, "TargetExport");
    put32(f, kDirRva + 0x0C, module_name_rva);
    put32(f, kDirRva + 0x10, 0);
    put32(f, kDirRva + 0x14, 3);
    put32(f, kDirRva + 0x18, 1);
    put32(f, kDirRva + 0x1C, eat_rva);
    put32(f, kDirRva + 0x20, names_rva);
    put32(f, kDirRva + 0x24, ordinals_rva);
    put32(f, eat_rva, 0);
    put32(f, eat_rva + 4, 0);
    put32(f, eat_rva + 8, kTextRva + 0x10);
    put32(f, names_rva, name_rva);
    put16(f, ordinals_rva, 2);
    put32(f, 0x98 + 112, kDirRva);
    put32(f, 0x98 + 116, cursor + 13 - kDirRva);
    return f;
}

std::vector<LoadedModule> resident_pair(const std::vector<std::uint8_t>& importer,
                                        const std::vector<std::uint8_t>& target)
{
    std::vector<LoadedModule> modules(2);
    modules[0].base = 0x7FF800000000ULL;
    modules[0].image = importer;
    std::memcpy(modules[0].name.data(), "hosta.dll", 9);
    modules[1].base = 0x7FF900000000ULL;
    modules[1].image = target;
    std::memcpy(modules[1].name.data(), "hostb.dll", 9);
    static_cast<void>(index_exports(modules[0]));
    static_cast<void>(index_exports(modules[1]));
    return modules;
}

TEST(DelayImports, RvaDescriptorBindsFinalVasAndNothingElse)
{
    const auto importer = make_delay_importer();
    const auto target = make_target();
    auto modules = resident_pair(importer, target);
    std::vector<UnresolvedImport> unresolved;
    const auto bound = bind_delayed_imports(modules[0].image, modules, &unresolved, ApiSetContext{},
                                            "hosta.dll", true);
    ASSERT_TRUE(bound.has_value());
    EXPECT_TRUE(unresolved.empty());
    ASSERT_EQ(bound->size(), 2u); // by-name + by-ordinal

    // both slots carry the final resolved VAs: the by-name thunk and the
    // ordinal-2 thunk land on the same target body
    const auto expected = modules[1].base + (kTextRva + 0x10);
    const auto slot0 = read_le64(modules[0].image, kIatRva);
    const auto slot1 = read_le64(modules[0].image, kIatRva + 8);
    EXPECT_EQ(slot0, expected);
    EXPECT_EQ(slot1, expected);
    EXPECT_EQ((*bound)[0].iat_rva, kIatRva);
    EXPECT_EQ((*bound)[1].iat_rva, kIatRva + 8);

    // the write set is the IAT slots ALONE (the capture evidence): the
    // descriptor timestamp, the module-handle slot and the bound-IAT
    // scratch keep their pre-bind bytes
    std::vector<std::uint8_t> untouched(kFileSize, 0);
    std::memcpy(untouched.data(), importer.data(), kFileSize);
    put64(untouched, kIatRva, expected);
    put64(untouched, kIatRva + 8, expected);
    EXPECT_EQ(0, std::memcmp(modules[0].image.data(), untouched.data(), kFileSize))
        << "the binding wrote outside the delay IAT slots";
}

TEST(DelayImports, ForwarderDescriptorResolvesAlongTheChain)
{
    auto importer = make_delay_importer();
    // the descriptor's name becomes "hosta.dll" (the forwarder owner): its
    // ForwardedExport resolves through the chain into hostb's body (both
    // thunks go by name - hosta has no ordinal 2)
    put_string(importer, kNameRva, "hosta.dll");
    put_string(importer, kHintRva + 2, "ForwardedExport");
    put64(importer, kIntRva + 8, kHintRva);
    put64(importer, kIatRva + 8, kHintRva);
    const auto target = make_target();
    auto modules = resident_pair(importer, target);
    std::vector<UnresolvedImport> unresolved;
    const auto bound = bind_delayed_imports(modules[0].image, modules, &unresolved, ApiSetContext{},
                                            "hosta.dll", true);
    ASSERT_TRUE(bound.has_value());
    EXPECT_TRUE(unresolved.empty());
    ASSERT_EQ(bound->size(), 2u);
    const auto expected = modules[1].base + (kTextRva + 0x10);
    EXPECT_EQ(read_le64(modules[0].image, kIatRva), expected);
}

TEST(DelayImports, MissingDelayedDependencyIsToleratedWithFileBytes)
{
    // the capture corpus's rule: a delayed dependency that cannot resolve -
    // module absent or export missing - keeps its file bytes (MSVC's static
    // failure thunks are exactly what the captured world carries), and the
    // miss is not reported as unresolved
    auto importer = make_delay_importer();
    put_string(importer, kNameRva, "nowhere.dll");
    const auto target = make_target();
    auto modules = resident_pair(importer, target);
    std::vector<UnresolvedImport> unresolved;
    const auto bound = bind_delayed_imports(modules[0].image, modules, &unresolved, ApiSetContext{},
                                            "hosta.dll", true);
    ASSERT_TRUE(bound.has_value());
    EXPECT_TRUE(unresolved.empty()) << "tolerated misses are never reported";
    EXPECT_TRUE(bound->empty()); // nothing resolved: nothing written
    // the slots keep their file bytes: the static failure thunks
    EXPECT_EQ(read_le64(modules[0].image, kIatRva), kHintRva);
    EXPECT_EQ(read_le64(modules[0].image, kIatRva + 8), 0x8000000000000000ULL | 2);
}

TEST(DelayImports, VaFormDescriptorIsTheNamedRejection)
{
    auto importer = make_delay_importer();
    // grAttrs bit 0 clear: VA-addressed legacy descriptor - no base guessing
    put32(importer, kDelayRva, 0);
    const auto target = make_target();
    auto modules = resident_pair(importer, target);
    std::vector<UnresolvedImport> unresolved;
    const auto bound = bind_delayed_imports(modules[0].image, modules, &unresolved, ApiSetContext{},
                                            "hosta.dll", true);
    ASSERT_FALSE(bound.has_value());
    EXPECT_EQ(bound.error(), LoadError::kBadDelayImport);
}

TEST(DelayImports, UnmappedContractAndMissingExportPreserveEveryInputByte)
{
    for (const bool unmapped : {false, true}) {
        auto image = make_delay_importer();
        if (unmapped) {
            put_string(image, kNameRva, "api-ms-not-in-map-l1-1-0.dll");
        } else {
            put_string(image, kHintRva + 2, "AbsentExport");
            put64(image, kIntRva + 8, kHintRva);
        }
        const auto before = image;
        auto modules = resident_pair(image, make_target());
        ApiSetContext ctx;
        ctx.mode = ApiSetContext::Mode::kDirectoryMap;
        const auto result = bind_delayed_imports(image, modules, nullptr, ctx, "hosta.dll", true);
        ASSERT_TRUE(result.has_value());
        EXPECT_TRUE(result->empty());
        EXPECT_EQ(image, before);
    }
}

TEST(DelayImports, OutOfRangeDescriptorIsTheNamedRejection)
{
    {
        // the INT points past the image
        auto importer = make_delay_importer();
        put32(importer, kDelayRva + 16, kFileSize + 0x100);
        const auto target = make_target();
        auto modules = resident_pair(importer, target);
        std::vector<UnresolvedImport> unresolved;
        const auto bound = bind_delayed_imports(modules[0].image, modules, &unresolved,
                                                ApiSetContext{}, "hosta.dll", true);
        ASSERT_FALSE(bound.has_value());
        EXPECT_EQ(bound.error(), LoadError::kBadDelayImport);
    }
    {
        // the descriptor array runs off the image without a terminator
        auto importer = make_delay_importer();
        put32(importer, 0x98 + 112 + 13 * 8 + 4, kFileSize); // directory size huge
        for (std::size_t at = kDelayRva + 32; at + 32 <= kFileSize; at += 32) {
            put32(importer, static_cast<std::uint32_t>(at), 1); // non-zero grAttrs
        }
        const auto target = make_target();
        auto modules = resident_pair(importer, target);
        std::vector<UnresolvedImport> unresolved;
        const auto bound = bind_delayed_imports(modules[0].image, modules, &unresolved,
                                                ApiSetContext{}, "hosta.dll", true);
        ASSERT_FALSE(bound.has_value());
        EXPECT_EQ(bound.error(), LoadError::kBadDelayImport);
    }
}

TEST(DelayImports, OutOfRangeDirectoryRvaIsTheNamedRejection)
{
    // directory(13) naming bytes past the image is malformed - the named
    // rejection, never a silent "no delay imports"
    auto importer = make_delay_importer();
    put32(importer, 0x98 + 112 + 13 * 8, kFileSize + 0x100);
    const auto target = make_target();
    auto modules = resident_pair(importer, target);
    std::vector<UnresolvedImport> unresolved;
    const auto bound = bind_delayed_imports(modules[0].image, modules, &unresolved, ApiSetContext{},
                                            "hosta.dll", true);
    ASSERT_FALSE(bound.has_value());
    EXPECT_EQ(bound.error(), LoadError::kBadDelayImport);
}

TEST(DelayImports, OutOfRangeHintThunkIsTheNamedRejection)
{
    // a by-name thunk whose hint/name RVA leaves the image is a malformed
    // descriptor - the named rejection, never a tolerated miss with an
    // empty-name lookup
    auto importer = make_delay_importer();
    put64(importer, kIntRva, kFileSize - 1);
    const auto target = make_target();
    auto modules = resident_pair(importer, target);
    std::vector<UnresolvedImport> unresolved;
    const auto bound = bind_delayed_imports(modules[0].image, modules, &unresolved, ApiSetContext{},
                                            "hosta.dll", true);
    ASSERT_FALSE(bound.has_value());
    EXPECT_EQ(bound.error(), LoadError::kBadDelayImport);
}

TEST(DelayImports, ClosureWalkReportsWithoutWriting)
{
    const auto importer = make_delay_importer();
    const auto target = make_target();
    auto modules = resident_pair(importer, target);
    std::vector<UnresolvedImport> unresolved;
    const auto checked = bind_delayed_imports(modules[0].image, modules, &unresolved,
                                              ApiSetContext{}, "hosta.dll", false);
    ASSERT_TRUE(checked.has_value());
    EXPECT_TRUE(unresolved.empty());
    ASSERT_EQ(checked->size(), 2u); // the resolutions are reported...
    // ...but the image keeps its file bytes everywhere
    EXPECT_EQ(0, std::memcmp(modules[0].image.data(), importer.data(), kFileSize));
}

TEST(DelayImports, NoDelayDirectoryIsACleanNoop)
{
    const auto target = make_target();
    std::vector<LoadedModule> modules(1);
    modules[0].base = 0x7FF900000000ULL;
    modules[0].image = target;
    std::memcpy(modules[0].name.data(), "hostb.dll", 9);
    static_cast<void>(index_exports(modules[0]));
    std::vector<UnresolvedImport> unresolved;
    const auto bound = bind_delayed_imports(modules[0].image, modules, &unresolved, ApiSetContext{},
                                            "hostb.dll", true);
    ASSERT_TRUE(bound.has_value());
    EXPECT_TRUE(bound->empty());
    EXPECT_TRUE(unresolved.empty());
}

TEST(DelayImports, MalformedStructureNeverBecomesAToleratedMiss)
{
    for (const auto field : {8u, 20u, 24u}) {
        auto image = make_delay_importer();
        put32(image, kDelayRva + field, kFileSize - 1);
        EXPECT_FALSE(bind_delayed_imports(image, {}, nullptr, {}, {}, true).has_value()) << field;
    }
    for (const auto size : {1u, 31u, 32u, 63u}) {
        auto image = make_delay_importer();
        put32(image, 0x98 + 112 + 13 * 8 + 4, size);
        EXPECT_FALSE(bind_delayed_imports(image, {}, nullptr, {}, {}, true).has_value()) << size;
    }
    for (const auto field : {20u, 24u}) {
        auto image = make_delay_importer();
        put32(image, kDelayRva + 32 + field, 1); // nonzero partial terminator
        EXPECT_FALSE(bind_delayed_imports(image, {}, nullptr, {}, {}, true).has_value());
    }
    for (const auto thunk : {0x100002B00ULL, 0x8000000000010002ULL}) {
        auto image = make_delay_importer();
        put64(image, kIntRva, thunk);
        EXPECT_FALSE(bind_delayed_imports(image, {}, nullptr, {}, {}, true).has_value());
    }
    auto image = make_delay_importer();
    std::fill(image.begin() + kHintRva + 2, image.end(), 'x');
    EXPECT_FALSE(bind_delayed_imports(image, {}, nullptr, {}, {}, true).has_value());
}

TEST(DelayImports, StaticImportsValidateAndDiscoverWithoutOverwritingLookup)
{
    auto image = make_delay_importer();
    // Ordinary import descriptor with no separate lookup table: FirstThunk
    // is both the lookup and destination. Discovery must leave it untouched.
    put32(image, 0x98 + 112 + 8, 0x2700);
    put32(image, 0x98 + 112 + 12, 40);
    put32(image, 0x2700 + 12, kNameRva);
    put32(image, 0x2700 + 16, kIatRva);
    auto modules = resident_pair(image, make_target());
    const auto before = image;
    auto discovered = resolve_imports(image, modules, nullptr, {}, {}, false);
    ASSERT_TRUE(discovered.has_value());
    EXPECT_EQ(image, before);
    ASSERT_EQ(discovered->size(), 2u);
    auto bound = resolve_imports(image, modules, nullptr);
    ASSERT_TRUE(bound.has_value());
    EXPECT_EQ(read_le64(image, kIatRva), 0x7FF900001010ULL);
    for (const auto rva : {kFileSize, kFileSize - 4}) {
        auto bad = before;
        put32(bad, 0x98 + 112 + 8, static_cast<std::uint32_t>(rva));
        ApiSetContext strict;
        strict.mode = ApiSetContext::Mode::kDirectoryMap;
        const auto result = resolve_imports(bad, modules, nullptr, strict, {});
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), LoadError::kBadImport);
    }
}

} // namespace
