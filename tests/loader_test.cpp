// Loader core unit tests: parse, layout, relocations and TLS
// extraction are pure byte functions - all driven here without unicorn.
// The KUSER environment fields join here: the fixed infrastructure page
// (NtSystemRoot included) and its double-construction identity.

#include "env.h"
#include "loader.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

using namespace sheller::loader;

std::uint16_t peek16(const std::vector<std::uint8_t>& bytes, std::size_t offset)
{
    std::uint16_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof value);
    return value;
}

TEST(LoaderEnv, KuserSystemRootShapeAndDoubleBuildIdentity)
{
    std::vector<std::uint8_t> first(0x1000, std::uint8_t{0});
    std::vector<std::uint8_t> second(0x1000, std::uint8_t{0});
    fill_kuser_shared_data(first);
    fill_kuser_shared_data(second);
    // double construction: byte-identical
    ASSERT_EQ(first.size(), second.size());
    EXPECT_EQ(0, std::memcmp(first.data(), second.data(), first.size()));

    // the NtSystemRoot field: UTF-16 `c:\windows` at 0x30 (the capture
    // spelling, lowercase, NUL-terminated) - a shell's PEB walk reads it
    static const std::uint8_t kExpected[] = {
        'c',  0x00, ':',  0x00, '\\', 0x00, 'w',  0x00, 'i',  0x00, 'n',
        0x00, 'd',  0x00, 'o',  0x00, 'w',  0x00, 's',  0x00, 0x00, 0x00}; // "c:\windows" + NUL
    EXPECT_EQ(0, std::memcmp(first.data() + 0x30, kExpected, sizeof kExpected));
    // nothing spills past the field
    for (std::size_t i = 0x30 + sizeof kExpected; i < 0x40; ++i) {
        ASSERT_EQ(first[i], 0) << "byte 0x" << std::hex << i;
    }
    // the time-varying pair keeps its existing fixed values
    EXPECT_EQ(first[0x14 + 7], 0x01); // the fixed file time's high byte
    EXPECT_EQ(first[0x320], 0x00);    // the fixed tick's low byte
}

TEST(LoaderEnv, KuserShortPageIsLeftAlone)
{
    std::vector<std::uint8_t> tiny(0x100, std::uint8_t{0xAB});
    fill_kuser_shared_data(tiny);
    for (const auto b : tiny) {
        ASSERT_EQ(b, 0xAB); // below the field floor: untouched
    }
}

TEST(LoaderEnv, ChainOrdersThreadEachChainByItsOwnRecord)
{
    // the capture corpus's three-chain record: load/memory lead with the
    // main image; init excludes it and runs ntdll, kernelbase, kernel32 -
    // one chain's order never extrapolates onto another
    const std::uint64_t env_base = 0x02000000;
    // module order: entry last (the images order), the record's members
    const std::vector<EnvModule> modules{{0x7FF800000000ULL, 0x268000, "ntdll.dll"},
                                         {0x7FF900000000ULL, 0xCB000, "kernel32.dll"},
                                         {0x7FFA00000000ULL, 0x401000, "kernelbase.dll"},
                                         {0x400000, 0x2000, "sheller_run.exe"}};
    const std::size_t entry = 3;
    ChainOrders orders;
    orders.load = {entry, 0, 1, 2};
    orders.memory = {entry, 0, 1, 2};
    orders.init = {0, 2, 1}; // the record: no main image, kernelbase before kernel32
    const auto build =
        build_environment(env_base, 0x400000, 0x300000, 0x200000, 0x4000000, modules, orders)
            .value();
    ASSERT_EQ(build.env.size(), static_cast<std::size_t>(kEnvBlockSize));

    const std::size_t node_base = static_cast<std::size_t>(kEnvLdrOffset) + 0x58;
    const auto peek64 = [&](std::size_t offset) {
        std::uint64_t value = 0;
        std::memcpy(&value, build.env.data() + offset, sizeof value);
        return value;
    };
    // walk each chain by Flink from its head; the sequence of node slots
    // maps back to member indices, checked against the order
    const auto walk = [&](std::size_t chain) {
        const std::size_t head = static_cast<std::size_t>(kEnvLdrOffset) + 0x10 + chain * 0x10;
        std::vector<std::size_t> sequence;
        std::uint64_t link = peek64(head);
        bool closed = false;
        for (std::size_t step = 0; step <= modules.size(); ++step) {
            const std::size_t at = static_cast<std::size_t>(link - env_base);
            if (at == head) {
                closed = true; // back at the head: closed
                break;
            }
            const std::size_t slot = at - node_base;
            const std::size_t index =
                (slot - chain * 0x10) / static_cast<std::size_t>(kLdrEntryStride);
            sequence.push_back(index);
            link = peek64(at);
        }
        EXPECT_TRUE(closed) << "chain " << chain << " does not close at its head";
        return sequence;
    };
    EXPECT_EQ(walk(0), (std::vector<std::size_t>{entry, 0, 1, 2})); // load
    EXPECT_EQ(walk(1), (std::vector<std::size_t>{entry, 0, 1, 2})); // memory
    EXPECT_EQ(walk(2), (std::vector<std::size_t>{0, 2, 1}));        // init: no main image
}

TEST(LoaderEnv, DefaultOrdersKeepArgumentSequenceEverywhere)
{
    // no orders: the pre-record shape - every chain in argument order
    const std::uint64_t env_base = 0x02000000;
    const std::vector<EnvModule> modules{{0x7FF800000000ULL, 0x268000, "ntdll.dll"},
                                         {0x400000, 0x2000, "sample.exe"}};
    const auto build =
        build_environment(env_base, 0x400000, 0x300000, 0x200000, 0x4000000, modules).value();
    const std::size_t node_base = static_cast<std::size_t>(kEnvLdrOffset) + 0x58;
    const auto peek64 = [&](std::size_t offset) {
        std::uint64_t value = 0;
        std::memcpy(&value, build.env.data() + offset, sizeof value);
        return value;
    };
    for (std::size_t chain = 0; chain < 3; ++chain) {
        const std::size_t head = static_cast<std::size_t>(kEnvLdrOffset) + 0x10 + chain * 0x10;
        EXPECT_EQ(peek64(head), env_base + node_base + chain * 0x10) << "chain " << chain;
    }
}

TEST(LoaderEnv, LdrEntryNamesAreUtf16WithByteLengths)
{
    // the static entries carry the same name conventions as the runtime
    // insertions and real captures: one UTF-16LE buffer + u16 NUL, UNICODE_STRING
    // Length counting bytes - a wchar-wise name walk (every read 2 bytes) compares
    // equal, and a wide read of the buffer yields the folded name
    const std::uint64_t env_base = 0x02000000;
    const std::vector<EnvModule> modules{{0x400000, 0x2000, "sample.exe"},
                                         {0x7FF800000000ULL, 0x268000, "ntdll.dll"}};
    const auto build =
        build_environment(env_base, 0x400000, 0x300000, 0x200000, 0x4000000, modules).value();
    const std::size_t node_base = static_cast<std::size_t>(kEnvLdrOffset) + 0x58;
    for (std::size_t i = 0; i < modules.size(); ++i) {
        const auto block = node_base + i * static_cast<std::size_t>(kLdrEntryStride);
        const auto length = static_cast<std::uint16_t>(2 * modules[i].name.size());
        // both UNICODE_STRINGs: Length bytes, MaximumLength adds the terminator
        EXPECT_EQ(peek16(build.env, block + 0x48), length) << "module " << i;
        EXPECT_EQ(peek16(build.env, block + 0x4A), length + 2) << "module " << i;
        EXPECT_EQ(peek16(build.env, block + 0x58), length) << "module " << i;
        EXPECT_EQ(peek16(build.env, block + 0x5A), length + 2) << "module " << i;
        // the buffer: UTF-16LE text, u16 NUL, nothing spills past the pair
        const auto buffer_at = block + 0x80;
        for (std::size_t c = 0; c < modules[i].name.size(); ++c) {
            EXPECT_EQ(build.env[buffer_at + 2 * c], static_cast<std::uint8_t>(modules[i].name[c]))
                << "module " << i << " char " << c;
            EXPECT_EQ(build.env[buffer_at + 2 * c + 1], 0) << "module " << i << " char " << c;
        }
        EXPECT_EQ(build.env[buffer_at + length], 0) << "module " << i;
        EXPECT_EQ(build.env[buffer_at + length + 1], 0) << "module " << i;
    }
}

TEST(LoaderEnv, OverlongEntryNameIsANamedRefusal)
{
    // exactly 64 characters need 130 bytes and the +0x80 buffer holds 0x80:
    // the build refuses by name instead of truncating (a truncated name
    // would be a second, quieter walk-breaking name)
    const std::uint64_t env_base = 0x02000000;
    const std::vector<EnvModule> modules{{0x400000, 0x2000, std::string(60, 'a') + ".dll"}};
    const auto refused =
        build_environment(env_base, 0x400000, 0x300000, 0x200000, 0x4000000, modules);
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().name, modules[0].name);
}

TEST(LoaderEnv, ExactlyFullEntryNameStillBuilds)
{
    // 63 characters need 2*63+2 = 0x80 bytes: exactly the +0x80 buffer, so
    // the refusal guard stays exclusive - one more char (the 64-char refusal
    // above) is what flips it
    const std::uint64_t env_base = 0x02000000;
    const std::vector<EnvModule> modules{{0x400000, 0x2000, std::string(63, 'a')}};
    const auto build =
        build_environment(env_base, 0x400000, 0x300000, 0x200000, 0x4000000, modules).value();
    const auto block = static_cast<std::size_t>(kEnvLdrOffset) + 0x58;
    EXPECT_EQ(peek16(build.env, block + 0x48), 126); // FullDllName.Length
    EXPECT_EQ(peek16(build.env, block + 0x4A), 128); // MaximumLength fills the buffer
    EXPECT_EQ(peek16(build.env, block + 0x58), 126); // BaseDllName.Length
    EXPECT_EQ(peek16(build.env, block + 0x5A), 128);
    // the shared buffer is exactly full: the u16 NUL lands on its last two bytes
    const auto buffer_at = block + 0x80;
    EXPECT_EQ(build.env[buffer_at + 0xFE], 0);
    EXPECT_EQ(build.env[buffer_at + 0xFF], 0);
}

// Minimal x64 PE32+ file: headers at 0x0, one section at raw 0x200 mapped at
// RVA 0x1000, a relocation block and a TLS directory inside the section.
// FILE offset = section raw pointer + (RVA - 0x1000) for section bytes.
struct TinyPe {
    std::vector<std::uint8_t> bytes;
    std::uint64_t image_base = 0x140000000ULL;
    std::uint64_t image_size = 0x2000;
    std::uint32_t entry_rva = 0x1000;
    std::uint32_t tls_dir_rva = 0x1000;   // image RVA of the TLS directory
    std::uint32_t reloc_dir_rva = 0x1100; // image RVA of the relocation block

    void put32(std::size_t offset, std::uint32_t value)
    {
        std::memcpy(&bytes[offset], &value, sizeof value);
    }
    void put16(std::size_t offset, std::uint16_t value)
    {
        std::memcpy(&bytes[offset], &value, sizeof value);
    }
    void put64(std::size_t offset, std::uint64_t value)
    {
        std::memcpy(&bytes[offset], &value, sizeof value);
    }
};

TinyPe make_tiny_pe()
{
    TinyPe t;
    t.bytes.assign(0x400, 0);
    t.bytes[0] = 'M';
    t.bytes[1] = 'Z';
    t.put32(0x3C, 0x40);        // e_lfanew
    t.put32(0x40, 0x00004550);  // PE signature
    t.put16(0x44, 0x8664);      // machine AMD64
    t.put16(0x46, 1);           // one section
    t.put16(0x54, 0xF0);        // SizeOfOptionalHeader
    t.put16(0x56, 0x0022);      // characteristics
    t.put16(0x58, 0x020B);      // PE32+
    t.bytes[0x5A] = 1;          // linker major
    t.put32(0x5C, 0x200);       // SizeOfCode
    t.put32(0x68, t.entry_rva); // AddressOfEntryPoint
    t.put32(0x6C, 0x1000);      // BaseOfCode
    t.put64(0x70, t.image_base);
    t.put32(0x78, 0x1000); // SectionAlignment
    t.put32(0x7C, 0x200);  // FileAlignment
    t.put32(0x90, static_cast<std::uint32_t>(t.image_size));
    t.put32(0x94, 0x200); // SizeOfHeaders
    // data directories: [5] relocation, [9] TLS
    t.put32(0xC8 + 5 * 8, t.reloc_dir_rva);
    t.put32(0xC8 + 5 * 8 + 4, 0x10);
    t.put32(0xC8 + 9 * 8, t.tls_dir_rva);
    t.put32(0xC8 + 9 * 8 + 4, 0x40);
    // section header at opt(0x58) + 0xF0 = 0x148: ".text"
    std::memcpy(&t.bytes[0x148], ".text", 5);
    t.put32(0x148 + 8, 0x200);       // VirtualSize
    t.put32(0x148 + 12, 0x1000);     // VirtualAddress
    t.put32(0x148 + 16, 0x200);      // SizeOfRawData
    t.put32(0x148 + 20, 0x200);      // PointerToRawData
    t.put32(0x148 + 36, 0x60000020); // CODE|EXECUTE|READ
    return t;
}

std::uint32_t load32_at(const std::vector<std::uint8_t>& bytes, const std::size_t offset)
{
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);
}

TEST(LoaderParse, TinyPeLayoutAndTlsExtraction)
{
    auto tiny = make_tiny_pe();
    // section raw 0x200 maps image RVA 0x1000: the TLS directory sits at file
    // 0x200 with AddressOfCallBacks pointing at the array in file 0x300
    const std::uint64_t callbacks_va = tiny.image_base + 0x1100;
    tiny.put64(0x218, callbacks_va); // AddressOfCallBacks (dir + 0x18)
    const std::uint64_t cb[3] = {tiny.image_base + 0x1200, tiny.image_base + 0x1300, 0};
    std::memcpy(&tiny.bytes[0x300], cb, sizeof cb);

    const auto info = parse_pe(tiny.bytes);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->image_base, tiny.image_base);
    EXPECT_EQ(info->image_size, tiny.image_size);
    EXPECT_EQ(info->entry_rva, 0x1000U);
    EXPECT_EQ(info->sections.size(), 1U);

    auto image = build_image(tiny.bytes, *info);
    ASSERT_TRUE(image.has_value());
    EXPECT_EQ(image->size(), tiny.image_size);

    const auto callbacks = tls_callbacks(*image, *info);
    std::puts("tls-extracted");
    ASSERT_TRUE(callbacks.has_value());
    ASSERT_EQ(callbacks->size(), 2U);
    EXPECT_EQ((*callbacks)[0], tiny.image_base + 0x1200);
    EXPECT_EQ((*callbacks)[1], tiny.image_base + 0x1300);
}

TEST(LoaderReloc, DeltaZeroIsIdempotent)
{
    auto tiny = make_tiny_pe();
    const auto info = parse_pe(tiny.bytes);
    ASSERT_TRUE(info.has_value());
    auto image = build_image(tiny.bytes, *info);
    ASSERT_TRUE(image.has_value());
    // one HIGHLOW entry: image RVA 0x1010 (file 0x210), block size 12
    tiny.put32(0x300, 0x1000);
    tiny.put32(0x304, 0x0C);
    tiny.put16(0x308, 0xA010);
    tiny.put32(0x210, 0xDEADBEEF);
    const auto before = *image;
    ASSERT_TRUE(apply_relocations(*image, *info, 0).has_value());
    EXPECT_EQ(image, before); // delta zero: nothing changes
}

TEST(LoaderReloc, HighLowMovesWithDelta)
{
    auto tiny = make_tiny_pe();
    const auto info = parse_pe(tiny.bytes);
    ASSERT_TRUE(info.has_value());
    auto image = build_image(tiny.bytes, *info);
    ASSERT_TRUE(image.has_value());
    // the relocation block lives in the IMAGE (image rva 0x1100, target 0x1010)
    auto put32i = [&image](std::size_t offset, std::uint32_t value) {
        std::memcpy(&(*image)[offset], &value, sizeof value);
    };
    auto put16i = [&image](std::size_t offset, std::uint16_t value) {
        std::memcpy(&(*image)[offset], &value, sizeof value);
    };
    put32i(0x1100, 0x1000); // block: page rva
    put32i(0x1104, 0x0C);   // block size
    put16i(0x1108, 0xA010); // HIGHLOW, target image rva 0x1010
    put32i(0x1010, 0x00400000);
    const std::uint64_t delta = 0x10000;
    ASSERT_TRUE(apply_relocations(*image, *info, delta).has_value());
    EXPECT_EQ(load32_at(*image, 0x1010), 0x00400000U + static_cast<std::uint32_t>(delta));
}

TEST(LoaderParse, RejectsMismatchedMachineAndGarbage)
{
    auto tiny = make_tiny_pe();
    tiny.put16(0x44, 0x014C); // i386 machine with a PE32+ header: broken shape
    EXPECT_FALSE(parse_pe(tiny.bytes).has_value());

    const std::vector<std::uint8_t> junk(0x300, 0x41);
    EXPECT_FALSE(parse_pe(junk).has_value());

    tiny.put16(0x44, 0x01F0); // PPC: unsupported machine
    EXPECT_FALSE(parse_pe(tiny.bytes).has_value());
}

// Minimal x86 PE32 file: same shape as TinyPe but with the PE32 optional
// header (magic 0x10B, 4-byte ImageBase at optional+0x1C, directories at
// optional+0x60, SizeOfOptionalHeader 0xE0).
TinyPe make_tiny_pe32()
{
    TinyPe t;
    t.image_base = 0x400000ULL; // 32-bit images live under 4GB
    t.bytes.assign(0x400, 0);
    t.bytes[0] = 'M';
    t.bytes[1] = 'Z';
    t.put32(0x3C, 0x40);                                     // e_lfanew
    t.put32(0x40, 0x00004550);                               // PE signature
    t.put16(0x44, 0x014C);                                   // machine i386
    t.put16(0x46, 1);                                        // one section
    t.put16(0x54, 0xE0);                                     // SizeOfOptionalHeader (PE32)
    t.put16(0x56, 0x0102);                                   // characteristics
    t.put16(0x58, 0x010B);                                   // PE32
    t.bytes[0x5A] = 1;                                       // linker major
    t.put32(0x5C, 0x200);                                    // SizeOfCode
    t.put32(0x68, t.entry_rva);                              // AddressOfEntryPoint
    t.put32(0x6C, 0x1000);                                   // BaseOfCode
    t.put32(0x70, 0x2000);                                   // BaseOfData (PE32 only)
    t.put32(0x74, static_cast<std::uint32_t>(t.image_base)); // ImageBase (4 bytes)
    t.put32(0x78, 0x1000);                                   // SectionAlignment
    t.put32(0x7C, 0x200);                                    // FileAlignment
    t.put32(0x90, static_cast<std::uint32_t>(t.image_size));
    t.put32(0x94, 0x200); // SizeOfHeaders
    // data directories at optional(0x58)+0x60 = 0xB8: [5] relocation, [9] TLS
    t.put32(0xB8 + 5 * 8, t.reloc_dir_rva);
    t.put32(0xB8 + 5 * 8 + 4, 0x10);
    t.put32(0xB8 + 9 * 8, t.tls_dir_rva);
    t.put32(0xB8 + 9 * 8 + 4, 0x40);
    // section header at opt(0x58) + 0xE0 = 0x138: ".text"
    std::memcpy(&t.bytes[0x138], ".text", 5);
    t.put32(0x138 + 8, 0x200);       // VirtualSize
    t.put32(0x138 + 12, 0x1000);     // VirtualAddress
    t.put32(0x138 + 16, 0x200);      // SizeOfRawData
    t.put32(0x138 + 20, 0x200);      // PointerToRawData
    t.put32(0x138 + 36, 0x60000020); // CODE|EXECUTE|READ
    return t;
}

TEST(LoaderParse32, LayoutBitnessAndTlsExtraction)
{
    auto tiny = make_tiny_pe32();
    // TLS directory at image RVA 0x1000 (file 0x200): PE32 AddressOfCallBacks
    // is the 4-byte field at +0x0C, entries are 4-byte VAs
    const std::uint32_t callbacks_va = static_cast<std::uint32_t>(tiny.image_base) + 0x1100;
    tiny.put32(0x20C, callbacks_va);
    const std::uint32_t cb[3] = {static_cast<std::uint32_t>(tiny.image_base) + 0x1200,
                                 static_cast<std::uint32_t>(tiny.image_base) + 0x1300, 0};
    std::memcpy(&tiny.bytes[0x300], cb, sizeof cb);

    const auto info = parse_pe(tiny.bytes);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->bitness, kBitness32);
    EXPECT_EQ(info->image_base, tiny.image_base);
    EXPECT_EQ(info->image_size, tiny.image_size);
    EXPECT_EQ(info->entry_rva, 0x1000U);
    EXPECT_EQ(info->sections.size(), 1U);
    EXPECT_EQ(info->sections[0].virtual_address, 0x1000U);

    auto image = build_image(tiny.bytes, *info);
    ASSERT_TRUE(image.has_value());
    EXPECT_EQ(image->size(), tiny.image_size);

    const auto callbacks = tls_callbacks(*image, *info);
    ASSERT_TRUE(callbacks.has_value());
    ASSERT_EQ(callbacks->size(), 2U);
    EXPECT_EQ((*callbacks)[0], tiny.image_base + 0x1200);
    EXPECT_EQ((*callbacks)[1], tiny.image_base + 0x1300);
}

TEST(LoaderParse64, ReportsBitness)
{
    const auto info = parse_pe(make_tiny_pe().bytes);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->bitness, kBitness64);
}

TEST(LoaderReloc32, HighLowMovesWithSmallDelta)
{
    auto tiny = make_tiny_pe32();
    const auto info = parse_pe(tiny.bytes);
    ASSERT_TRUE(info.has_value());
    auto image = build_image(tiny.bytes, *info);
    ASSERT_TRUE(image.has_value());
    auto put32i = [&image](std::size_t offset, std::uint32_t value) {
        std::memcpy(&(*image)[offset], &value, sizeof value);
    };
    auto put16i = [&image](std::size_t offset, std::uint16_t value) {
        std::memcpy(&(*image)[offset], &value, sizeof value);
    };
    // one HIGHLOW entry in the image: block at RVA 0x1100, target 0x1010
    put32i(0x1100, 0x1000);
    put32i(0x1104, 0x0C);
    put16i(0x1108, 0xA010);
    put32i(0x1010, 0x00400000);
    const std::uint64_t delta = 0x10000;
    ASSERT_TRUE(apply_relocations(*image, *info, delta).has_value());
    EXPECT_EQ(load32_at(*image, 0x1010), 0x00400000U + static_cast<std::uint32_t>(delta));
}

TEST(LoaderEnv, HeaderSpanDeclarationsLeavingTheImageAreNamedRejections)
{
    // the section table (and SizeOfHeaders) must stay inside BOTH the source
    // file and the destination image: a header span that leaves either is
    // the named rejection, never a truncated copy or an out-of-range write
    // (96 sections at TinyPe's layout put the table end at 0x1048 - an image
    // that ends at 0x1000 cannot hold it, and build_image refuses by name)
    TinyPe t = make_tiny_pe();
    t.put16(0x46, 96);
    t.image_size = 0x1000;
    t.put32(0x90, static_cast<std::uint32_t>(t.image_size));
    const std::size_t table_end = 0x148 + 96 * 40; // 0x1048
    t.bytes.resize(table_end + 0x40, 0);           // the file itself carries the table
    auto info = parse_pe(t.bytes);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->sections.size(), 96u);
    EXPECT_GT(info->table_end_rva, t.image_size);
    const auto built = build_image(t.bytes, *info);
    ASSERT_FALSE(built.has_value());
    EXPECT_EQ(built.error(), LoadError::kBadHeaders);
}

TEST(LoaderEnv, DeclaredSizeOfHeadersLeavingTheImageIsNamedRejection)
{
    // SizeOfHeaders past the image (or past the file) is the same rejection
    TinyPe t = make_tiny_pe();
    t.put32(0x94, 0x8000); // SizeOfHeaders > SizeOfImage 0x2000
    auto info = parse_pe(t.bytes);
    ASSERT_TRUE(info.has_value());
    const auto built = build_image(t.bytes, *info);
    ASSERT_FALSE(built.has_value());
    EXPECT_EQ(built.error(), LoadError::kBadHeaders);
}

} // namespace
