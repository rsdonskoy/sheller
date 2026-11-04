// PE header parser tests run on every platform: the parser is portable on
// purpose, fed with the same hand-crafted fixture bytes the Windows capture
// tests map from file.

#include "minimal_pe.h"
#include "pe_headers.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

namespace capture = sheller::capture;

TEST(PeHeaders, ParsesMinimalFixture)
{
    for (const bool with_tls : {false, true}) {
        const auto image = sheller_test::make_minimal_pe(with_tls);
        capture::PeImageInfo info;
        const auto error = capture::parse_pe_headers(image.data(), image.size(), info);
        ASSERT_EQ(error, capture::PeError::kNone) << capture::pe_error_message(error);
        EXPECT_EQ(info.machine, capture::kMachineAmd64);
        EXPECT_EQ(info.preferred_base, sheller_test::kImageBase);
        EXPECT_EQ(info.entry_rva, sheller_test::kEntryPointRva);
        EXPECT_EQ(info.has_tls, with_tls);
        if (with_tls) {
            EXPECT_EQ(info.tls_directory_rva, sheller_test::kTlsDirectoryRva);
        }
    }
}

TEST(PeHeaders, RejectsMissingDosHeader)
{
    const std::vector<std::uint8_t> tiny(16, std::uint8_t{0x4D});
    capture::PeImageInfo info;
    EXPECT_EQ(capture::parse_pe_headers(tiny.data(), tiny.size(), info),
              capture::PeError::kBufferTooSmall);
    EXPECT_EQ(capture::parse_pe_headers(tiny.data(), 0, info), capture::PeError::kBufferTooSmall);
}

TEST(PeHeaders, RejectsBrokenMzSignature)
{
    auto image = sheller_test::make_minimal_pe(false);
    image[0] = 'X';
    capture::PeImageInfo info;
    EXPECT_EQ(capture::parse_pe_headers(image.data(), image.size(), info),
              capture::PeError::kBufferTooSmall);
}

TEST(PeHeaders, RejectsOutOfRangeE_lfanew)
{
    auto image = sheller_test::make_minimal_pe(false);
    auto& dos = *reinterpret_cast<capture::DosHeader*>(image.data());
    dos.e_lfanew = -1;
    capture::PeImageInfo info;
    EXPECT_EQ(capture::parse_pe_headers(image.data(), image.size(), info),
              capture::PeError::kDosHeader);
}

TEST(PeHeaders, RejectsBrokenPeSignature)
{
    auto image = sheller_test::make_minimal_pe(false);
    auto& nt = *reinterpret_cast<capture::NtHeaders64*>(image.data() + 0x80);
    nt.signature = 0;
    capture::PeImageInfo info;
    EXPECT_EQ(capture::parse_pe_headers(image.data(), image.size(), info),
              capture::PeError::kNtHeader);
}

TEST(PeHeaders, I386MachineWithPe32PlusHeaderRejected)
{
    auto image = sheller_test::make_minimal_pe(false);
    auto& nt = *reinterpret_cast<capture::NtHeaders64*>(image.data() + 0x80);
    nt.file_header.machine = capture::kMachineI386; // i386 needs PE32 headers
    capture::PeImageInfo info;
    EXPECT_EQ(capture::parse_pe_headers(image.data(), image.size(), info),
              capture::PeError::kOptionalHeader);
}

TEST(PeHeaders, RejectsForeignMachine)
{
    auto image = sheller_test::make_minimal_pe(false);
    auto& nt = *reinterpret_cast<capture::NtHeaders64*>(image.data() + 0x80);
    nt.file_header.machine = 0xAA64; // ARM64
    capture::PeImageInfo info;
    EXPECT_EQ(capture::parse_pe_headers(image.data(), image.size(), info),
              capture::PeError::kOptionalHeader);
}

TEST(PeHeaders, RejectsPe32OptionalHeader)
{
    auto image = sheller_test::make_minimal_pe(false);
    auto& nt = *reinterpret_cast<capture::NtHeaders64*>(image.data() + 0x80);
    nt.optional_header.magic = 0x10B; // PE32
    capture::PeImageInfo info;
    EXPECT_EQ(capture::parse_pe_headers(image.data(), image.size(), info),
              capture::PeError::kOptionalHeader);
}

TEST(PeHeaders, SkipsTlsWhenDirectoryAbsent)
{
    auto image = sheller_test::make_minimal_pe(false);
    auto& nt = *reinterpret_cast<capture::NtHeaders64*>(image.data() + 0x80);
    nt.optional_header.number_of_rva_and_sizes = capture::kTlsDirectoryIndex;
    capture::PeImageInfo info;
    ASSERT_EQ(capture::parse_pe_headers(image.data(), image.size(), info), capture::PeError::kNone);
    EXPECT_FALSE(info.has_tls);
}

// A thunk table whose last slot runs past the host buffer must read as
// malformed imports, not as an out-of-bounds host read. The fixture maps a
// valid descriptor and module name, then truncates the file so the thunk RVA
// converts to an offset whose 8-byte slot crosses EOF.
TEST(PeHeaders, TruncatedThunkSlotReadsAsMalformedImports)
{
    std::vector<std::uint8_t> image(0x2000, std::uint8_t{0});
    const auto put16 = [&](const std::uint32_t offset, const std::uint16_t value) {
        image[offset] = static_cast<std::uint8_t>(value);
        image[offset + 1] = static_cast<std::uint8_t>(value >> 8);
    };
    const auto put32 = [&](const std::uint32_t offset, const std::uint32_t value) {
        for (unsigned i = 0; i < 4; ++i) {
            image[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
        }
    };
    const auto put_str = [&](const std::uint32_t offset, const std::string_view text) {
        std::memcpy(image.data() + offset, text.data(), text.size());
        image[offset + text.size()] = 0;
    };
    auto& dos = *reinterpret_cast<capture::DosHeader*>(image.data());
    dos.e_magic = capture::kMzSignature;
    dos.e_lfanew = 0x80;
    const std::uint32_t nt = 0x80;
    put32(nt, capture::kPeSignature);
    put16(nt + 4, capture::kMachineAmd64);
    put16(nt + 6, 1); // one section
    put16(nt + 20, sizeof(capture::OptionalHeader64));
    const std::uint32_t opt = nt + 24;
    put16(opt, capture::kPe32PlusMagic);
    put32(opt + 56, 0x4000); // SizeOfImage
    put32(opt + 60, 0x1000); // SizeOfHeaders
    put32(opt + 108, 16);    // NumberOfRvaAndSizes
    const std::uint32_t dirs = opt + 112;
    put32(dirs + 8, 0x1010); // DataDirectory[1]: import descriptors
    const std::uint32_t sect = opt + sizeof(capture::OptionalHeader64);
    put_str(sect, ".idata");
    put32(sect + 8, 0x1000);  // VirtualSize
    put32(sect + 12, 0x1000); // VirtualAddress
    put32(sect + 16, 0x1000); // SizeOfRawData
    put32(sect + 20, 0x1000); // PointerToRawData

    put32(0x1010, 0x1100); // OriginalFirstThunk (the near-EOF table)
    put32(0x101C, 0x1020); // Name RVA
    put_str(0x1020, "a.dll");
    // The thunk table slot at 0x1100 stays nonzero garbage: the file ends
    // four bytes into the 8-byte slot.
    put32(0x1100, 0xDEADBEEF);

    capture::PeImageInfo info;
    std::vector<capture::PeImportThunk> imports;
    EXPECT_EQ(capture::parse_imports(image.data(), 0x1104, imports), capture::PeError::kBadImports);
    // The full buffer parses past the slot (the garbage thunk's by-name RVA
    // is unmapped and rejected as malformed in its own right): the truncated
    // run's rejection is the EOF-crossing slot, not the shape.
    EXPECT_EQ(capture::parse_imports(image.data(), image.size(), imports),
              capture::PeError::kBadImports);
}

} // namespace
