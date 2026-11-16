// A synthetic ntdll built in guest memory: minimal PE32+ header plus an export
// directory naming three functions (two Nt* stubs the number decoder resolves
// and one non-Nt export it must skip). Shared by the syscall-number walk test
// and the run-facts inverse-map test so both drive the same image instead of a
// second approximation of it.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace sheller_test {

inline constexpr std::uint64_t kNtdllBase = 0x7FF800000000;
inline constexpr std::uint32_t kExportDirRva = 0x2000;
inline constexpr std::uint32_t kStubRva = 0x3000;
inline constexpr std::size_t kNtdllImageSize = 0x4000;

inline void put_u32(std::vector<std::uint8_t>& image, const std::uint64_t offset,
                    const std::uint32_t value)
{
    image[offset] = static_cast<std::uint8_t>(value);
    image[offset + 1] = static_cast<std::uint8_t>(value >> 8);
    image[offset + 2] = static_cast<std::uint8_t>(value >> 16);
    image[offset + 3] = static_cast<std::uint8_t>(value >> 24);
}

inline void put_u16(std::vector<std::uint8_t>& image, const std::uint64_t offset,
                    const std::uint16_t value)
{
    image[offset] = static_cast<std::uint8_t>(value);
    image[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

inline void put_u64(std::vector<std::uint8_t>& image, const std::uint64_t offset,
                    const std::uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) {
        image[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
}

// Builds a minimal PE32+ image with an export directory naming three
// functions: two Nt* stubs and one non-Nt export the number filter skips.
// The export-directory arrays sit at 0x150+, clear of the optional header
// (0x58..0x148) so nothing clobbers anything.
inline std::vector<std::uint8_t> build_fake_ntdll()
{
    std::vector<std::uint8_t> image(kNtdllImageSize, 0);
    image[0] = 'M';
    image[1] = 'Z';
    put_u32(image, 0x3C, 0x40); // e_lfanew
    const std::uint32_t pe_signature = 0x00004550;
    put_u32(image, 0x40, pe_signature);
    put_u16(image, 0x46, 1);   // one section (table content unused here)
    put_u16(image, 0x54, 240); // size of optional header
    const auto optional = static_cast<std::uint64_t>(0x58);
    put_u16(image, optional, 0x20B); // PE32+
    put_u32(image, optional + 0x70, kExportDirRva);
    put_u32(image, optional + 0x74, 0x100);

    const auto dir = static_cast<std::uint64_t>(kExportDirRva);
    put_u32(image, dir + 0x14, 3);     // number of functions
    put_u32(image, dir + 0x18, 3);     // number of names
    put_u32(image, dir + 0x1C, 0x150); // functions RVA
    put_u32(image, dir + 0x20, 0x160); // names RVA
    put_u32(image, dir + 0x24, 0x170); // ordinals RVA

    put_u32(image, 0x150, kStubRva);
    put_u32(image, 0x154, kStubRva + 0x20);
    put_u32(image, 0x158, 0x3900);
    put_u32(image, 0x160, 0x180);
    put_u32(image, 0x164, 0x1A0);
    put_u32(image, 0x168, 0x1C0);
    put_u16(image, 0x170, 0);
    put_u16(image, 0x172, 1);
    put_u16(image, 0x174, 2);

    const char name1[] = "NtTerminateProcess";
    const char name2[] = "NtProtectVirtualMemory";
    const char name3[] = "RtlIdle";
    std::memcpy(image.data() + 0x180, name1, sizeof name1);
    std::memcpy(image.data() + 0x1A0, name2, sizeof name2);
    std::memcpy(image.data() + 0x1C0, name3, sizeof name3);

    const std::uint8_t stub1[8] = {0x4C, 0x8B, 0xD1, 0xB8, 0x34, 0x12, 0x00, 0x00};
    std::memcpy(image.data() + kStubRva, stub1, sizeof stub1);
    const std::uint8_t stub2[8] = {0x4C, 0x8B, 0xD1, 0xB8, 0x78, 0x56, 0x00, 0x00};
    std::memcpy(image.data() + kStubRva + 0x20, stub2, sizeof stub2);
    return image;
}

// The KnownDLL view fixture: a full image (PE32+ default, PE32 when asked)
// whose whole transform surface is observable. Absolute slots carry
// base + rva the way a resident image holds them, so the view expectation
// is a pure function of the fixture and the two bases. The file and image
// layouts coincide (section content sits at its RVA), so the same bytes
// work as a placed resident module and as a file-backed section's bound
// file. Observed surface:
// - CheckSum (optional+0x40) and the Security data-directory entry are
//   non-zero and must arrive zeroed in the view;
// - the adjacent optional-header words the old wrong-offset hygiene
//   zeroed (optional+0x28, e_lfanew+0x40) and SizeOfInitializedData must
//   survive;
// - the relocation table names one self-pointer (RVA 0x3010): the delta
//   readout;
// - two named exports: an unbound rip-relative thunk (FF 25 -> slot at
//   RVA 0x2830, placeholder target) the compat patch must repoint, and a
//   bound-shape export (loader-rewritten E9 jmp) it must leave alone;
// - non-zero tail-page marker bytes at RVA 0x3FC0 that must ride into the
//   view (a zero-filled view fails every assertion above).
inline constexpr std::uint64_t kFixtureDllBase = 0x7FF700000000;
inline constexpr std::size_t kFixtureDllImageSize = 0x4000;
inline constexpr std::uint32_t kFixtureRelocRva = 0x1000;
inline constexpr std::uint32_t kFixtureRelocPointerRva = 0x3010;
inline constexpr std::uint32_t kFixtureExportRva = 0x2000;
inline constexpr std::uint32_t kFixtureThunkRva = 0x2800;
inline constexpr std::uint32_t kFixtureThunkSlotRva = 0x2830;
inline constexpr std::uint32_t kFixtureBoundRva = 0x2820;
inline constexpr std::uint32_t kFixtureTailRva = 0x3FC0;
inline constexpr std::uint32_t kFixtureSecurityVa = 0x9DEB0000;
inline constexpr std::uint32_t kFixtureSecuritySize = 0x2000;
inline constexpr std::uint32_t kFixtureChecksum = 0xCAFEF00D;
inline constexpr std::uint32_t kFixtureAdjacentWords = 0x00010006; // OS version 6.1
inline constexpr std::uint32_t kFixtureSizeOfInitializedData = 0x5A5A5A5A;

inline std::vector<std::uint8_t> build_fake_known_dll(const std::uint64_t base,
                                                      const bool pe32plus = true)
{
    const std::size_t optional_size = pe32plus ? 0xF0 : 0xE0;
    const std::size_t directory_base = pe32plus ? 0x70 : 0x60;
    std::vector<std::uint8_t> image(kFixtureDllImageSize, 0);
    image[0] = 'M';
    image[1] = 'Z';
    put_u32(image, 0x3C, 0x40); // e_lfanew
    put_u32(image, 0x40, 0x00004550);
    put_u16(image, 0x44, pe32plus ? 0x8664 : 0x014C); // machine
    put_u16(image, 0x46, 1);                          // one section
    put_u16(image, 0x54, static_cast<std::uint16_t>(optional_size));
    put_u16(image, 0x56, 0x2022); // characteristics
    const std::size_t optional = 0x58;
    put_u16(image, optional, pe32plus ? 0x20B : 0x10B);
    put_u32(image, optional + 0x08, kFixtureSizeOfInitializedData);
    if (pe32plus) {
        put_u64(image, optional + 0x18, base); // ImageBase
    } else {
        put_u32(image, optional + 0x1C, static_cast<std::uint32_t>(base));
    }
    put_u32(image, optional + 0x20, 0x1000);                // SectionAlignment
    put_u32(image, optional + 0x24, 0x1000);                // FileAlignment
    put_u32(image, optional + 0x28, kFixtureAdjacentWords); // OS version pair
    put_u32(image, optional + 0x38, static_cast<std::uint32_t>(kFixtureDllImageSize));
    put_u32(image, optional + 0x3C, 0x400); // SizeOfHeaders
    put_u32(image, optional + 0x40, kFixtureChecksum);
    const std::size_t directory = optional + directory_base;
    put_u32(image, directory + 0 * 8, kFixtureExportRva); // DataDirectory[0] export
    put_u32(image, directory + 0 * 8 + 4, 0x100);
    put_u32(image, directory + 4 * 8, kFixtureSecurityVa); // DataDirectory[4] Security
    put_u32(image, directory + 4 * 8 + 4, kFixtureSecuritySize);
    put_u32(image, directory + 5 * 8, kFixtureRelocRva); // DataDirectory[5] reloc
    put_u32(image, directory + 5 * 8 + 4, 12);

    const std::size_t section_table = optional + optional_size;
    const char section_name[] = ".text";
    std::memcpy(image.data() + section_table, section_name, sizeof section_name);
    put_u32(image, section_table + 8, 0x3000);  // VirtualSize
    put_u32(image, section_table + 12, 0x1000); // VirtualAddress
    put_u32(image, section_table + 16, 0x3000); // SizeOfRawData
    put_u32(image, section_table + 20, 0x1000); // PointerToRawData
    put_u32(image, section_table + 36, 0x60000020);

    // relocation table: one DIR64 (PE32+) / HIGHLOW (PE32) fixup on the
    // self-pointer slot at RVA 0x3010 - the delta readout
    put_u32(image, kFixtureRelocRva, 0x3000); // page RVA
    put_u32(image, kFixtureRelocRva + 4, 12); // block size
    const auto fixup = static_cast<std::uint16_t>((pe32plus ? 0xA000 : 0x3000) |
                                                  (kFixtureRelocPointerRva & 0xFFF));
    put_u16(image, kFixtureRelocRva + 8, fixup);
    if (pe32plus) {
        put_u64(image, kFixtureRelocPointerRva, base + kFixtureRelocPointerRva);
    } else {
        put_u32(image, kFixtureRelocPointerRva,
                static_cast<std::uint32_t>(base + kFixtureRelocPointerRva));
    }

    // export directory naming the two thunk shapes
    const auto dir = static_cast<std::uint64_t>(kFixtureExportRva);
    put_u32(image, dir + 0x0C, 0x2060); // Name RVA
    put_u32(image, dir + 0x10, 1);      // OrdinalBase
    put_u32(image, dir + 0x14, 2);      // NumberOfFunctions
    put_u32(image, dir + 0x18, 2);      // NumberOfNames
    put_u32(image, dir + 0x1C, 0x2100); // AddressOfFunctions
    put_u32(image, dir + 0x20, 0x2110); // AddressOfNames
    put_u32(image, dir + 0x24, 0x2120); // AddressOfNameOrdinals
    put_u32(image, 0x2100, kFixtureThunkRva);
    put_u32(image, 0x2104, kFixtureBoundRva);
    put_u32(image, 0x2110, 0x2130); // "ThunkOut"
    put_u32(image, 0x2114, 0x2140); // "BoundIn"
    put_u16(image, 0x2120, 0);
    put_u16(image, 0x2122, 1);
    const char dll_name[] = "fixdll.dll";
    std::memcpy(image.data() + 0x2060, dll_name, sizeof dll_name);
    const char name1[] = "ThunkOut";
    std::memcpy(image.data() + 0x2130, name1, sizeof name1);
    const char name2[] = "BoundIn";
    std::memcpy(image.data() + 0x2140, name2, sizeof name2);

    // the unbound rip-relative thunk and its placeholder slot
    put_u16(image, kFixtureThunkRva, 0x25FF);
    put_u32(image, kFixtureThunkRva + 2, kFixtureThunkSlotRva - (kFixtureThunkRva + 6));
    if (pe32plus) {
        put_u64(image, kFixtureThunkSlotRva, base + kFixtureThunkSlotRva);
    } else {
        put_u32(image, kFixtureThunkSlotRva,
                static_cast<std::uint32_t>(base + kFixtureThunkSlotRva));
    }
    // the bound shape: the loader rewrote the entry into a direct jmp
    image[kFixtureBoundRva] = 0xE9;
    put_u32(image, kFixtureBoundRva + 1, 0x2840 - (kFixtureBoundRva + 5));
    image[0x2840] = 0xC3;

    // the tail-page marker the view must carry
    for (std::size_t i = 0; i < 16; ++i) {
        image[kFixtureTailRva + i] = 0x77;
    }
    return image;
}

} // namespace sheller_test
