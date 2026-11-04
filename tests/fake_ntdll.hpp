// A synthetic ntdll built in guest memory: minimal PE32+ header plus an export
// directory naming three functions (two Nt* stubs the number decoder resolves
// and one non-Nt export it must skip). Shared by the syscall-number walk test
// and the run-facts inverse-map test so both drive the same image instead of a
// second approximation of it.
#pragma once

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

} // namespace sheller_test
