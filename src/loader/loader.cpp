#include "loader.h"

#include <algorithm>
#include <cstring>

namespace sheller::loader {
namespace {

// Offsets mirror winnt.h; the module keeps its own portable minimum.
constexpr std::uint32_t kELfanewOffset = 0x3C;
constexpr std::uint32_t kOptionalHeaderOffset = 24;
constexpr std::uint32_t kSizeOfImageOffset = 56;      // optional+0x38 (both magics)
constexpr std::uint32_t kSizeOfHeadersOffset = 60;    // optional+0x3C (both magics)
constexpr std::uint32_t kEntryOffset = 16;            // optional+0x10 (both magics)
constexpr std::uint32_t kImageBaseOffset64 = 24;      // PE32+ optional+0x18 (8 bytes)
constexpr std::uint32_t kImageBaseOffset32 = 28;      // PE32  optional+0x1C (4 bytes)
constexpr std::uint32_t kDataDirectoryOffset64 = 112; // PE32+ optional+0x70
constexpr std::uint32_t kDataDirectoryOffset32 = 96;  // PE32  optional+0x60
constexpr std::size_t kMaxSections = 96;
constexpr std::size_t kMaxTlsCallbacks = 64;
constexpr std::uint16_t kMachineAmd64 = 0x8664;
constexpr std::uint16_t kMachineI386 = 0x014C;
constexpr std::uint16_t kPe32PlusMagic = 0x20B;
constexpr std::uint16_t kPe32Magic = 0x10B;
constexpr std::uint16_t kRelocAbsolute = 0x00;   // padding entry: skipped
constexpr std::uint16_t kRelocHighLow = 0x03;    // IMAGE_REL_BASED_HIGHLOW: 32-bit += delta
constexpr std::uint16_t kRelocDir64Value = 0x0A; // IMAGE_REL_BASED_DIR64: 64-bit += delta

std::uint16_t read16(std::span<const std::uint8_t> bytes, const std::size_t offset)
{
    return static_cast<std::uint16_t>(bytes[offset] |
                                      (static_cast<std::uint16_t>(bytes[offset + 1]) << 8));
}

std::uint32_t read32(std::span<const std::uint8_t> bytes, const std::size_t offset)
{
    std::uint32_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof value);
    return value;
}

std::uint64_t read64(std::span<const std::uint8_t> bytes, const std::size_t offset)
{
    std::uint64_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof value);
    return value;
}

void write32(std::span<std::uint8_t> bytes, const std::size_t offset, const std::uint32_t value)
{
    std::memcpy(bytes.data() + offset, &value, sizeof value);
}

void write64(std::span<std::uint8_t> bytes, const std::size_t offset, const std::uint64_t value)
{
    std::memcpy(bytes.data() + offset, &value, sizeof value);
}

} // namespace

std::string_view load_error_message(const LoadError error)
{
    switch (error) {
    case LoadError::kNone:
        return "ok";
    case LoadError::kTooSmall:
        return "PE file too small";
    case LoadError::kBadDos:
        return "broken PE file (e_lfanew out of range)";
    case LoadError::kBadPe:
        return "broken PE file (PE signature missing)";
    case LoadError::kUnsupportedMachine:
        return "loader route accepts AMD64/i386 images only";
    case LoadError::kUnsupportedOptHeader:
        return "loader route accepts PE32+/PE32 images only";
    case LoadError::kBadImageSize:
        return "SizeOfImage missing or beyond the loader cap";
    case LoadError::kBadReloc:
        return "relocation block out of range";
    }
    return "unknown loader error";
}

std::expected<ImageInfo, LoadError> parse_pe(std::span<const std::uint8_t> file)
{
    if (file.size() < 0x40 + 4 + 20) {
        return std::unexpected(LoadError::kTooSmall);
    }
    if (read16(file, 0) != 0x5A4D) {
        return std::unexpected(LoadError::kBadDos);
    }
    const auto pe = read32(file, kELfanewOffset);
    if (pe == 0 || static_cast<std::uint64_t>(pe) + 4 + 20 > file.size()) {
        return std::unexpected(LoadError::kBadDos);
    }
    if (read32(file, pe) != 0x00004550) {
        return std::unexpected(LoadError::kBadPe);
    }
    const auto coff = pe + 4;
    const auto machine = read16(file, coff);
    if (machine != kMachineAmd64 && machine != kMachineI386) {
        return std::unexpected(LoadError::kUnsupportedMachine);
    }
    const auto opt = coff + 20;
    const auto magic = read16(file, opt);
    const bool pe32plus = magic == kPe32PlusMagic;
    if (!pe32plus && magic != kPe32Magic) {
        return std::unexpected(LoadError::kUnsupportedOptHeader);
    }
    if (pe32plus != (machine == kMachineAmd64)) {
        // PE32+ headers come with AMD64, PE32 with i386; mixtures are broken
        // input, not a supported shape
        return std::unexpected(LoadError::kUnsupportedOptHeader);
    }

    ImageInfo info;
    info.bitness = pe32plus ? kBitness64 : kBitness32;
    info.image_base =
        pe32plus ? read64(file, opt + kImageBaseOffset64) : read32(file, opt + kImageBaseOffset32);
    info.entry_rva = read32(file, opt + kEntryOffset);
    info.image_size = read32(file, opt + kSizeOfImageOffset);
    if (info.image_size == 0 || info.image_size > kMaxImageSize) {
        return std::unexpected(LoadError::kBadImageSize);
    }

    const auto dir_base = opt + (pe32plus ? kDataDirectoryOffset64 : kDataDirectoryOffset32);
    info.reloc_directory_rva = read32(file, dir_base + 5 * 8);
    info.reloc_directory_size = read32(file, dir_base + 5 * 8 + 4);
    info.tls_directory_rva = read32(file, dir_base + 9 * 8);
    info.tls_directory_size = read32(file, dir_base + 9 * 8 + 4);

    const auto section_count = std::min<std::size_t>(read16(file, coff + 2), kMaxSections);
    // section table follows the optional header, whose full size (read from
    // the COFF header) already includes the data directory array for either
    // magic (PE32+ 0xF0, PE32 0xE0)
    const auto size_of_optional = read16(file, coff + 16);
    const auto first_section = opt + size_of_optional;
    for (std::size_t i = 0; i < section_count; ++i) {
        const auto base = first_section + i * 40;
        SectionInfo section;
        section.virtual_size = read32(file, base + 8);
        section.virtual_address = read32(file, base + 12);
        section.raw_size = read32(file, base + 16);
        section.raw_pointer = read32(file, base + 20);
        section.characteristics = read32(file, base + 36);
        info.sections.push_back(section);
    }
    return info;
}

std::expected<std::vector<std::uint8_t>, LoadError> build_image(std::span<const std::uint8_t> file,
                                                                const ImageInfo& info)
{
    if (info.image_size == 0 || info.image_size > kMaxImageSize) {
        return std::unexpected(LoadError::kBadImageSize);
    }
    std::vector<std::uint8_t> image(static_cast<std::size_t>(info.image_size), 0);
    const auto header_bytes = std::min<std::uint64_t>(0x400, file.size());
    std::memcpy(image.data(), file.data(), static_cast<std::size_t>(header_bytes));
    for (const auto& section : info.sections) {
        if (section.raw_size == 0 || section.raw_pointer >= file.size()) {
            continue;
        }
        const auto copy =
            std::min<std::uint64_t>(section.raw_size, file.size() - section.raw_pointer);
        const auto target = section.virtual_address;
        if (target >= image.size() || copy > image.size() - target) {
            continue; // out-of-bounds section: skipped, guest is untrusted input
        }
        std::memcpy(image.data() + target, file.data() + section.raw_pointer,
                    static_cast<std::size_t>(copy));
    }
    return image;
}

std::expected<void, LoadError> apply_relocations(std::span<std::uint8_t> image,
                                                 const ImageInfo& info,
                                                 const std::uint64_t base_delta)
{
    if (info.reloc_directory_size == 0 || info.reloc_directory_rva == 0 ||
        info.reloc_directory_rva >= image.size()) {
        return {}; // no relocation directory: nothing to rewrite
    }
    if (base_delta == 0) {
        return {}; // image sits at its declared base: values are already correct
    }
    auto offset = static_cast<std::size_t>(info.reloc_directory_rva);
    const auto end = static_cast<std::size_t>(info.reloc_directory_rva + info.reloc_directory_size);
    while (offset + 8 <= end && end <= image.size()) {
        const auto page_rva = read32(image, offset);
        const auto block_size = read32(image, offset + 4);
        if (block_size < 8 || block_size > end - offset) {
            break; // malformed block: stop deterministically
        }
        const auto entry_count = (block_size - 8) / 2;
        for (std::size_t i = 0; i < entry_count; ++i) {
            const auto entry = read16(image, offset + 8 + 2 * i);
            const auto type = entry >> 12;
            const auto target = static_cast<std::size_t>(page_rva + (entry & 0xFFF));
            if (type == kRelocHighLow) {
                if (target + 4 > image.size()) {
                    continue;
                }
                const auto value = read32(image, target);
                write32(image, target, static_cast<std::uint32_t>(value + base_delta));
            } else if (type == kRelocDir64Value) {
                if (target + 8 > image.size()) {
                    continue;
                }
                const auto value = read64(image, target);
                write64(image, target, value + base_delta);
            }
            // other types: padding or unsupported, skipped
        }
        offset += block_size;
    }
    return {};
}

std::expected<void, LoadError> validate_relocations(std::span<const std::uint8_t> image,
                                                    const ImageInfo& info)
{
    if (info.reloc_directory_size == 0 || info.reloc_directory_rva == 0 ||
        info.reloc_directory_rva >= image.size()) {
        return {}; // no relocation directory: nothing to validate
    }
    auto offset = static_cast<std::size_t>(info.reloc_directory_rva);
    const auto end = static_cast<std::size_t>(info.reloc_directory_rva + info.reloc_directory_size);
    if (end > image.size()) {
        return std::unexpected(LoadError::kBadReloc);
    }
    while (offset + 8 <= end) {
        const auto page_rva = read32(image, offset);
        const auto block_size = read32(image, offset + 4);
        if (block_size < 8 || block_size > end - offset) {
            return std::unexpected(LoadError::kBadReloc);
        }
        const auto entry_count = (block_size - 8) / 2;
        for (std::size_t i = 0; i < entry_count; ++i) {
            const auto entry = read16(image, offset + 8 + 2 * i);
            const auto type = entry >> 12;
            if (type != kRelocHighLow && type != kRelocDir64Value) {
                continue; // padding or an unknown type: not a fixup claim
            }
            const auto target = static_cast<std::size_t>(page_rva + (entry & 0xFFF));
            const auto width = type == kRelocHighLow ? 4 : 8;
            if (target + width > image.size()) {
                return std::unexpected(LoadError::kBadReloc);
            }
        }
        offset += block_size;
    }
    return {};
}

std::expected<std::vector<std::uint64_t>, LoadError>
tls_callbacks(std::span<const std::uint8_t> image, const ImageInfo& info,
              const std::uint64_t base_delta)
{
    std::vector<std::uint64_t> callbacks;
    if (info.tls_directory_rva == 0 || info.tls_directory_rva >= image.size() ||
        info.tls_directory_rva + 64 > image.size()) {
        return callbacks;
    }
    // AddressOfCallBacks slot position and entry width follow the TLS
    // directory variant: PE32+ has four 8-byte fields (callbacks at +0x18),
    // PE32 four 4-byte fields (callbacks at +0x0C)
    const bool pe32plus = info.bitness == kBitness64;
    const auto callbacks_field = info.tls_directory_rva + (pe32plus ? 0x18 : 0x0C);
    const auto array_va =
        pe32plus ? read64(image, callbacks_field) : read32(image, callbacks_field);
    const auto mapped_base = info.image_base + base_delta;
    if (array_va < mapped_base || array_va >= mapped_base + info.image_size) {
        return callbacks;
    }
    const auto entry_size = pe32plus ? 8 : 4;
    auto offset = static_cast<std::size_t>(array_va - mapped_base);
    while (offset + entry_size <= image.size() && callbacks.size() < kMaxTlsCallbacks) {
        const auto callback = pe32plus ? read64(image, offset) : read32(image, offset);
        if (callback == 0) {
            break;
        }
        callbacks.push_back(callback);
        offset += entry_size;
    }
    return callbacks;
}

} // namespace sheller::loader
