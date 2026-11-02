// PE loader core: pure byte-level
// construction of a loader-ready image from a PE file - parse, layout and
// relocations, no unicorn. The engine maps the produced image bytes and
// schedules the extracted TLS callbacks; keeping this module unicorn-free
// makes the whole construction unit-testable and host-portable.

#ifndef SHELLER_LOADER_LOADER_H
#define SHELLER_LOADER_LOADER_H

#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <vector>

namespace sheller::loader {

enum class LoadError {
    kNone = 0,
    kTooSmall,             // less than a DOS header
    kBadDos,               // missing MZ or e_lfanew out of range
    kBadPe,                // missing PE signature
    kUnsupportedMachine,   // machine is neither AMD64 nor i386
    kUnsupportedOptHeader, // optional header is neither PE32+ nor PE32
    kBadImageSize,         // SizeOfImage missing or beyond the cap
    kBadReloc,             // relocation block out of range
};

std::string_view load_error_message(LoadError error);

// Cap: loader-route images stay within a sane span (The
// guest is untrusted input).
inline constexpr std::uint64_t kMaxImageSize = 64ULL * 1024 * 1024;

inline constexpr std::uint32_t kBitness32 = 32;
inline constexpr std::uint32_t kBitness64 = 64;

struct SectionInfo {
    std::uint32_t virtual_address{};
    std::uint32_t virtual_size{};
    std::uint32_t raw_size{};
    std::uint32_t raw_pointer{};
    std::uint32_t characteristics{};
};

struct ImageInfo {
    std::uint32_t bitness{}; // kBitness32 (PE32/i386) or kBitness64 (PE32+/AMD64)
    std::uint64_t image_base{};
    std::uint64_t image_size{};
    std::uint64_t entry_rva{};
    std::uint32_t tls_directory_rva{};
    std::uint32_t tls_directory_size{};
    std::uint32_t reloc_directory_rva{};
    std::uint32_t reloc_directory_size{};
    std::vector<SectionInfo> sections;
};

// Header walk over the raw file bytes. Accepts AMD64/PE32+ and i386/PE32;
// the returned layout (including the bitness tag) drives build_image and
// every width-dependent consumer.
std::expected<ImageInfo, LoadError> parse_pe(std::span<const std::uint8_t> file);

// Assembles the SizeOfImage-sized image: headers block + sections copied
// from their raw file offsets. Zero-fills everything else.
std::expected<std::vector<std::uint8_t>, LoadError> build_image(std::span<const std::uint8_t> file,
                                                                const ImageInfo& info);

// Applies base relocations in place: every HIGHLOW (32-bit) and DIR64
// (64-bit) entry gains the base delta; ABSOLUTE entries are padding;
// unknown types are skipped and counted. Idempotent at delta zero.
std::expected<void, LoadError> apply_relocations(std::span<std::uint8_t> image,
                                                 const ImageInfo& info, std::uint64_t base_delta);

// Verifies the relocation table is applicable: every HIGHLOW/DIR64 fixup
// target must land inside the image. The directory-mode load consults this
// before trusting a shifted image - a table that names out-of-range targets
// is the "needs relocation without effective info" shape, and the load is
// a named rejection instead of a half-fixed image.
std::expected<void, LoadError> validate_relocations(std::span<const std::uint8_t> image,
                                                    const ImageInfo& info);

// Reads the TLS callback VA array (DataDirectory[9] -> directory's
// AddressOfCallBacks, NUL-terminated array of absolute VAs). Bounded.
// base_delta is the relocation already applied to the image: a remapped
// sample's pointers ride image_base + base_delta, while info.image_base is
// the declared base.
std::expected<std::vector<std::uint64_t>, LoadError>
tls_callbacks(std::span<const std::uint8_t> image, const ImageInfo& info,
              std::uint64_t base_delta = 0);

} // namespace sheller::loader

#endif // SHELLER_LOADER_LOADER_H
