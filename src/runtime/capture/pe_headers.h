// Portable minimal PE header walk - just enough of the PE spec for the
// capture path (entry RVA, TLS data directory, preferred base). Linux ships
// no system PE header (only <elf.h>), so the few needed structures are
// mirrored here field-for-field from winnt.h and pinned with static_asserts;
// parsing casts the buffer onto them, the way winnt.h-based tools do.
// Full image parsing with peconv is not implemented here.

#ifndef SHELLER_CAPTURE_PE_HEADERS_H
#define SHELLER_CAPTURE_PE_HEADERS_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace sheller::capture {

inline constexpr std::uint16_t kMzSignature = 0x5A4D;     // "MZ"
inline constexpr std::uint32_t kPeSignature = 0x00004550; // "PE\0\0"
inline constexpr std::uint16_t kPe32PlusMagic = 0x20B;
inline constexpr std::uint16_t kPe32Magic = 0x10B;
inline constexpr std::uint16_t kMachineAmd64 = 0x8664;
inline constexpr std::uint16_t kMachineI386 = 0x14C;
inline constexpr std::size_t kTlsDirectoryIndex = 9;
inline constexpr std::size_t kDataDirectoryCount = 16;

// Mirror of IMAGE_DOS_HEADER.
struct DosHeader {
    std::uint16_t e_magic;
    std::array<std::uint16_t, 13> e_dos_body; // e_cblp..e_ovno, unused here
    std::array<std::uint16_t, 4> e_res;
    std::uint16_t e_oemid;
    std::uint16_t e_oeminfo;
    std::array<std::uint16_t, 10> e_res2;
    std::int32_t e_lfanew;
};
static_assert(sizeof(DosHeader) == 64);
static_assert(offsetof(DosHeader, e_lfanew) == 60);

struct DataDirectory {
    std::uint32_t virtual_address;
    std::uint32_t size;
};
static_assert(sizeof(DataDirectory) == 8);

// Mirror of IMAGE_FILE_HEADER.
struct FileHeader {
    std::uint16_t machine;
    std::uint16_t number_of_sections;
    std::uint32_t time_date_stamp;
    std::uint32_t pointer_to_symbol_table;
    std::uint32_t number_of_symbols;
    std::uint16_t size_of_optional_header;
    std::uint16_t characteristics;
};
static_assert(sizeof(FileHeader) == 20);

// Mirror of IMAGE_OPTIONAL_HEADER64.
struct OptionalHeader64 {
    std::uint16_t magic;
    std::uint8_t major_linker_version;
    std::uint8_t minor_linker_version;
    std::uint32_t size_of_code;
    std::uint32_t size_of_initialized_data;
    std::uint32_t size_of_uninitialized_data;
    std::uint32_t address_of_entry_point;
    std::uint32_t base_of_code;
    std::uint64_t image_base;
    std::uint32_t section_alignment;
    std::uint32_t file_alignment;
    std::uint16_t major_operating_system_version;
    std::uint16_t minor_operating_system_version;
    std::uint16_t major_image_version;
    std::uint16_t minor_image_version;
    std::uint16_t major_subsystem_version;
    std::uint16_t minor_subsystem_version;
    std::uint32_t win32_version_value;
    std::uint32_t size_of_image;
    std::uint32_t size_of_headers;
    std::uint32_t check_sum;
    std::uint16_t subsystem;
    std::uint16_t dll_characteristics;
    std::uint64_t size_of_stack_reserve;
    std::uint64_t size_of_stack_commit;
    std::uint64_t size_of_heap_reserve;
    std::uint64_t size_of_heap_commit;
    std::uint32_t loader_flags;
    std::uint32_t number_of_rva_and_sizes;
    std::array<DataDirectory, kDataDirectoryCount> data_directory;
};
static_assert(sizeof(OptionalHeader64) == 240);

// Mirror of IMAGE_NT_HEADERS64.
struct NtHeaders64 {
    std::uint32_t signature;
    FileHeader file_header;
    OptionalHeader64 optional_header;
};
static_assert(sizeof(NtHeaders64) == 264);

// Mirror of IMAGE_OPTIONAL_HEADER32 (magic 0x010B).
struct OptionalHeader32 {
    std::uint16_t magic;
    std::uint8_t major_linker_version;
    std::uint8_t minor_linker_version;
    std::uint32_t size_of_code;
    std::uint32_t size_of_initialized_data;
    std::uint32_t size_of_uninitialized_data;
    std::uint32_t address_of_entry_point;
    std::uint32_t base_of_code;
    std::uint32_t base_of_data;
    std::uint32_t image_base; // 4 bytes in PE32
    std::uint32_t section_alignment;
    std::uint32_t file_alignment;
    std::uint16_t major_os_version;
    std::uint16_t minor_os_version;
    std::uint16_t major_image_version;
    std::uint16_t minor_image_version;
    std::uint16_t major_subsystem_version;
    std::uint16_t minor_subsystem_version;
    std::uint32_t win32_version_value;
    std::uint32_t size_of_image;
    std::uint32_t size_of_headers;
    std::uint32_t check_sum;
    std::uint16_t subsystem;
    std::uint16_t dll_characteristics;
    std::uint32_t size_of_stack_reserve;
    std::uint32_t size_of_stack_commit;
    std::uint32_t size_of_heap_reserve;
    std::uint32_t size_of_heap_commit;
    std::uint32_t loader_flags;
    std::uint32_t number_of_rva_and_sizes;
    std::array<DataDirectory, kDataDirectoryCount> data_directory;
};
static_assert(sizeof(OptionalHeader32) == 224);

// Mirror of IMAGE_NT_HEADERS32.
struct NtHeaders32 {
    std::uint32_t signature;
    FileHeader file_header;
    OptionalHeader32 optional_header;
};
static_assert(sizeof(NtHeaders32) == 248);

// Mirror of IMAGE_TLS_DIRECTORY64 (read from process memory by the capture
// path; only address_of_callbacks matters here).
struct TlsDirectory64 {
    std::uint64_t start_address_of_raw_data;
    std::uint64_t end_address_of_raw_data;
    std::uint64_t address_of_index;
    std::uint64_t address_of_callbacks;
    std::uint32_t size_of_zero_fill;
    std::uint32_t characteristics;
};
static_assert(sizeof(TlsDirectory64) == 40);

enum class PeError {
    kNone = 0,
    kDosHeader,      // missing MZ signature or e_lfanew out of range
    kNtHeader,       // missing PE signature or headers truncated
    kOptionalHeader, // neither PE32+ x64 nor PE32 x86
    kBufferTooSmall, // less than a DOS header in the input
    kBadImports,     // import directory malformed or unmapped
};

struct PeImageInfo {
    std::uint16_t machine{};
    std::uint32_t bitness{}; // 32 (PE32) or 64 (PE32+)
    std::uint64_t preferred_base{};
    std::uint64_t entry_rva{};
    bool has_tls{};
    std::uint64_t tls_directory_rva{};
    bool is_dll{}; // IMAGE_FILE_DLL set
};

// Walks headers from the first bytes of a PE file (mapped view or plain
// buffer; the caller passes at least the first 4 KiB of the file). The TLS
// directory *contents* are read from process memory by the capture path.
PeError parse_pe_headers(const std::uint8_t* data, std::size_t size, PeImageInfo& info);

std::string_view pe_error_message(PeError error);

// One import thunk as written: either by name (the exact referenced symbol)
// or by ordinal. Module is the dependency DLL name from the descriptor.
struct PeImportThunk {
    std::string module;
    std::string name;        // non-empty for by-name imports
    std::uint16_t ordinal{}; // meaningful when name is empty
};

// Walks the import descriptor table from file bytes (bounded: 64 modules,
// 512 thunks each). Requires the section table to map RVAs to file
// offsets; a malformed or unmapped directory is kBadImports, not a crash.
PeError parse_imports(const std::uint8_t* data, std::size_t size, std::vector<PeImportThunk>& out);

} // namespace sheller::capture

#endif // SHELLER_CAPTURE_PE_HEADERS_H
