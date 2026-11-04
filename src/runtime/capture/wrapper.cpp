#include "wrapper.h"

#include "module_name.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>

namespace sheller::capture {
namespace {

constexpr std::uint32_t kFileAlignment = 0x200;
constexpr std::uint32_t kSectionAlignment = 0x1000;
// Both layouts round the header block to one file-alignment unit, so the
// section raw data always starts here.
constexpr std::uint32_t kSectionHeaderOffsetX64 =
    0x148; // DOS40 + sig4 + COFF20 + opt240 (112 + 16*8 dirs)
constexpr std::uint32_t kSectionHeaderOffsetX86 =
    0x138; // DOS40 + sig4 + COFF20 + opt224 (96 + 16*8 dirs)
constexpr std::uint32_t kSizeOfHeaders = kFileAlignment;
constexpr std::uint32_t kSectionRva = kSectionAlignment;

constexpr std::uint16_t kMachineX64 = 0x8664;
constexpr std::uint16_t kMachineX86 = 0x014C;
constexpr std::uint16_t kOptionalHeaderMagicX64 = 0x020B;
constexpr std::uint16_t kOptionalHeaderMagicX86 = 0x010B;
constexpr std::uint32_t kSectionCharacteristics = 0x60000020; // CODE | EXECUTE | READ
constexpr std::uint16_t kImageCharacteristics = 0x0022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

std::uint32_t align_up(const std::uint32_t value, const std::uint32_t alignment)
{
    return (value + alignment - 1) / alignment * alignment;
}

void store16(std::vector<std::uint8_t>& out, const std::size_t offset, const std::uint16_t value)
{
    out[offset] = static_cast<std::uint8_t>(value & 0xFF);
    out[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

void store32(std::vector<std::uint8_t>& out, const std::size_t offset, const std::uint32_t value)
{
    out[offset] = static_cast<std::uint8_t>(value & 0xFF);
    out[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    out[offset + 2] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
    out[offset + 3] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
}

} // namespace

std::string_view wrap_error_message(const WrapError error)
{
    switch (error) {
    case WrapError::kNone:
        return "ok";
    case WrapError::kEmptyBlob:
        return "shellcode blob is empty";
    case WrapError::kTooLarge:
        return "shellcode blob exceeds the wrapper capacity";
    case WrapError::kTempDirUnavailable:
        return "cannot resolve the host temporary directory";
    }
    return "unknown wrap error";
}

Status wrap_status(const WrapError error)
{
    return error == WrapError::kTempDirUnavailable ? Status::kCaptureFailed : Status::kNotX64Pe;
}

bool looks_like_pe(const std::span<const std::uint8_t> bytes)
{
    return bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z';
}

std::expected<std::vector<std::uint8_t>, WrapError>
wrap_blob(const WrapArch arch, const std::span<const std::uint8_t> blob)
{
    if (blob.empty()) {
        return std::unexpected(WrapError::kEmptyBlob);
    }
    if (blob.size() > kMaxBlobBytes) {
        return std::unexpected(WrapError::kTooLarge);
    }

    const bool is_x64 = arch == WrapArch::kX64;
    const auto blob_size = static_cast<std::uint32_t>(blob.size());
    const auto raw_size = align_up(blob_size, kFileAlignment);
    const auto image_size =
        kSectionRva + std::max(align_up(blob_size, kSectionAlignment), kSectionAlignment);

    std::vector<std::uint8_t> out;
    out.assign(kSizeOfHeaders + raw_size, 0);

    // DOS header: the classic minimal stub, e_lfanew points at 0x40.
    out[0] = 'M';
    out[1] = 'Z';
    store16(out, 0x02, 0x0003); // bytes on last page
    store16(out, 0x04, 0x0001); // pages in file
    store16(out, 0x0C, 0x0001); // header size in paragraphs
    store16(out, 0x18, 0x0040); // minimum allocation
    store32(out, 0x3C, 0x40);   // e_lfanew

    // PE signature + COFF file header.
    store32(out, 0x40, 0x00004550); // "PE\0\0"
    const std::size_t coff = 0x44;
    store16(out, coff + 0x00, is_x64 ? kMachineX64 : kMachineX86);
    store16(out, coff + 0x02, 1);                    // one section
    store32(out, coff + 0x08, 0);                    // time stamp: determinism
    store16(out, coff + 0x10, is_x64 ? 0xF0 : 0xE0); // SizeOfOptionalHeader
    store16(out, coff + 0x12, kImageCharacteristics);

    const std::size_t opt = coff + 0x14;
    // Optional header (PE32+ 0x70 / PE32 0xE0). PE32 diverges only in the
    // BaseOfData field, the ImageBase width and the 4-byte stack/heap sizes.
    store16(out, opt + 0x00, is_x64 ? kOptionalHeaderMagicX64 : kOptionalHeaderMagicX86);
    out[opt + 0x02] = 1;                   // major linker version
    store32(out, opt + 0x04, raw_size);    // SizeOfCode
    store32(out, opt + 0x10, kSectionRva); // AddressOfEntryPoint = section head
    store32(out, opt + 0x14, kSectionRva); // BaseOfCode
    if (is_x64) {
        store32(out, opt + 0x18, 0x00400000); // ImageBase (classic low base)
    } else {
        store32(out, opt + 0x18, kSectionRva); // BaseOfData (PE32 only)
        store32(out, opt + 0x1C, 0x00400000);  // ImageBase
    }
    store32(out, opt + 0x20, kSectionAlignment);
    store32(out, opt + 0x24, kFileAlignment);
    store16(out, opt + 0x28, 6); // OS version 6.0
    store16(out, opt + 0x2C, 0); // image version 0.0
    store16(out, opt + 0x30, 6); // subsystem version 6.0
    store32(out, opt + 0x34, 0); // Win32 version value
    store32(out, opt + 0x38, image_size);
    store32(out, opt + 0x3C, kSizeOfHeaders);
    store32(out, opt + 0x40, 0); // checksum: not verified for EXE images
    store16(out, opt + 0x44, 3); // subsystem: console
    store16(out, opt + 0x46, 0); // dll characteristics: no ASLR, no relocs
    if (is_x64) {
        store32(out, opt + 0x48, 0x00100000);
        store32(out, opt + 0x4C, 0); // stack reserve
        store32(out, opt + 0x50, 0x00001000);
        store32(out, opt + 0x54, 0); // stack commit
        store32(out, opt + 0x58, 0x00100000);
        store32(out, opt + 0x5C, 0); // heap reserve
        store32(out, opt + 0x60, 0x00001000);
        store32(out, opt + 0x64, 0);  // heap commit
        store32(out, opt + 0x68, 0);  // loader flags
        store32(out, opt + 0x6C, 16); // NumberOfRvaAndSizes
    } else {
        store32(out, opt + 0x48, 0x00100000); // stack reserve
        store32(out, opt + 0x4C, 0x00001000); // stack commit
        store32(out, opt + 0x50, 0x00100000); // heap reserve
        store32(out, opt + 0x54, 0x00001000); // heap commit
        store32(out, opt + 0x58, 0);          // loader flags
        store32(out, opt + 0x5C, 16);         // NumberOfRvaAndSizes
    }
    // data directories: all zero (no imports, no relocs, no exceptions table)

    // Section header: ".text", the blob rides here and the entry is its head.
    const std::size_t sec = is_x64 ? kSectionHeaderOffsetX64 : kSectionHeaderOffsetX86;
    std::memcpy(out.data() + sec, ".text", 5);
    store32(out, sec + 0x08, blob_size);      // VirtualSize
    store32(out, sec + 0x0C, kSectionRva);    // VirtualAddress
    store32(out, sec + 0x10, raw_size);       // SizeOfRawData
    store32(out, sec + 0x14, kSizeOfHeaders); // PointerToRawData
    store32(out, sec + 0x24, kSectionCharacteristics);
    store32(out, opt + 0x10, kSectionRva); // AddressOfEntryPoint = section head

    // Blob bytes right after the header block, zero padding to raw size.
    std::memcpy(out.data() + kSizeOfHeaders, blob.data(), blob.size());
    return out;
}

namespace {

// The runner keeps the wrapper's single-section shape but the section is
// RWX (UPX1-style): the loader writes the IAT at init, so the pages that
// hold it must not rely on a read-only grant.
constexpr std::uint32_t kRunnerSectionCharacteristics = 0xE00000E0; // CODE | EXECUTE | READ | WRITE

// Fixed entry-stub byte shapes (x64 / x86). The RIP-relative displacements
// and the absolute x86 addresses are patched by the builder from the final
// section layout.
constexpr std::size_t kStubX64Size = 29;
// sub rsp,28h; lea rcx,[rip+disp32]; call [rip+disp32];
// mov ecx,imm32; call [rip+disp32]; int3
const std::uint8_t kStubX64[kStubX64Size] = {
    0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28        @0
    0x48, 0x8D, 0x0D, 0,    0,    0, 0, // lea rcx, [rip+path]  @4, disp @7
    0xFF, 0x15, 0,    0,    0,    0,    // call [rip+LoadLib]   @11, disp @13
    0xB9, 0x5A, 0x00, 0x00, 0x00,       // mov ecx, 0x5A        @17
    0xFF, 0x15, 0,    0,    0,    0,    // call [rip+Exit]      @22, disp @24
    0xCC,                               // int3                 @28
};
constexpr std::size_t kStubX86Size = 20;
// push imm32(path VA); call dword ptr [&IAT.LoadLibraryW];
// push 0x5A; call dword ptr [&IAT.ExitProcess]; int3
const std::uint8_t kStubX86[kStubX86Size] = {
    0x68, 0,    0, 0, 0,    // push path_va       @0, imm @1
    0xFF, 0x15, 0, 0, 0, 0, // call [&LoadLib]    @5, imm @7
    0x6A, 0x5A,             // push 0x5A           @11
    0xFF, 0x15, 0, 0, 0, 0, // call [&Exit]       @13, imm @15
    0xCC,                   // int3                @19
};
constexpr std::size_t kStubPathDispX64 = 7;   // lea disp position
constexpr std::size_t kStubCall1DispX64 = 13; // LoadLibraryW disp position
constexpr std::size_t kStubCall2DispX64 = 24; // ExitProcess disp position
constexpr std::size_t kStubPathImmX86 = 1;
constexpr std::size_t kStubCall1ImmX86 = 7;
constexpr std::size_t kStubCall2ImmX86 = 15;
constexpr std::uint32_t kRunnerImageBase = 0x00400000;
constexpr std::uint32_t kRunnerExitCode = 0x5A;

void store64(std::vector<std::uint8_t>& out, const std::size_t offset, const std::uint64_t value)
{
    for (std::size_t i = 0; i < 8; ++i) {
        out[offset + i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xFF);
    }
}

} // namespace

std::string_view runner_error_message(const RunnerError error)
{
    switch (error) {
    case RunnerError::kNone:
        return "ok";
    case RunnerError::kBadArrivalName:
        return "runner arrival name is empty or contains path separators";
    case RunnerError::kReservedArrival:
        return "arrival name collides with a planned system dependency name";
    case RunnerError::kNoImports:
        return "runner plan lacks the base LoadLibraryW/ExitProcess imports";
    case RunnerError::kTooManyImports:
        return "runner plan exceeds the bounded import capacity";
    case RunnerError::kBadSymbol:
        return "runner import has neither a name nor an ordinal";
    }
    return "unknown runner error";
}

std::expected<std::vector<std::uint8_t>, RunnerError> build_runner(const RunnerPlan& plan)
{
    if (plan.arrival_name.empty() || plan.arrival_name.find('\\') != std::string::npos ||
        plan.arrival_name.find('/') != std::string::npos ||
        plan.arrival_name.find(':') != std::string::npos) {
        return std::unexpected(RunnerError::kBadArrivalName);
    }
    if (plan.imports.size() < 2 || plan.imports.size() > kMaxRunnerImports) {
        return std::unexpected(plan.imports.size() < 2 ? RunnerError::kNoImports
                                                       : RunnerError::kTooManyImports);
    }
    bool has_load_library = false;
    bool has_exit = false;
    for (const auto& import : plan.imports) {
        if (import.symbol.empty() && import.ordinal == 0) {
            return std::unexpected(RunnerError::kBadSymbol);
        }
        if (import.symbol.size() > 128 || import.module.empty() || import.module.size() > 64) {
            return std::unexpected(RunnerError::kBadSymbol);
        }
        if (fold_module_name_equals(import.module, "kernel32.dll")) {
            has_load_library = has_load_library || import.symbol == "LoadLibraryW";
            has_exit = has_exit || import.symbol == "ExitProcess";
        }
        if (fold_module_name_equals(import.module, plan.arrival_name)) {
            return std::unexpected(RunnerError::kReservedArrival);
        }
    }
    if (!has_load_library || !has_exit) {
        return std::unexpected(RunnerError::kNoImports);
    }

    const bool is_x64 = plan.arch == WrapArch::kX64;
    const std::size_t stub_size = is_x64 ? kStubX64Size : kStubX86Size;

    // Section layout: entry stub, then the UTF-16 path string, then the
    // import data (hint/name entries, DLL names, descriptors, INT, IAT).
    std::string path_utf16;
    path_utf16.reserve(plan.arrival_name.size() * 2 + 2);
    for (const char c : plan.arrival_name) {
        path_utf16.push_back(c);
        path_utf16.push_back('\0');
    }
    path_utf16.push_back('\0');
    path_utf16.push_back('\0');

    // Group imports by module preserving first-seen order, then sort each
    // group's symbol slots by (ordinal, name) for determinism.
    std::vector<std::pair<std::string, std::vector<const RunnerImport*>>> groups;
    for (const auto& import : plan.imports) {
        bool found = false;
        for (auto& [module, slots] : groups) {
            if (fold_module_name_equals(module, import.module)) {
                slots.push_back(&import);
                found = true;
                break;
            }
        }
        if (!found) {
            groups.emplace_back(import.module, std::vector<const RunnerImport*>{&import});
        }
    }
    for (auto& [module, slots] : groups) {
        (void)module;
        std::sort(slots.begin(), slots.end(), [](const RunnerImport* a, const RunnerImport* b) {
            if ((a->symbol.empty()) != (b->symbol.empty())) {
                return b->symbol.empty(); // by-name first
            }
            if (a->symbol.empty()) {
                return a->ordinal < b->ordinal;
            }
            return a->symbol < b->symbol;
        });
    }

    // Build the section payload into a scratch buffer, then splice it into
    // the PE image.
    std::vector<std::uint8_t> section;
    section.insert(section.end(), is_x64 ? kStubX64 : kStubX86,
                   (is_x64 ? kStubX64 : kStubX86) + stub_size);
    while (section.size() % 2 != 0) {
        section.push_back(0);
    }
    const std::uint32_t path_rva_off = static_cast<std::uint32_t>(section.size());
    section.insert(section.end(), path_utf16.begin(), path_utf16.end());
    while (section.size() % 2 != 0) {
        section.push_back(0);
    }

    // hint/name entries (2-byte hint + name + NUL, padded even)
    std::vector<std::uint32_t> hint_rvas(plan.imports.size(), 0);
    for (std::size_t g = 0, i = 0; g < groups.size(); ++g) {
        for (const RunnerImport* import : groups[g].second) {
            hint_rvas[i++] = static_cast<std::uint32_t>(section.size());
            section.push_back(0);
            section.push_back(0); // hint = 0
            for (const char c : import->symbol) {
                section.push_back(static_cast<std::uint8_t>(c));
            }
            section.push_back('\0');
            if (!import->symbol.empty() && section.size() % 2 != 0) {
                section.push_back('\0');
            }
        }
    }
    // DLL name strings
    std::vector<std::uint32_t> name_rvas(groups.size(), 0);
    for (std::size_t g = 0; g < groups.size(); ++g) {
        name_rvas[g] = static_cast<std::uint32_t>(section.size());
        for (const char c : groups[g].first) {
            section.push_back(static_cast<std::uint8_t>(c));
        }
        section.push_back('\0');
        if (section.size() % 2 != 0) {
            section.push_back('\0');
        }
    }
    // Import descriptors (one per module + the null terminator)
    const std::uint32_t descriptor_off = static_cast<std::uint32_t>(section.size());
    const std::size_t descriptor_bytes = (groups.size() + 1) * 20;
    section.insert(section.end(), descriptor_bytes, 0);
    // INT and IAT arrays (identical content: RVA thunks, ordinal-flagged
    // for by-ordinal imports)
    const std::uint32_t int_off = static_cast<std::uint32_t>(section.size());
    const std::size_t thunk_width = is_x64 ? 8 : 4;
    const std::size_t int_bytes = (plan.imports.size() + groups.size()) * thunk_width;
    section.insert(section.end(), int_bytes, 0);
    const std::uint32_t iat_off = static_cast<std::uint32_t>(section.size());
    section.insert(section.end(), int_bytes, 0);

    // Fill descriptors and thunks. Each module's arrays occupy its slots
    // plus one terminating zero slot - advance past the terminator before
    // the next module's base.
    const auto ordinal_flag = is_x64 ? 0x8000000000000000ull : 0x80000000ull;
    for (std::size_t g = 0, i = 0, slot = 0; g < groups.size(); ++g) {
        const std::size_t desc = descriptor_off + g * 20;
        store32(section, desc + 0,
                kSectionRva + int_off + static_cast<std::uint32_t>(slot * thunk_width));
        store32(section, desc + 4, 0); // timestamp
        store32(section, desc + 8, 0); // forwarder chain
        store32(section, desc + 12, kSectionRva + name_rvas[g]);
        store32(section, desc + 16,
                kSectionRva + iat_off + static_cast<std::uint32_t>(slot * thunk_width));
        for (std::size_t k = 0; k < groups[g].second.size(); ++k, ++i, ++slot) {
            const RunnerImport* import = groups[g].second[k];
            const std::uint64_t thunk = import->symbol.empty() ? (ordinal_flag | import->ordinal)
                                                               : (kSectionRva + hint_rvas[i]);
            const std::size_t int_pos = int_off + slot * thunk_width;
            const std::size_t iat_pos = iat_off + slot * thunk_width;
            if (is_x64) {
                store64(section, int_pos, thunk);
                store64(section, iat_pos, thunk);
            } else {
                store32(section, int_pos, static_cast<std::uint32_t>(thunk));
                store32(section, iat_pos, static_cast<std::uint32_t>(thunk));
            }
        }
        ++slot; // the terminating zero slot of this module's arrays
    }

    // Patch the stub's references now that the layout is final. The two
    // base slots are located by symbol name - group sorting may reorder
    // them (ExitProcess sorts before LoadLibraryW).
    const auto slot_of = [&](const std::string_view module,
                             const std::string_view symbol) -> std::size_t {
        std::size_t slot = 0;
        for (const auto& [group_module, slots] : groups) {
            if (!fold_module_name_equals(group_module, module)) {
                slot += slots.size() + 1; // past this module's terminator
                continue;
            }
            for (std::size_t k = 0; k < slots.size(); ++k, ++slot) {
                if (slots[k]->symbol == symbol) {
                    return slot;
                }
            }
            break;
        }
        return SIZE_MAX;
    };
    const std::size_t load_slot = slot_of("kernel32.dll", "LoadLibraryW");
    const std::size_t exit_slot = slot_of("kernel32.dll", "ExitProcess");
    // Validated above: both base entries exist, so both slots resolve.
    if (load_slot == SIZE_MAX || exit_slot == SIZE_MAX) {
        return std::unexpected(RunnerError::kNoImports);
    }
    const auto image_va = [&](const std::uint32_t section_offset) {
        return kRunnerImageBase + kSectionRva + section_offset;
    };
    if (is_x64) {
        const auto rip_disp = [&](const std::size_t stub_pos, const std::uint32_t target_off) {
            return static_cast<std::int32_t>(static_cast<std::int64_t>(target_off) -
                                             static_cast<std::int64_t>(stub_pos + 4));
        };
        const auto disp_path = rip_disp(kStubPathDispX64, path_rva_off);
        const auto disp_load = rip_disp(
            kStubCall1DispX64, iat_off + static_cast<std::uint32_t>(load_slot * thunk_width));
        const auto disp_exit = rip_disp(
            kStubCall2DispX64, iat_off + static_cast<std::uint32_t>(exit_slot * thunk_width));
        for (int b = 0; b < 4; ++b) {
            section[kStubPathDispX64 + b] = static_cast<std::uint8_t>(disp_path >> (8 * b));
            section[kStubCall1DispX64 + b] = static_cast<std::uint8_t>(disp_load >> (8 * b));
            section[kStubCall2DispX64 + b] = static_cast<std::uint8_t>(disp_exit >> (8 * b));
        }
    } else {
        store32(section, kStubPathImmX86, image_va(path_rva_off));
        store32(section, kStubCall1ImmX86,
                image_va(iat_off + static_cast<std::uint32_t>(load_slot * thunk_width)));
        store32(section, kStubCall2ImmX86,
                image_va(iat_off + static_cast<std::uint32_t>(exit_slot * thunk_width)));
    }

    // Assemble the PE image with the wrapper's header shape.
    const auto section_raw = align_up(static_cast<std::uint32_t>(section.size()), kFileAlignment);
    const auto image_size =
        kSectionRva +
        std::max(align_up(static_cast<std::uint32_t>(section.size()), kSectionAlignment),
                 kSectionAlignment);

    std::vector<std::uint8_t> out;
    out.assign(kSizeOfHeaders + section_raw, 0);
    out[0] = 'M';
    out[1] = 'Z';
    store16(out, 0x02, 0x0003);
    store16(out, 0x04, 0x0001);
    store16(out, 0x0C, 0x0001);
    store16(out, 0x18, 0x0040);
    store32(out, 0x3C, 0x40);
    store32(out, 0x40, 0x00004550);
    const std::size_t coff = 0x44;
    store16(out, coff + 0x00, is_x64 ? kMachineX64 : kMachineX86);
    store16(out, coff + 0x02, 1);
    store32(out, coff + 0x08, 0); // timestamp: determinism
    store16(out, coff + 0x10, is_x64 ? 0xF0 : 0xE0);
    store16(out, coff + 0x12, kImageCharacteristics);
    const std::size_t opt = coff + 0x14;
    store16(out, opt + 0x00, is_x64 ? kOptionalHeaderMagicX64 : kOptionalHeaderMagicX86);
    out[opt + 0x02] = 1;
    store32(out, opt + 0x04, section_raw);
    store32(out, opt + 0x10, kSectionRva); // entry = section head (the stub)
    store32(out, opt + 0x14, kSectionRva);
    if (is_x64) {
        store32(out, opt + 0x18, kRunnerImageBase);
    } else {
        store32(out, opt + 0x18, kSectionRva); // BaseOfData
        store32(out, opt + 0x1C, kRunnerImageBase);
    }
    store32(out, opt + 0x20, kSectionAlignment);
    store32(out, opt + 0x24, kFileAlignment);
    store16(out, opt + 0x28, 6);
    store16(out, opt + 0x2C, 0);
    store16(out, opt + 0x30, 6);
    store32(out, opt + 0x34, 0);
    store32(out, opt + 0x38, image_size);
    store32(out, opt + 0x3C, kSizeOfHeaders);
    store32(out, opt + 0x40, 0);
    store16(out, opt + 0x44, 3); // console
    store16(out, opt + 0x46, 0); // no ASLR, no relocs
    if (is_x64) {
        store32(out, opt + 0x48, 0x00100000);
        store32(out, opt + 0x4C, 0);
        store32(out, opt + 0x50, 0x00001000);
        store32(out, opt + 0x54, 0);
        store32(out, opt + 0x58, 0x00100000);
        store32(out, opt + 0x5C, 0);
        store32(out, opt + 0x60, 0x00001000);
        store32(out, opt + 0x64, 0);
        store32(out, opt + 0x68, 0);
        store32(out, opt + 0x6C, 16);
    } else {
        store32(out, opt + 0x48, 0x00100000);
        store32(out, opt + 0x4C, 0x00001000);
        store32(out, opt + 0x50, 0x00100000);
        store32(out, opt + 0x54, 0x00001000);
        store32(out, opt + 0x58, 0);
        store32(out, opt + 0x5C, 16);
    }
    // data directory[1] = import table
    store32(out, opt + (is_x64 ? 0x70 : 0x68) + 8, kSectionRva + descriptor_off);
    store32(out, opt + (is_x64 ? 0x70 : 0x68) + 12, static_cast<std::uint32_t>(descriptor_bytes));

    const std::size_t sec = is_x64 ? kSectionHeaderOffsetX64 : kSectionHeaderOffsetX86;
    std::memcpy(out.data() + sec, ".text", 5);
    store32(out, sec + 0x08, static_cast<std::uint32_t>(section.size()));
    store32(out, sec + 0x0C, kSectionRva);
    store32(out, sec + 0x10, section_raw);
    store32(out, sec + 0x14, kSizeOfHeaders);
    store32(out, sec + 0x24, kRunnerSectionCharacteristics);

    std::memcpy(out.data() + kSizeOfHeaders, section.data(), section.size());
    return out;
}

} // namespace sheller::capture
