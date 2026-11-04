#include "guest_objects.h"

#include "diag_trace.h"

#include "../loader/loader.h"
#include "../syscalls/syscall_number_map.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iterator>

namespace sheller::engine {
namespace {

// -- section objects ---------------------------------

SectionObject* resolve_section(SyscallRunState& state, const std::uint64_t handle)
{
    if (handle < kSectionHandleBase || (handle - kSectionHandleBase) % kSectionHandleStride != 0) {
        return nullptr;
    }
    const auto index =
        static_cast<std::size_t>((handle - kSectionHandleBase) / kSectionHandleStride);
    if (index >= state.sections.size()) {
        return nullptr;
    }
    return &state.sections.at(index);
}

std::uint64_t issue_section(SyscallRunState& state, SectionObject object)
{
    state.sections.push_back(std::move(object));
    return kSectionHandleBase + (state.sections.size() - 1) * kSectionHandleStride;
}

void write_section_handle(SyscallRunState& state, uc_engine* const uc, const std::uint64_t pointer,
                          const std::uint64_t handle)
{
    if (pointer == 0) {
        return;
    }
    if (state.guest_mode == GuestMode::kX86) {
        const auto handle32 = static_cast<std::uint32_t>(handle);
        uc_mem_write(uc, pointer, &handle32, sizeof handle32);
    } else {
        uc_mem_write(uc, pointer, &handle, sizeof handle);
    }
}

// Reads and folds the OBJECT_ATTRIBUTES' ObjectName (arch-shaped), stripping
// the \KnownDlls\ directory prefix - the only namespace the engine carries.
bool read_section_object_name(SyscallRunState& state, uc_engine* const uc,
                              const std::uint64_t objattr, std::string& folded)
{
    const bool x86 = state.guest_mode == GuestMode::kX86;
    std::uint64_t name_ptr = 0;
    if (x86) {
        name_ptr = read_guest_u32(uc, objattr + 8);
    } else if (uc_mem_read(uc, objattr + 0x10, &name_ptr, sizeof name_ptr) != UC_ERR_OK) {
        return false;
    }
    if (name_ptr == 0) {
        return false;
    }
    std::uint16_t bytes = 0;
    uc_mem_read(uc, name_ptr, &bytes, sizeof bytes);
    std::uint64_t buffer = 0;
    if (x86) {
        buffer = read_guest_u32(uc, name_ptr + 4);
    } else {
        uc_mem_read(uc, name_ptr + 8, &buffer, sizeof buffer);
    }
    std::string name;
    for (std::uint16_t i = 0; i + 2 <= bytes; i += 2) {
        char c = 0;
        uc_mem_read(uc, buffer + i, &c, 1);
        name.push_back(c);
    }
    folded = fold_name(name);
    constexpr std::string_view kKnownDllsPrefix = "\\knowndlls\\";
    if (folded.size() > kKnownDllsPrefix.size() &&
        folded.compare(0, kKnownDllsPrefix.size(), kKnownDllsPrefix) == 0) {
        folded.erase(0, kKnownDllsPrefix.size());
    }
    return !folded.empty();
}

} // namespace

void apply_open_section(SyscallRunState& state, uc_engine* uc,
                        [[maybe_unused]] const syscalls::SyscallFrame& frame,
                        syscalls::SyscallOutcome& outcome)
{
    std::string folded;
    if (!read_section_object_name(state, uc, outcome.section_objattr, folded)) {
        outcome.status = syscalls::kStatusObjectNameNotFound;
        return;
    }
    for (std::size_t i = 0; i < state.region_map->module_count(); ++i) {
        const auto& module = state.region_map->module(i);
        if (std::string_view(module.name.data()) == folded) {
            SectionObject object;
            object.view_size = module.size;
            const auto name_bytes = (std::min)(folded.size(), object.name.size() - 1);
            std::memcpy(object.name.data(), folded.data(), name_bytes);
            object.known_dll = true;
            const auto handle = issue_section(state, std::move(object));
            write_section_handle(state, uc, outcome.section_handle_out, handle);
            return;
        }
    }
    // The
    // real kernel answers OBJECT_NAME_NOT_FOUND for any name outside the
    // captured module set - non-resident system DLLs (kernel.appcore.dll on
    // the packed corpus) are NOT KnownDlls on the desktop host, and the real
    // loader takes the file path (NtOpenFile -> NtCreateSection(file)). A
    // prior System-DLL fallback here answered a synthetic section for any
    // host-System32 name, which walked the replayed loader down the
    // KnownDll-section branch native never runs (its failure tail is the
    // WER report path built on NtAlpcConnectPort).
    outcome.status = syscalls::kStatusObjectNameNotFound;
}

void apply_create_section(SyscallRunState& state, uc_engine* uc,
                          [[maybe_unused]] const syscalls::SyscallFrame& frame,
                          syscalls::SyscallOutcome& outcome)
{
    // A FileHandle makes this an image-section create
    // (the real loader's non-KnownDll DLL loads) - bind the captured host
    // file bytes; the view size is the PE's SizeOfImage. Fail-soft: an
    // unresolvable handle, absent bytes or malformed PE keep the invalid-
    // parameter answer the zero-size pagefile path uses.
    if (outcome.section_file_handle != 0) {
        if (outcome.section_file_handle < kFileHandleBase ||
            (outcome.section_file_handle - kFileHandleBase) % kFileHandleStride != 0) {
            outcome.status = syscalls::kStatusInvalidHandle;
            return;
        }
        const auto file_index = static_cast<std::size_t>(
            (outcome.section_file_handle - kFileHandleBase) / kFileHandleStride);
        if (file_index >= state.files.size()) {
            outcome.status = syscalls::kStatusInvalidHandle;
            return;
        }
        const auto& file_bytes = state.files[file_index].content;
        const auto info = loader::parse_pe(file_bytes);
        if (!info || info->image_size == 0 || info->image_size > kMaxSectionBytes) {
            outcome.status = syscalls::kStatusInvalidParameter;
            return;
        }
        SectionObject object;
        object.view_size = info->image_size;
        object.source_bytes = file_bytes;
        const auto handle = issue_section(state, std::move(object));
        write_section_handle(state, uc, outcome.section_handle_out, handle);
        return;
    }
    const auto size = (outcome.section_maxsize + 0xFFFULL) & ~0xFFFULL;
    if (size == 0 || size > kMaxSectionBytes) {
        outcome.status = syscalls::kStatusInvalidParameter;
        return;
    }
    SectionObject object;
    object.view_size = size;
    const auto handle = issue_section(state, std::move(object));
    write_section_handle(state, uc, outcome.section_handle_out, handle);
}

namespace {

// Build the mapped-view image bytes from a host file's raw bytes: build with
// the loader's own mapper and RELOCATE for the actual view base - the
// kernel's memory manager does the same when mapping an image section at a
// non-preferred base; skipping it leaves stale absolute pointers that make
// real CRT/loader code write through wrong addresses. Windows-only and
// fail-soft - malformed bytes leave the content empty (the view stays
// zero-filled and the loader's image validation fails the load cleanly).
void build_image_content(SectionObject& section, const std::vector<std::uint8_t>& bytes,
                         const std::uint64_t view_base)
{
#ifdef _WIN32
    const auto info = loader::parse_pe(bytes);
    if (!info) {
        return;
    }
    auto image = loader::build_image(bytes, *info);
    if (!image) {
        return;
    }
    const auto base_delta = view_base - info->image_base;
    if (base_delta != 0) {
        static_cast<void>(loader::apply_relocations(*image, *info, base_delta));
    }
    section.content = std::move(*image);
    // Two rebuilt-image hygiene fixes the loader's deep validation trips
    // over with STATUS_INVALID_IMAGE_FORMAT:
    // - the file's CheckSum no longer describes the rebuilt byte layout -
    //   zero it so the comparison is skipped;
    // - the Security directory (Authenticode signature) lives past
    //   SizeOfImage in the FILE and is not part of the built view - a
    //   non-empty entry reads past the mapping. Zero it; nothing in the
    //   replay verifies signatures.
    if (section.content.size() > 0x40 + 4) {
        const auto e_lfanew = static_cast<std::uint64_t>(section.content[0x3c]) |
                              (static_cast<std::uint64_t>(section.content[0x3d]) << 8) |
                              (static_cast<std::uint64_t>(section.content[0x3e]) << 16) |
                              (static_cast<std::uint64_t>(section.content[0x3f]) << 24);
        if (e_lfanew + 0x40 + 4 <= section.content.size()) {
            const std::array<std::uint8_t, 4> zero_checksum{};
            std::memcpy(section.content.data() + e_lfanew + 0x40, zero_checksum.data(), 4);
        }
        constexpr auto kSecurityDirOffset = 0x18 + 0x70 + 4 * 8; // opt + DataDirectory[4]
        if (e_lfanew + kSecurityDirOffset + 8 <= section.content.size()) {
            const std::array<std::uint8_t, 8> zero_dir{};
            std::memcpy(section.content.data() + e_lfanew + kSecurityDirOffset, zero_dir.data(),
                        zero_dir.size());
        }
    }
#else
    (void)section;
    (void)bytes;
    (void)view_base;
#endif
}

// KnownDLL views carry real content: the host's DLL image looked up by the
// section's folded name in the host system directory.
void backfill_section_content(SyscallRunState& state, SectionObject& section,
                              const std::uint64_t view_base)
{
#ifdef _WIN32
    char system_root[MAX_PATH] = {};
    const auto len = state.guest_mode == GuestMode::kX86
                         ? GetSystemWow64DirectoryA(system_root, sizeof system_root)
                         : GetSystemDirectoryA(system_root, sizeof system_root);
    if (len == 0) {
        return;
    }
    const auto dll_path = std::filesystem::path(system_root) / std::string(section.name.data());
    std::ifstream in(dll_path, std::ios::binary);
    if (!in) {
        return;
    }
    std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(in),
                                    std::istreambuf_iterator<char>()};
    build_image_content(section, bytes, view_base);
#else
    (void)state;
    (void)view_base;
    (void)section;
#endif
}

// Foreign-thunk DLLs (kernel.appcore.dll and its kin export
// `jmp qword ptr [rip+disp]` thunks whose target slots the system loader
// patches at real load time from outside the file) can never execute from
// the raw image: the slots hold placeholder values that point into
// unrelated .rdata bytes. Synthesize the desktop-default answers in place:
// every AppPolicy getter takes (handle, out u32*) and the desktop answer is
// S_OK with the classic enum value - for AppPolicyGetProcessTerminationMethod
// that is 1 (ExitProcess), the value ucrt's exit path requires to flush
// stdio instead of TerminateProcess. The stub rides in the final page's
// relocation padding, inside the view, and each unbound slot is repointed at
// it. Runs after the built image is in guest memory (the export walk reads
// the mapped view).
void patch_foreign_thunks(SyscallRunState& state, SectionObject& section,
                          const std::uint64_t view_base)
{
    if (state.guest_mode != GuestMode::kX64 || section.content.size() < 0x20) {
        return;
    }
    const auto stub_offset = section.content.size() - 0x20;
    const std::array<std::uint8_t, 9> desktop_stub = {0xC7, 0x02, 0x00, 0x00, 0x00,
                                                      0x00,       // mov dword ptr [rdx], 0
                                                      0x31, 0xC0, // xor eax, eax
                                                      0xC3};      // ret
    std::memcpy(section.content.data() + stub_offset, desktop_stub.data(), desktop_stub.size());
    uc_mem_write(state.uc, view_base + stub_offset, desktop_stub.data(), desktop_stub.size());
    for (const auto& export_entry : syscalls::enumerate_exports(state.uc, view_base)) {
        std::array<std::uint8_t, 6> thunk{};
        if (uc_mem_read(state.uc, export_entry.address, thunk.data(), thunk.size()) != UC_ERR_OK ||
            thunk[0] != 0xFF || thunk[1] != 0x25) {
            continue; // not an unbound rip-relative thunk
        }
        std::int32_t disp = 0;
        for (std::size_t i = 0; i < 4; ++i) {
            disp |= static_cast<std::int32_t>(thunk[2 + i]) << (8 * i);
        }
        const auto slot_va = export_entry.address + 6 + static_cast<std::uint64_t>(disp);
        const auto slot_rva = slot_va - view_base;
        if (slot_va < view_base || slot_rva >= section.content.size()) {
            continue;
        }
        const auto stub_va = view_base + stub_offset;
        uc_mem_write(state.uc, slot_va, &stub_va, sizeof stub_va);
        std::memcpy(section.content.data() + slot_rva, &stub_va, sizeof stub_va);
    }
}

} // namespace

void apply_map_view_of_section(SyscallRunState& state, uc_engine* uc,
                               [[maybe_unused]] const syscalls::SyscallFrame& frame,
                               syscalls::SyscallOutcome& outcome)
{
    auto* section = resolve_section(state, outcome.map_view_handle);
    if (section == nullptr) {
        outcome.status = syscalls::kStatusInvalidHandle;
        return;
    }
    if (section->view_size == 0 || section->view_size > kMaxSectionBytes) {
        outcome.status = syscalls::kStatusInvalidParameter;
        return;
    }
    const bool x86 = state.guest_mode == GuestMode::kX86;
    std::uint64_t requested = 0;
    if (x86) {
        requested = read_guest_u32(uc, outcome.map_view_base_ptr);
    } else {
        uc_mem_read(uc, outcome.map_view_base_ptr, &requested, sizeof requested);
    }
    std::uint64_t base = 0;
    if (requested != 0) {
        // map into the caller's reservation: commit each page zero-filled
        base = requested & ~0xFFFULL;
        for (std::uint64_t page = 0; page < section->view_size; page += 0x1000) {
            std::uint8_t probe = 0;
            if (uc_mem_read(uc, base + page, &probe, 1) != UC_ERR_OK) {
                if (uc_mem_map(uc, base + page, 0x1000, UC_PROT_ALL) != UC_ERR_OK) {
                    outcome.status = syscalls::kStatusNoMemory;
                    return;
                }
            }
        }
    } else {
        const auto& layout = layout_for(state.guest_mode);
        base = (state.valloc_cursor + 0xFFFULL) & ~0xFFFULL;
        if (base + section->view_size > layout.alloc_end) {
            outcome.status = syscalls::kStatusNoMemory;
            return;
        }
        if (uc_mem_map(uc, base, static_cast<std::size_t>(section->view_size), UC_PROT_ALL) !=
            UC_ERR_OK) {
            outcome.status = syscalls::kStatusNoMemory;
            return;
        }
        state.valloc_cursor = base + section->view_size;
    }
    if (section->known_dll && section->content.empty() && !section->name.empty()) {
        backfill_section_content(state, *section, base);
    }
    if (section->content.empty() && !section->source_bytes.empty()) {
        build_image_content(*section, section->source_bytes, base);
    }
    if (!section->content.empty()) {
        const auto content_bytes =
            (std::min)(section->content.size(), static_cast<std::size_t>(section->view_size));
        uc_mem_write(uc, base, section->content.data(), content_bytes);
        patch_foreign_thunks(state, *section, base);
    } else {
        // commit semantics: fresh reservations may hold stale bytes, views
        // are zero-filled
        std::array<std::uint8_t, 0x1000> zeros{};
        for (std::uint64_t page = 0; page < section->view_size; page += zeros.size()) {
            uc_mem_write(uc, base + page, zeros.data(), zeros.size());
        }
    }
    if (state.write_ledger != nullptr) {
        state.write_ledger->add_region(base, section->view_size, kPageReadWrite, kMemPrivate);
    }
    if (x86) {
        const auto base32 = static_cast<std::uint32_t>(base);
        const auto size32 = static_cast<std::uint32_t>(section->view_size);
        uc_mem_write(uc, outcome.map_view_base_ptr, &base32, sizeof base32);
        // a NULL *ViewSize is legal caller semantics (size not wanted);
        // same for an unreadable argument stack - the base answer stands
        if (outcome.map_view_size_ptr != 0) {
            uc_mem_write(uc, outcome.map_view_size_ptr, &size32, sizeof size32);
        }
    } else {
        uc_mem_write(uc, outcome.map_view_base_ptr, &base, sizeof base);
        if (outcome.map_view_size_ptr != 0) {
            uc_mem_write(uc, outcome.map_view_size_ptr, &section->view_size,
                         sizeof section->view_size);
        }
    }
}

// Minimal file-object semantics. Handles are
// deterministic (constants shared with the section table above); content is
// read from the host filesystem at open time, so replayed payload I/O sees
// real bytes.

// A bare DOS drive name: one letter, optionally followed by a colon
// ("C" / "C:") - the loader's search-path probes open the drive root.
bool is_dos_drive_name(const std::u16string& wide)
{
    const auto letter = wide.empty() ? u'\0' : wide[0];
    const bool alpha = (letter >= u'a' && letter <= u'z') || (letter >= u'A' && letter <= u'Z');
    return alpha && (wide.size() == 1 || (wide.size() == 2 && wide[1] == u':'));
}

// Resolve a guest OBJECT_ATTRIBUTES' ObjectName to a host filesystem path.
// Returns nullopt when the name is unreadable or the host object is absent
// (the failure status rides the outcome). Existing directories - including
// DOS drive roots - resolve with directory=true: the real loader's DLL
// search-path iteration opens those probes to succeed, and answering
// OBJECT_NAME_NOT_FOUND for them derails LdrLoadDll into an error branch.
std::optional<ResolvedGuestPath> resolve_guest_file_path(SyscallRunState& state_, uc_engine* uc,
                                                         const std::uint64_t objattr,
                                                         syscalls::SyscallOutcome& outcome)
{
    // OBJECT_ATTRIBUTES.ObjectName (+0x10) -> UNICODE_STRING {u16 len, u16
    // max, u16* buffer}: the guest path, wide chars.
    std::uint64_t name_struct = 0;
    if (objattr == 0 ||
        uc_mem_read(uc, objattr + 0x10, &name_struct, sizeof name_struct) != UC_ERR_OK) {
        outcome.status = syscalls::kStatusInvalidParameter;
        return std::nullopt;
    }
    std::uint16_t length = 0;
    std::uint64_t buffer = 0;
    if (uc_mem_read(uc, name_struct, &length, sizeof length) != UC_ERR_OK ||
        uc_mem_read(uc, name_struct + 8, &buffer, sizeof buffer) != UC_ERR_OK) {
        outcome.status = syscalls::kStatusInvalidParameter;
        return std::nullopt;
    }
    // u16 (not wstring): std::u16string is a standard fs::path source
    // (UTF-16, converted to the native encoding) and works on every host -
    // a wstring source compiles only on Windows and aborts on Linux
    // (libstdc++ throws conversion_error outside hook context, and the
    // engine builds with -fno-exceptions). Reinterpreting the UTF-16 bytes
    // as char8_t is equally wrong: each ASCII wide char carries a 0x00
    // trail byte that truncates the path.
    std::u16string wide;
    wide.resize(length / 2);
    if (!wide.empty() &&
        uc_mem_read(uc, buffer, wide.data(), wide.size() * sizeof(char16_t)) != UC_ERR_OK) {
        outcome.status = syscalls::kStatusInvalidParameter;
        return std::nullopt;
    }
    // The guest builds these UNICODE_STRINGs with the terminator inside
    // Length: a trailing embedded null would ride the fs::path (every
    // exists() check fails) and print as a truncated name. No legitimate
    // path carries embedded nulls.
    while (!wide.empty() && wide.back() == u'\0') {
        wide.pop_back();
    }
    // the NT namespace prefix (\??\ or \\??\ or \Device\HarddiskVolume...):
    // the Win11 kernel builds it with a SINGLE leading backslash - strip
    // leading \...\ components until a rooted drive path remains
    while (!wide.empty() && wide[0] == u'\\') {
        const auto next = wide.find(u'\\', 1);
        if (next == std::u16string::npos) {
            break; // no further separator: the prefix is one component
        }
        wide.erase(0, next + 1);
    }
    std::error_code ec;
    // A bare DOS drive ("\??\C" after the prefix strip) is the drive root,
    // not a name to join against the base directory.
    std::filesystem::path guest_path{wide};
    const bool drive_root = is_dos_drive_name(wide);
    if (drive_root) {
        // the drive root, absolute: letter + ":/" (native spelling on a
        // Windows replay host; a POSIX host simply has no "C:/" directory
        // and the probe keeps its NOT_FOUND answer)
        const auto letter = wide[0];
        wide.assign(1, letter);
        wide.push_back(u':');
        wide.push_back(u'/');
        guest_path = std::filesystem::path{wide};
    }
    // relative guest paths resolve against the sample's directory, not the
    // replay host's CWD (which is wherever sheller itself was launched)
    const auto host_path = guest_path.is_relative() ? state_.relative_base / guest_path
                                                    : std::filesystem::absolute(guest_path, ec);
    const bool directory = !ec && std::filesystem::is_directory(host_path, ec);
    {
        // Diagnostic file-open trace: what the guest asked for, and whether
        // the replay host could serve it. Host file layout differences show
        // up here first.
        if (diag::file_on()) {
            const auto served =
                directory || (!ec && std::filesystem::is_regular_file(host_path, ec));
            diag::emit(sheller::log::level::kDebug, diag::file_on(), "[file] guest={} served={}",
                       guest_path.string(), static_cast<int>(served));
        }
    }
    if (ec || !(directory || std::filesystem::is_regular_file(host_path, ec))) {
        outcome.status = syscalls::kStatusObjectNameNotFound;
        return std::nullopt;
    }
    return ResolvedGuestPath{host_path, directory};
}

void apply_create_file(SyscallRunState& state, uc_engine* uc,
                       [[maybe_unused]] const syscalls::SyscallFrame& frame,
                       syscalls::SyscallOutcome& outcome)
{
    const auto resolved = resolve_guest_file_path(state, uc, outcome.file_objattr, outcome);
    if (!resolved.has_value()) {
        return;
    }
    SyscallRunState::FileObject file;
    if (resolved->directory) {
        // attribute-only probe object: reads answer EOF, the standard-info
        // query reports Directory=TRUE
        file.directory = true;
    } else {
        std::ifstream in(resolved->host, std::ios::binary);
        if (!in) {
            outcome.status = syscalls::kStatusObjectNameNotFound;
            return;
        }
        file.content.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        if (file.content.size() > kMaxSectionBytes) {
            outcome.status = syscalls::kStatusNoMemory; // sanity bound, same cap as sections
            return;
        }
    }
    state.files.push_back(std::move(file));
    const auto handle = kFileHandleBase + (state.files.size() - 1) * kFileHandleStride;
    const bool x86 = state.guest_mode == GuestMode::kX86;
    if (x86) {
        const auto handle32 = static_cast<std::uint32_t>(handle);
        uc_mem_write(uc, outcome.file_handle_out, &handle32, sizeof handle32);
    } else {
        uc_mem_write(uc, outcome.file_handle_out, &handle, sizeof handle);
    }
    // IO_STATUS_BLOCK: {NTSTATUS status, ULONG_PTR information}
    const std::uint64_t information = 1; // FILE_OPENED
    uc_mem_write(uc, outcome.file_io_status, &outcome.status, sizeof outcome.status);
    uc_mem_write(uc, outcome.file_io_status + 8, &information, sizeof information);
}

void apply_read_file(SyscallRunState& state, uc_engine* uc, const syscalls::SyscallFrame& frame,
                     syscalls::SyscallOutcome& outcome)
{
    if (outcome.read_handle < kFileHandleBase ||
        (outcome.read_handle - kFileHandleBase) % kFileHandleStride != 0) {
        outcome.status = syscalls::kStatusInvalidHandle;
        return;
    }
    const auto index =
        static_cast<std::size_t>((outcome.read_handle - kFileHandleBase) / kFileHandleStride);
    if (index >= state.files.size()) {
        outcome.status = syscalls::kStatusInvalidHandle;
        return;
    }
    auto& file = state.files[index];
    const auto remaining =
        file.content.size() > file.offset ? file.content.size() - file.offset : 0;
    const auto serve = (std::min)(static_cast<std::uint64_t>(remaining), outcome.read_length);
    if (serve != 0 && uc_mem_write(uc, outcome.read_buffer, file.content.data() + file.offset,
                                   static_cast<std::size_t>(serve)) != UC_ERR_OK) {
        outcome.status = syscalls::kStatusAccessDenied;
        return;
    }
    file.offset += serve;
    // IO_STATUS_BLOCK: status + bytes-transferred (0 at EOF = STATUS_END_OF_FILE)
    uc_mem_write(uc, outcome.read_io_status, &outcome.status, sizeof outcome.status);
    uc_mem_write(uc, outcome.read_io_status + 8, &serve, sizeof serve);
    static_cast<void>(frame);
}

void apply_query_file(SyscallRunState& state, uc_engine* uc,
                      [[maybe_unused]] const syscalls::SyscallFrame& frame,
                      syscalls::SyscallOutcome& outcome)
{
    constexpr std::uint64_t kFileStandardInformation = 5;
    if (outcome.query_file_class != kFileStandardInformation) {
        outcome.status = syscalls::kStatusInvalidParameter;
        return;
    }
    if (outcome.query_file_handle < kFileHandleBase ||
        (outcome.query_file_handle - kFileHandleBase) % kFileHandleStride != 0) {
        outcome.status = syscalls::kStatusInvalidHandle;
        return;
    }
    const auto index =
        static_cast<std::size_t>((outcome.query_file_handle - kFileHandleBase) / kFileHandleStride);
    if (index >= state.files.size()) {
        outcome.status = syscalls::kStatusInvalidHandle;
        return;
    }
    const auto& file = state.files[index];
    // FILE_STANDARD_INFORMATION: {LARGE_INTEGER AllocationSize, EndOfFile;
    // ULONG NumberOfLinks; BOOLEAN DeletePending, Directory; padding}
    if (outcome.query_file_len < 24) {
        outcome.status = syscalls::kStatusInfoLengthMismatch;
        return;
    }
    const std::uint64_t size = file.content.size();
    const std::uint64_t zero = 0;
    uc_mem_write(uc, outcome.query_file_out, &size, sizeof size);      // AllocationSize
    uc_mem_write(uc, outcome.query_file_out + 8, &size, sizeof size);  // EndOfFile
    uc_mem_write(uc, outcome.query_file_out + 16, &zero, sizeof zero); // links + flags
    if (file.directory) {
        const std::uint8_t directory_flag = 1; // BOOLEAN Directory at +21
        uc_mem_write(uc, outcome.query_file_out + 21, &directory_flag, sizeof directory_flag);
    }
    uc_mem_write(uc, outcome.query_file_iosb, &outcome.status, sizeof outcome.status);
    uc_mem_write(uc, outcome.query_file_iosb + 8, &outcome.query_file_len,
                 sizeof outcome.query_file_len); // bytes written
}

void apply_query_attributes([[maybe_unused]] SyscallRunState& state, uc_engine* uc,
                            [[maybe_unused]] const syscalls::SyscallFrame& frame,
                            syscalls::SyscallOutcome& outcome)
{
    const auto resolved = resolve_guest_file_path(state, uc, outcome.attributes_objattr, outcome);
    if (!resolved.has_value()) {
        return; // status set by the resolver (missing host file etc.)
    }
    // FILE_NETWORK_OPEN_INFORMATION, written through AllocationSize only.
    // This
    // call comes from LdrpGetNtPathFromDosPath, whose answer buffer sits
    // directly against its stack-cookie slot - the kernel's EndOfFile write
    // at buffer+0x28 lands ON the cookie. Native Win11 absorbs that: the
    // GS check fails, ntdll!_report_gsfailure runs (pure bookkeeping) and
    // returns, and the load proceeds. The replay cannot absorb it that way -
    // the same mismatch cascaded through the loader's WER service report
    // (NtAlpcConnectPort, rejected) into __fastfail(FAST_FAIL_FATAL_APP_EXIT).
    // Preserving the slot keeps the replay on native's post-check path: the
    // loader reads the query status, not the truncated size fields.
    // file_size with the error-code overload: a directory root on a POSIX
    // replay host (or an unqueryable object) must answer size 0, never throw
    // (the engine builds with -fno-exceptions).
    std::error_code size_ec;
    const auto size = resolved->directory ? std::uint64_t{0}
                                          : std::filesystem::file_size(resolved->host, size_ec);
    std::array<std::uint8_t, 0x28> info{};
    const auto put64 = [&](std::size_t offset, std::uint64_t value) {
        std::memcpy(info.data() + offset, &value, sizeof value);
    };
    put64(0x20, size_ec ? std::uint64_t{0} : size); // AllocationSize (EndOfFile at +0x28 would
                                                    // overlap the cookie)
    uc_mem_write(uc, outcome.attributes_out, info.data(), info.size());
}

} // namespace sheller::engine
