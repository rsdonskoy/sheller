#include "run_facts.h"

#include "rebuild_state.h"

#include "../syscalls/syscall_number_map.h"

#include <unicorn/unicorn.h>

#include <string>
#include <string_view>

namespace sheller::engine {
namespace {

// The captured process's own current directory: the faithful base for relative
// guest paths. PEB->ProcessParameters->CurrentDirectory is a CURDIR
// {UNICODE_STRING, HANDLE}; the snapshot route photographs it, so replay
// resolves exactly where the real process would have.
//
// Win11 24H2 x64 layout (verified against the captured packed sample):
// ProcessParameters at PEB+0x20, CurrentDirectory at +0x38, its DosPath
// UNICODE_STRING buffer pointer at +0x48. Any failed read or rejected value
// returns an empty path, and the caller keeps the guest's own base.
std::filesystem::path derived_cwd(uc_engine* const uc, const std::uint64_t peb)
{
    if (peb == 0) {
        return {};
    }
    std::uint64_t params = 0;
    std::uint64_t buffer = 0;
    std::uint16_t len = 0;
    if (uc_mem_read(uc, peb + 0x20, &params, sizeof params) != UC_ERR_OK || params == 0 ||
        uc_mem_read(uc, params + 0x40, &len, sizeof len) != UC_ERR_OK ||
        uc_mem_read(uc, params + 0x48, &buffer, sizeof buffer) != UC_ERR_OK || len < 2 ||
        len % 2 != 0) {
        return {};
    }
    // u16 (not wstring): std::u16string is a standard fs::path source on every
    // host; a wstring source compiles only on Windows and aborts the Linux
    // build.
    std::u16string wide(len / 2, u'\0');
    if (uc_mem_read(uc, buffer, wide.data(), wide.size() * sizeof(char16_t)) != UC_ERR_OK) {
        return {};
    }
    constexpr char16_t kSep = u'\\';
    if (!wide.empty() && wide.back() != kSep) {
        wide.push_back(kSep);
    }
    std::error_code ec;
    const std::filesystem::path cwd{wide};
    if (!cwd.is_absolute() || !std::filesystem::is_directory(cwd, ec)) {
        return {};
    }
    return cwd;
}

} // namespace

GuestFacts snapshot_guest_facts(const PreparedGuest& guest)
{
    GuestFacts facts;
    facts.relative_base = guest.relative_base;
    if (const auto cwd = derived_cwd(guest.unicorn.get(), guest.metadata.peb_address);
        !cwd.empty()) {
        facts.relative_base = cwd;
    }
    for (const auto& mod : guest.loader_modules) {
        if (fold_name(std::string_view(mod.name.data())) != "ntdll") {
            continue;
        }
        // Resolve number -> Nt name once (real ntdll stubs only; synthetic
        // 0x1000+ numbers never collide). One allocation, off the hook hot path.
        for (const auto& entry :
             syscalls::enumerate_ntdll_syscalls(guest.unicorn.get(), mod.base)) {
            facts.syscall_numbers_by_name.emplace(std::string(entry.name.data()), entry.number);
        }
        for (const auto& [name, number] : facts.syscall_numbers_by_name) {
            facts.syscall_names.emplace(number, name);
        }
        break;
    }
    for (std::size_t i = 0; i < guest.map.module_count(); ++i) {
        if (guest.map.module(i).base == guest.metadata.image_base) {
            facts.sample_image_size = guest.map.module(i).size;
            facts.sample_module_known = true;
            facts.sample_module_index = i;
            break;
        }
    }
    return facts;
}

} // namespace sheller::engine
