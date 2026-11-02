#include "intercept.h"

#include "diag_trace.h"
#include "dll_loader.h"
#include "engine_hooks.h"

#include "../loader/imports.h"
#include "../loader/loader.h"
#include "../syscalls/win32_nt_equivalence.h"

namespace sheller::engine {
namespace {

std::uint32_t protect_to_perms(std::uint32_t protect)
{
    switch (protect & 0xFF) {
    case 0x02:
        return UC_PROT_READ;
    case 0x04:
    case 0x08:
        return UC_PROT_READ | UC_PROT_WRITE;
    case 0x10:
        return UC_PROT_EXEC;
    case 0x20:
        return UC_PROT_READ | UC_PROT_EXEC;
    case 0x40:
    case 0x80:
        return UC_PROT_ALL;
    default:
        return UC_PROT_ALL;
    }
}

// Intercept argument fetch: x64 fastcall reads the call registers; x86
// stdcall reads the stack slots above the return address.
std::uint64_t intercept_arg(const SyscallRunState& state, const std::size_t index)
{
    if (state.guest_mode == GuestMode::kX86) {
        return read_guest_u32(state.uc, read_rsp(state.uc) + 4 + 4 * index);
    }
    constexpr uc_x86_reg kArgRegs[4]{UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9};
    std::uint64_t value = 0;
    if (index < 4) {
        uc_reg_read(state.uc, kArgRegs[index], &value);
    } else {
        // x64 fastcall spills arguments 5+ onto the caller's stack above
        // the 32-byte shadow space. The code hook fires at the entry's
        // FIRST instruction with the return address already pushed, so
        // rsp = entry_rsp - 8: slot i (0-based) sits at rsp + 8 + 0x20 +
        // 8*(i-4). uc_mem_read failure leaves 0 (deterministic).
        const auto slot = read_rsp(state.uc) + 0x28 + 8 * (index - 4);
        static_cast<void>(uc_mem_read(state.uc, slot, &value, sizeof value));
    }
    return value;
}

// Guest UTF-16 at va -> UTF-8 at the capture point (pinned conversion in
// the contract codec; NUL-terminated, capped by the parameter record cap).
std::string read_guest_wstring_utf8(SyscallRunState& state, const std::uint64_t va);
std::string read_guest_cstring(SyscallRunState& state, std::uint64_t va);

std::string read_guest_wstring_utf8(SyscallRunState& state, const std::uint64_t va)
{
    std::vector<std::uint8_t> raw;
    for (std::size_t i = 0; i < 260; ++i) {
        std::uint16_t c = 0;
        if (uc_mem_read(state.uc, va + 2 * i, &c, sizeof c) != UC_ERR_OK || c == 0) {
            break;
        }
        raw.push_back(static_cast<std::uint8_t>(c & 0xFF));
        raw.push_back(static_cast<std::uint8_t>(c >> 8));
    }
    std::string out;
    static_cast<void>(convert_utf16le_to_utf8(raw, out, kParamStrMaxBytes));
    return out;
}

std::string read_guest_cstring(SyscallRunState& state, std::uint64_t va)
{
    std::string out;
    for (std::size_t i = 0; i < 260; ++i) {
        char c = 0;
        if (uc_mem_read(state.uc, va + i, &c, 1) != UC_ERR_OK || c == 0) {
            break;
        }
        out.push_back(c);
    }
    return out;
}

// -- registry family --------------------------------

// Registry handles live in their own value range, away from the file and
// section handle ranges so a sample's cross-probing cannot alias them.
constexpr std::uint64_t kRegHandleBase = 0x5245470000000000ULL;

// Predefined root HKEY values (winreg.h): fold to stable small integers for
// the key table. Values outside the table are treated as their own custom
// root (fake-root probes from hostile samples answer normally).
std::uint32_t fold_registry_root(const std::uint64_t hkey)
{
    switch (static_cast<std::uint32_t>(hkey)) {
    case 0x80000000u:
        return 1; // HKEY_CLASSES_ROOT
    case 0x80000001u:
        return 2; // HKEY_CURRENT_USER
    case 0x80000002u:
        return 3; // HKEY_LOCAL_MACHINE
    case 0x80000003u:
        return 4; // HKEY_USERS
    case 0x80000005u:
        return 5; // HKEY_CURRENT_CONFIG
    default:
        return static_cast<std::uint32_t>(hkey) | 0x80000000u; // custom root
    }
}

// RegOpenKeyExA/W(hKey, lpSubKey, ulOptions, samDesired, phkResult):
// deterministic handle derived from (root, subkey); same key reopens to the
// same handle. phkResult receives the handle (ERROR_SUCCESS=0).
void intercept_reg_open(SyscallRunState& state, const bool wide)
{
    const auto root = fold_registry_root(intercept_arg(state, 0));
    const auto name_va = intercept_arg(state, 1);
    std::string subkey;
    if (wide) {
        std::string utf8;
        std::vector<std::uint8_t> raw;
        for (std::size_t i = 0; i < 260; ++i) {
            std::uint16_t c = 0;
            if (uc_mem_read(state.uc, name_va + 2 * i, &c, sizeof c) != UC_ERR_OK || c == 0) {
                break;
            }
            raw.push_back(static_cast<std::uint8_t>(c & 0xFF));
            raw.push_back(static_cast<std::uint8_t>(c >> 8));
        }
        static_cast<void>(convert_utf16le_to_utf8(raw, utf8, kParamStrMaxBytes));
        subkey = fold_name(utf8);
    } else {
        subkey = fold_name(read_guest_cstring(state, name_va));
    }
    const auto out_ptr = intercept_arg(state, 4);
    auto& table = state.registry_keys;
    const auto key = std::make_pair(root, subkey);
    const auto it = table.find(key);
    std::uint64_t handle = 0;
    if (it != table.end()) {
        handle = it->second; // reopen: same key, same handle
    } else {
        handle = kRegHandleBase + table.size();
        table.emplace(key, handle);
    }
    if (state.guest_mode == GuestMode::kX86) {
        const auto handle32 = static_cast<std::uint32_t>(handle);
        static_cast<void>(uc_mem_write(state.uc, out_ptr, &handle32, sizeof handle32));
    } else {
        static_cast<void>(uc_mem_write(state.uc, out_ptr, &handle, sizeof handle));
    }
    intercept_return(state, 0, state.guest_mode == GuestMode::kX86 ? 20 : 0);
}

// RegQueryValueExA/W(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData):
// the honest value-missing answer - ERROR_FILE_NOT_FOUND (2), type and
// length outputs zeroed - so the sample takes its "value absent" branch
// (the same design as the packed route's DLL-probe OBJECT_NAME_NOT_FOUND).
void intercept_reg_query(SyscallRunState& state)
{
    const auto type_ptr = intercept_arg(state, 3);
    const auto len_ptr = intercept_arg(state, 5);
    const auto zero32 = std::uint32_t{0};
    const auto handle = intercept_arg(state, 0);
    const bool valid = [&state, handle] {
        for (const auto& [key, value] : state.registry_keys) {
            if (value == handle) {
                return true;
            }
        }
        return false;
    }();
    if (type_ptr != 0) {
        static_cast<void>(uc_mem_write(state.uc, type_ptr, &zero32, sizeof zero32));
    }
    if (len_ptr != 0) {
        static_cast<void>(uc_mem_write(state.uc, len_ptr, &zero32, sizeof zero32));
    }
    const auto retval = valid ? 2u : 6u; // ERROR_FILE_NOT_FOUND / INVALID_HANDLE
    intercept_return(state, retval, state.guest_mode == GuestMode::kX86 ? 24 : 0);
}

// RegCloseKey(hKey): drops the table entry; stale handles answer
// INVALID_HANDLE on the next use.
void intercept_reg_close(SyscallRunState& state)
{
    const auto handle = intercept_arg(state, 0);
    for (auto it = state.registry_keys.begin(); it != state.registry_keys.end(); ++it) {
        if (it->second == handle) {
            state.registry_keys.erase(it);
            intercept_return(state, 0, state.guest_mode == GuestMode::kX86 ? 4 : 0);
            return;
        }
    }
    intercept_return(state, 6, state.guest_mode == GuestMode::kX86 ? 4 : 0); // INVALID_HANDLE
}

void intercept_virtual_alloc(SyscallRunState& state)
{
    // (process, size, type, protect)
    const auto size = intercept_arg(state, 1);
    const auto protect = intercept_arg(state, 3);
    const auto aligned = (size + 0xFFF) & ~0xFFFULL;
    const auto alloc_end = layout_for(state.guest_mode).alloc_end;
    if (aligned == 0 || state.valloc_cursor + aligned > alloc_end) {
        intercept_return(state, 0, 16); // NULL: out of the deterministic range
        return;
    }
    const auto base = state.valloc_cursor;
    state.valloc_cursor += aligned;
    uc_mem_map(state.uc, base, static_cast<std::size_t>(aligned),
               protect_to_perms(static_cast<std::uint32_t>(protect)));
    if (state.write_ledger != nullptr) {
        state.write_ledger->add_region(base, aligned, static_cast<std::uint32_t>(protect) & 0xFF,
                                       kMemPrivate);
    }
    // Issuer attribution (direct-issuance, symmetric with the syscall
    // route's alloc seam): the bounded stack scan classifies the allocation -
    // sample territory gets the full event surface, system-issued machinery
    // (CRT startup heaps) maps event-silently.
    const bool x64 = state.guest_mode == GuestMode::kX64;
    const bool sample_issued =
        stack_carries_sample_frame(state.uc, read_rsp(state.uc), x64, state.region_map, state);
    if (state.region_map != nullptr) {
        state.region_map->register_region(base, aligned, static_cast<std::uint32_t>(protect) & 0xFF,
                                          kMemPrivate, sample_issued);
    }
    intercept_return(state, base, 16);
}

void intercept_virtual_protect(SyscallRunState& state)
{
    // (process, page_bytes, new_protect, old_ptr)
    const auto address = intercept_arg(state, 0);
    const auto size = intercept_arg(state, 1);
    const auto protect = intercept_arg(state, 2);
    const auto old_ptr = intercept_arg(state, 3);
    const auto aligned_base = address & ~0xFFFULL;
    const auto aligned_size = (size + 0xFFF) & ~0xFFFULL;
    uc_mem_protect(state.uc, aligned_base, static_cast<std::size_t>(aligned_size),
                   protect_to_perms(static_cast<std::uint32_t>(protect)));
    // Symmetric with the syscall route's protect consumption: the covered
    // interval is carved at page granularity in the attribution map.
    if (state.region_map != nullptr) {
        state.region_map->apply_protection(aligned_base, aligned_size,
                                           static_cast<std::uint32_t>(protect) & 0xFF);
    }
    // The behavior fact rides the issuer (direct-issuance): a system module
    // protecting its own memory is infrastructure and stays event-silent.
    const bool x64_protect = state.guest_mode == GuestMode::kX64;
    const bool protect_sample_issued = stack_carries_sample_frame(
        state.uc, read_rsp(state.uc), x64_protect, state.region_map, state);
    // the protection flip is the behavior layer's RWX signal source
    if (state.behavior_sink && protect_sample_issued) {
        BehaviorFact fact;
        fact.kind = BehaviorFact::Kind::kProtect;
        fact.pc = 0;
        fact.addr = aligned_base;
        fact.aux = aligned_size;
        fact.size = static_cast<std::uint32_t>(protect);
        state.behavior_sink(fact);
    }
    if (old_ptr != 0) {
        const auto old_protect = static_cast<std::uint32_t>(protect);
        uc_mem_write(state.uc, old_ptr, &old_protect, sizeof old_protect);
    }
    intercept_return(state, 1, 16); // TRUE
}

// Resident-module lookup by folded name (API-set reduction first, then the
// module table). Pure: no load side effects. Shared by the load and handle
// queries. The API-set reduction follows the run's explicit context — the
// prefix rules in the synthetic routes, the directory map in directory mode
// (no fallback); an api-set name the map does not cover reduces to nothing.
std::uint64_t resident_module_base(const SyscallRunState& state, const std::string& folded)
{
    for (const auto& record : state.loader_modules) {
        if (fold_name(std::string_view(record.name.data())) == folded) {
            return record.base;
        }
    }
    if (state.directory_mode) {
        if (state.api_set_ctx.mode == loader::ApiSetContext::Mode::kDirectoryMap &&
            state.api_set_ctx.directory_map != nullptr) {
            auto contract = folded;
            if (contract.size() > 4 && contract.compare(contract.size() - 4, 4, ".dll") == 0) {
                contract.resize(contract.size() - 4);
            }
            if (contract.rfind("api-ms-", 0) != 0 && contract.rfind("ext-ms-", 0) != 0) {
                return 0;
            }
            const auto host = state.api_set_ctx.directory_map->host_for(contract, {});
            if (!host.has_value()) {
                return 0;
            }
            const auto host_folded = fold_name(*host);
            for (const auto& record : state.loader_modules) {
                if (fold_name(std::string_view(record.name.data())) == host_folded) {
                    return record.base;
                }
            }
        }
        return 0;
    }
    // API-set request: reduce to the host module (API Set Schema pre-pass,
    // loader::api_set_host) - the set has no image of its own, and the real
    // loader answers with the host module's base.
    if (const auto host = loader::api_set_host(folded); !host.empty()) {
        for (const auto& record : state.loader_modules) {
            if (fold_name(std::string_view(record.name.data())) == host) {
                return record.base;
            }
        }
    }
    return 0;
}

void intercept_load_library(SyscallRunState& state, const bool wide)
{
    const auto name_va = intercept_arg(state, 0);
    std::string name;
    if (wide) {
        for (std::size_t i = 0; i < 260; ++i) {
            std::uint16_t c = 0;
            uc_mem_read(state.uc, name_va + 2 * i, &c, sizeof c);
            if (c == 0) {
                break;
            }
            name.push_back(static_cast<char>(c));
        }
    } else {
        name = read_guest_cstring(state, name_va);
    }
    const auto folded = fold_name(name);

    // Dispatch order: resident modules (with API-set reduction) first; the
    // pending module second (synthetic load - the DLL-input route); a miss
    // answers 0 (DLL_NOT_FOUND family).
    const auto resident = resident_module_base(state, folded);
    if (resident != 0) {
        intercept_return(state, resident, 4);
        return;
    }
    if (state.pending_module != nullptr && folded == fold_name(state.pending_module->name)) {
        // Record the caller's resume site before the frames take over the
        // stack; the continuation slot finishes this call. call_base is the
        // aligned stack base every synthetic frame (TLS/DllMain) builds
        // from, so a callback's stack use cannot leak into the next frame.
        std::uint64_t rsp = read_rsp(state.uc);
        std::uint64_t ret = 0;
        uc_mem_read(state.uc, rsp, &ret, sizeof ret);
        state.dll_load.caller_rip = ret;
        state.dll_load.caller_rsp = rsp + 8;
        state.dll_load.call_base_rsp = state.dll_load.caller_rsp;
        if (state.dll_load.active) {
            // Repeat request: same base, no re-entry - answer directly.
            intercept_return(state, state.dll_load.base, 4);
            return;
        }
        if (const auto failure = synthesize_pending_load(state)) {
            // Construction failure: answer NULL, name the reason in the log
            // channel only - the guest sees a plain load failure.
            state.dll_load = {};
            intercept_return(state, 0, 4);
            return;
        }
        // Frames armed: hand the leg over (the resume slot completes the
        // answer with the handle or NULL after DllMain).
        state.api_resume = true;
        uc_emu_stop(state.uc);
        return;
    }
    intercept_return(state, 0, 4);
}

void intercept_get_module_handle(SyscallRunState& state, const bool wide)
{
    // Pure query: resident modules only. A not-yet-loaded pending module
    // does NOT materialize here (no mapping, no TLS, no DllMain) - that is
    // the whole point of splitting this from the load path.
    const auto name_va = intercept_arg(state, 0);
    std::string name;
    if (wide) {
        for (std::size_t i = 0; i < 260; ++i) {
            std::uint16_t c = 0;
            uc_mem_read(state.uc, name_va + 2 * i, &c, sizeof c);
            if (c == 0) {
                break;
            }
            name.push_back(static_cast<char>(c));
        }
    } else {
        name = read_guest_cstring(state, name_va);
    }
    intercept_return(state, resident_module_base(state, fold_name(name)), 4);
}

void intercept_get_proc_address(SyscallRunState& state)
{
    // (module, proc_name)
    const auto module_base = intercept_arg(state, 0);
    const auto name_va = intercept_arg(state, 1);
    const auto function_name = read_guest_cstring(state, name_va);
    std::uint64_t va = 0;
    for (const auto& entry : state.loader_exports) {
        if (entry.module_base == module_base && entry.name == function_name) {
            va = entry.function_va;
            break;
        }
    }
    intercept_return(state, va, 8);
}

void intercept_exit_process(SyscallRunState& state)
{
    const auto code = intercept_arg(state, 0);
    state.terminated = true;
    state.exit_code = static_cast<std::uint32_t>(code);
    uc_emu_stop(state.uc);
}

// DllMain-support family (DLL-input route). DisableThreadLibraryCalls is
// answered TRUE: thread events were never delivered, so "disabling" them
// changes nothing. GetStdHandle answers stable pseudo-handles; the write
// path does not read the handle (the single-sink contract), so the value
// only needs to be non-zero and distinct per standard stream.
void intercept_disable_thread_library_calls(SyscallRunState& state)
{
    intercept_return(state, 1, 4); // TRUE
}

void intercept_get_std_handle(SyscallRunState& state)
{
    // STD_INPUT_HANDLE (-10) / STD_OUTPUT_HANDLE (-11) / STD_ERROR_HANDLE (-12)
    constexpr std::uint64_t kStdPseudoBase = 0x5A1200000ULL;
    const auto which = static_cast<std::int64_t>(intercept_arg(state, 0));
    std::uint64_t handle = kStdPseudoBase;
    if (which == -11) {
        handle = kStdPseudoBase + 1;
    } else if (which == -12) {
        handle = kStdPseudoBase + 2;
    }
    intercept_return(state, handle, 4);
}

// strlen(s): the honest length of the NUL-terminated guest string, walked
// byte by byte (a failed read ends the walk - unmapped memory reads as if
// the string ended there). Capped to keep a hostile unterminated buffer
// from spinning the hook; cdecl cleans its own frame on both bitnesses.
void intercept_strlen(SyscallRunState& state)
{
    constexpr std::uint64_t kStrlenCap = 1ULL << 20;
    const auto va = intercept_arg(state, 0);
    std::uint64_t length = 0;
    if (va != 0) {
        while (length < kStrlenCap) {
            std::uint8_t byte = 0;
            if (uc_mem_read(state.uc, va + length, &byte, sizeof byte) != UC_ERR_OK || byte == 0) {
                break;
            }
            ++length;
        }
    }
    intercept_return(state, length, 0);
}

// Critical-section family: a no-op lock. Initialize writes nothing (the
// emulated Enter never reads the structure), Enter/Leave are vacuous, and
// Delete returns void. The spin-count variant answers TRUE.
void intercept_critical_section(SyscallRunState& state, const InterceptId id)
{
    switch (id) {
    case InterceptId::kInitializeCriticalSection:
    case InterceptId::kEnterCriticalSection:
    case InterceptId::kLeaveCriticalSection:
    case InterceptId::kDeleteCriticalSection:
        intercept_return(state, 0, 4); // void-shaped: rax value unused
        break;
    case InterceptId::kInitializeCriticalSectionAndSpinCount:
        intercept_return(state, 1, 4); // TRUE
        break;
    default:
        break;
    }
}

// FLS/TLS family: engine-side slot tables (deterministic indices, values
// kept per run state - the same slot answers for the whole run). Win32
// semantics: out-of-range index is FALSE/0, alloc never fails in practice;
// a deterministic exhaustion point (0xFFFFFFFF) keeps hostile loops honest.
void intercept_fls_tls(SyscallRunState& state, const InterceptId id)
{
    switch (id) {
    case InterceptId::kFlsAlloc:   // (callback) -> index
    case InterceptId::kTlsAlloc: { // () -> index
        if (state.tls_next_index == 0xFFFFFFFFull) {
            intercept_return(state, 0xFFFFFFFFull, 4); // TLS_OUT_OF_INDEXES
            return;
        }
        const auto index = state.tls_next_index++;
        intercept_return(state, index, 4);
        return;
    }
    case InterceptId::kFlsFree:
    case InterceptId::kTlsFree: // (index) -> BOOL
        intercept_return(state, 1, 4);
        return;
    case InterceptId::kFlsSetValue: // (index, value) -> BOOL
    case InterceptId::kTlsSetValue: {
        const auto index = static_cast<std::uint32_t>(intercept_arg(state, 0));
        const auto value = intercept_arg(state, 1);
        state.tls_slots[index] = value;
        intercept_return(state, 1, 4);
        return;
    }
    case InterceptId::kFlsGetValue:
    case InterceptId::kTlsGetValue: { // (index) -> value (0 on miss)
        const auto index = static_cast<std::uint32_t>(intercept_arg(state, 0));
        const auto found = state.tls_slots.find(index);
        intercept_return(state, found != state.tls_slots.end() ? found->second : 0, 4);
        return;
    }
    case InterceptId::kAddVectoredExceptionHandler: // (first, handler) -> handle
        // Honest unsupported answer: NULL. The engine's dispatcher owns
        // exception delivery in this world; a silently dropped handler (a
        // fake success) would turn a DLL's handled exceptions into
        // unhandled ones with no observable reason. The CRT's fail-fast
        // registration tolerates a failed add.
        intercept_return(state, 0, 4);
        return;
    case InterceptId::kRemoveVectoredExceptionHandler: // (handle) -> ULONG
        intercept_return(state, 0, 4);                 // nothing was ever registered
        return;
    default:
        return;
    }
}

void intercept_rtl_allocate_heap(SyscallRunState& state)
{
    // (heap, flags, size)
    const auto size = intercept_arg(state, 2);
    const auto aligned = (size + 0xF) & ~0xFULL;
    const auto heap_end =
        layout_for(state.guest_mode).heap_base + layout_for(state.guest_mode).heap_size;
    if (aligned == 0 || state.heap_cursor + aligned > heap_end) {
        intercept_return(state, 0, 12);
        return;
    }
    const auto ptr = state.heap_cursor;
    state.heap_cursor += aligned;
    intercept_return(state, ptr, 12);
}

void intercept_virtual_free(SyscallRunState& state)
{
    intercept_return(state, 1, 12); // TRUE: decommit recorded, pages stay mapped
}

void intercept_rtl_free_heap(SyscallRunState& state)
{
    intercept_return(state, 1, 12); // TRUE: same recorded no-op as VirtualFree
}

void intercept_rtl_re_allocate_heap(SyscallRunState& state)
{
    // (heap, flags, ptr, size): a fresh allocation of the new size; the
    // contents copy needs the old size, which the heap bookkeeping does not
    // track - documented MVP limitation
    const auto size = intercept_arg(state, 3);
    const auto aligned = (size + 0xF) & ~0xFULL;
    const auto heap_end =
        layout_for(state.guest_mode).heap_base + layout_for(state.guest_mode).heap_size;
    if (aligned == 0 || state.heap_cursor + aligned > heap_end) {
        intercept_return(state, 0, 16);
        return;
    }
    const auto ptr = state.heap_cursor;
    state.heap_cursor += aligned;
    intercept_return(state, ptr, 16);
}

void intercept_rtl_create_heap(SyscallRunState& state)
{
    // (flags, base, reserve, commit, lock, params): the handle value is
    // opaque to the guest - the heap family never dereferences it, every
    // entry lands back in the engine bump allocator.
    intercept_return(state, layout_for(state.guest_mode).heap_base, 24);
}

void intercept_rtl_destroy_heap(SyscallRunState& state)
{
    // (heap): success; the bump region is not reclaimed (deterministic
    // no-reclaim, same contract as the free path).
    intercept_return(state, 1, 4);
}

void intercept_rtl_size_heap(SyscallRunState& state)
{
    // (heap, flags, ptr): sizes are untracked by the bump bookkeeping -
    // documented MVP limitation, same as the realloc copy gap.
    intercept_return(state, 0, 12);
}

void intercept_ldr_load_dll(SyscallRunState& state)
{
    // (path, chars, *UNICODE_STRING, *handle): resolve the requested DLL
    // against the loader route's resident modules. A resident hit returns
    // its synthetic LDR entry as the handle - downstream dereferences walk
    // a valid entry - and a miss answers STATUS_DLL_NOT_FOUND. Both without
    // running the real loader's load/teardown paths against the synthetic
    // Ldr: those read structures the environment does not provide and died
    // in cleanup on the packed corpus.
    constexpr std::uint64_t kStatusDllNotFound = 0xC0000135;
    const auto name_struct = intercept_arg(state, 2);
    const auto handle_ptr = intercept_arg(state, 3);
    const bool x86 = state.guest_mode == GuestMode::kX86;
    std::uint16_t bytes = 0;
    std::uint64_t buffer = 0;
    if (x86) {
        bytes = static_cast<std::uint16_t>(read_guest_u32(state.uc, name_struct));
        buffer = read_guest_u32(state.uc, name_struct + 4);
    } else {
        uc_mem_read(state.uc, name_struct, &bytes, sizeof bytes);
        uc_mem_read(state.uc, name_struct + 8, &buffer, sizeof buffer);
    }
    std::string requested;
    for (std::uint16_t i = 0; i + 2 <= bytes; i += 2) {
        char c = 0;
        uc_mem_read(state.uc, buffer + i, &c, 1);
        requested.push_back(c);
    }
    auto folded = fold_name(requested);
    if (!folded.empty() && folded.size() >= 4 &&
        folded.compare(folded.size() - 4, 4, ".exe") == 0) {
        folded.resize(folded.size() - 4); // resident under the module record name
    }
    for (std::size_t i = 0; i < state.loader_modules.size() && i < state.ldr_entry_vas.size();
         ++i) {
        const auto candidate = std::string(state.loader_modules.at(i).name.data());
        if (candidate != folded && (folded + ".dll") != candidate &&
            (folded + ".exe") != candidate) {
            continue;
        }
        if (x86) {
            const auto entry32 = static_cast<std::uint32_t>(state.ldr_entry_vas.at(i));
            uc_mem_write(state.uc, handle_ptr, &entry32, sizeof entry32);
        } else {
            const auto entry = state.ldr_entry_vas.at(i);
            uc_mem_write(state.uc, handle_ptr, &entry, sizeof entry);
        }
        intercept_return(state, 0, 16);
        return;
    }
    // A non-resident name in the SNAPSHOT route falls
    // through to the real captured loader - its native resolution path (API
    // set fold, KnownDll probe, System32 file search, file-backed image
    // section) is exactly what the native machine runs, and the engine's
    // aligned syscall answers carry it. The old unconditional DLL_NOT_FOUND
    // short-circuit killed the ucrtbase AppPolicy delay-load of
    // kernel.appcore.dll at its FIRST (api-set) attempt, forcing the fallback
    // full-path load whose KnownDll-probe failure ends in the WER report
    // path (the NtAlpcConnectPort this change was filed for). The LOADER
    // route keeps the answer: its synthetic Ldr dies in real load-path
    // cleanup (the reason this intercept exists).
    if (!state.loader_route) {
        state.pending_intercept = -1; // not handled: the real function runs
        return;
    }
    intercept_return(state, kStatusDllNotFound, 16);
}

} // namespace

// -- Loader-route API interception --

// Deterministic bump allocators. VirtualAlloc carves page-granular mappings
// upward from kLoaderAllocBase (defined with the loader layout constants);
// the Rtl heap trio carves 16-byte chunks from a pre-mapped heap region
// (Free is a recorded no-op - determinism over fidelity).

// intercept-set membership by resolved final function name
std::optional<std::uint32_t> intercept_id_for(std::string_view name)
{
    static const std::pair<std::string_view, std::uint32_t> kTable[] = {
        {"VirtualAlloc", static_cast<std::uint32_t>(InterceptId::kVirtualAlloc)},
        {"VirtualProtect", static_cast<std::uint32_t>(InterceptId::kVirtualProtect)},
        {"VirtualFree", static_cast<std::uint32_t>(InterceptId::kVirtualFree)},
        {"LoadLibraryA", static_cast<std::uint32_t>(InterceptId::kLoadLibraryA)},
        {"LoadLibraryW", static_cast<std::uint32_t>(InterceptId::kLoadLibraryW)},
        {"GetProcAddress", static_cast<std::uint32_t>(InterceptId::kGetProcAddress)},
        {"GetModuleHandleA", static_cast<std::uint32_t>(InterceptId::kGetModuleHandleA)},
        {"GetModuleHandleW", static_cast<std::uint32_t>(InterceptId::kGetModuleHandleW)},
        {"ExitProcess", static_cast<std::uint32_t>(InterceptId::kExitProcess)},
        // DLL-input route: DllMain bodies of real corpora call these before
        // anything else; their real implementations walk ntdll internals the
        // emulated world does not provision, so they answer in-engine.
        {"DisableThreadLibraryCalls",
         static_cast<std::uint32_t>(InterceptId::kDisableThreadLibraryCalls)},
        {"GetStdHandle", static_cast<std::uint32_t>(InterceptId::kGetStdHandle)},
        {"InitializeCriticalSection",
         static_cast<std::uint32_t>(InterceptId::kInitializeCriticalSection)},
        {"InitializeCriticalSectionAndSpinCount",
         static_cast<std::uint32_t>(InterceptId::kInitializeCriticalSectionAndSpinCount)},
        {"EnterCriticalSection", static_cast<std::uint32_t>(InterceptId::kEnterCriticalSection)},
        {"LeaveCriticalSection", static_cast<std::uint32_t>(InterceptId::kLeaveCriticalSection)},
        {"DeleteCriticalSection", static_cast<std::uint32_t>(InterceptId::kDeleteCriticalSection)},
        // The kernel32 critical-section exports are forwarders: IAT binding
        // follows them to these ntdll entries, so the ntdll-side names need
        // the same treatment.
        {"RtlInitializeCriticalSection",
         static_cast<std::uint32_t>(InterceptId::kInitializeCriticalSection)},
        {"RtlInitializeCriticalSectionAndSpinCount",
         static_cast<std::uint32_t>(InterceptId::kInitializeCriticalSectionAndSpinCount)},
        {"RtlEnterCriticalSection", static_cast<std::uint32_t>(InterceptId::kEnterCriticalSection)},
        {"RtlLeaveCriticalSection", static_cast<std::uint32_t>(InterceptId::kLeaveCriticalSection)},
        {"RtlDeleteCriticalSection",
         static_cast<std::uint32_t>(InterceptId::kDeleteCriticalSection)},
        // FLS/TLS: the CRT resolves these dynamically during DllMain init
        // (FlsGetValue2 is the Win11 spelling it probes for). Engine-side
        // slot tables answer - the real bodies read TEB storage that is not
        // provisioned.
        {"FlsAlloc", static_cast<std::uint32_t>(InterceptId::kFlsAlloc)},
        {"RtlFlsAlloc", static_cast<std::uint32_t>(InterceptId::kFlsAlloc)},
        {"FlsFree", static_cast<std::uint32_t>(InterceptId::kFlsFree)},
        {"RtlFlsFree", static_cast<std::uint32_t>(InterceptId::kFlsFree)},
        {"FlsSetValue", static_cast<std::uint32_t>(InterceptId::kFlsSetValue)},
        {"RtlFlsSetValue", static_cast<std::uint32_t>(InterceptId::kFlsSetValue)},
        {"FlsGetValue", static_cast<std::uint32_t>(InterceptId::kFlsGetValue)},
        {"FlsGetValue2", static_cast<std::uint32_t>(InterceptId::kFlsGetValue)},
        {"RtlFlsGetValue", static_cast<std::uint32_t>(InterceptId::kFlsGetValue)},
        {"TlsAlloc", static_cast<std::uint32_t>(InterceptId::kTlsAlloc)},
        {"RtlTlsAlloc", static_cast<std::uint32_t>(InterceptId::kTlsAlloc)},
        {"TlsFree", static_cast<std::uint32_t>(InterceptId::kTlsFree)},
        {"RtlTlsFree", static_cast<std::uint32_t>(InterceptId::kTlsFree)},
        {"TlsSetValue", static_cast<std::uint32_t>(InterceptId::kTlsSetValue)},
        {"RtlTlsSetValue", static_cast<std::uint32_t>(InterceptId::kTlsSetValue)},
        {"TlsGetValue", static_cast<std::uint32_t>(InterceptId::kTlsGetValue)},
        {"RtlTlsGetValue", static_cast<std::uint32_t>(InterceptId::kTlsGetValue)},
        // Vectored registration: answered in-engine (stable pseudo-handle);
        // the real path's ntdll bookkeeping cannot run against the
        // emulated world.
        {"AddVectoredExceptionHandler",
         static_cast<std::uint32_t>(InterceptId::kAddVectoredExceptionHandler)},
        {"AddVectoredContinueHandler",
         static_cast<std::uint32_t>(InterceptId::kAddVectoredExceptionHandler)},
        {"RtlAddVectoredExceptionHandler",
         static_cast<std::uint32_t>(InterceptId::kAddVectoredExceptionHandler)},
        {"RemoveVectoredExceptionHandler",
         static_cast<std::uint32_t>(InterceptId::kRemoveVectoredExceptionHandler)},
        {"RemoveVectoredContinueHandler",
         static_cast<std::uint32_t>(InterceptId::kRemoveVectoredExceptionHandler)},
        {"RtlRemoveVectoredExceptionHandler",
         static_cast<std::uint32_t>(InterceptId::kRemoveVectoredExceptionHandler)},
        {"RtlAllocateHeap", static_cast<std::uint32_t>(InterceptId::kRtlAllocateHeap)},
        {"RtlFreeHeap", static_cast<std::uint32_t>(InterceptId::kRtlFreeHeap)},
        {"RtlReAllocateHeap", static_cast<std::uint32_t>(InterceptId::kRtlReAllocateHeap)},
        {"RtlTerminateProcess", static_cast<std::uint32_t>(InterceptId::kExitProcess)},
        {"RegOpenKeyExA", static_cast<std::uint32_t>(InterceptId::kRegOpenKeyEx)},
        {"RegOpenKeyExW", static_cast<std::uint32_t>(InterceptId::kRegOpenKeyEx)},
        {"RegQueryValueExA", static_cast<std::uint32_t>(InterceptId::kRegQueryValueEx)},
        {"RegQueryValueExW", static_cast<std::uint32_t>(InterceptId::kRegQueryValueEx)},
        {"RegCloseKey", static_cast<std::uint32_t>(InterceptId::kRegCloseKey)},
        // Directory mode: real kernelbase bodies (lstrlenA et al) call this
        // CRT-in-ntdll spelling; the trap-classified derived body never runs.
        {"strlen", static_cast<std::uint32_t>(InterceptId::kStrlen)},
    };
    for (const auto& [key, id] : kTable) {
        if (key == name) {
            return id;
        }
    }
    return std::nullopt;
}

// The apicall event for the intercept in flight: name-in-band + module
// index + flags + retval (the handler's result) + caller (stack return
// address, still intact at this point) + kind-encoded parameters. Scalar
// intercepts report four u64 register values; the string-taking Win32
// entries report the captured text (A raw, W converted). Called from
// intercept_return BEFORE the stack pop mutates the frame.
void emit_intercept_event(SyscallRunState& state, const std::uint64_t retval)
{
    const auto index = state.pending_intercept;
    state.pending_intercept = -1;
    if (!state.event_sink || index < 0 ||
        index >= static_cast<std::int32_t>(state.intercept_names.size())) {
        return;
    }
    const auto slot = static_cast<std::size_t>(index);
    const auto id = static_cast<InterceptId>(state.intercept_ids[slot]);
    std::uint64_t caller = 0;
    static_cast<void>(uc_mem_read(state.uc, read_rsp(state.uc), &caller, sizeof caller));
    std::array<std::uint8_t, kApiCallFixedBytes + 255 + 3 + kParamStrMaxBytes + 3 * 11> fields{};
    const ApiCallFields head{.name = state.intercept_names[slot],
                             .module = state.intercept_modules[slot],
                             .flags = retval != 0 ? kEventFlagSuccess : std::uint8_t{0},
                             .retval = retval,
                             .caller_retaddr = caller};
    auto head_end = encode_api_call_head(fields, head);
    if (!head_end.has_value()) {
        return;
    }
    std::size_t cursor = *head_end;
    const auto add_scalar_args = [&] {
        for (std::size_t a = 0; a < 4; ++a) {
            std::array<std::uint8_t, 8> value{};
            le::store_le64(value.data(), intercept_arg(state, a));
            static_cast<void>(append_param_record(fields, cursor, ParamKind::kU64, value));
        }
    };
    const auto add_str_arg = [&](const std::size_t arg_index, const bool wide) {
        const auto text = wide ? read_guest_wstring_utf8(state, intercept_arg(state, arg_index))
                               : read_guest_cstring(state, intercept_arg(state, arg_index));
        static_cast<void>(append_param_record(
            fields, cursor, wide ? ParamKind::kStrW : ParamKind::kStrA,
            std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(text.data()),
                                          text.size()}));
    };
    switch (id) {
    case InterceptId::kLoadLibraryA:
    case InterceptId::kGetModuleHandleA:
        add_str_arg(0, false);
        break;
    case InterceptId::kLoadLibraryW:
    case InterceptId::kGetModuleHandleW:
        add_str_arg(0, true);
        break;
    case InterceptId::kGetProcAddress:
        add_str_arg(1, false);
        break;
    default:
        add_scalar_args();
        break;
    }
    // Shallow-stack snapshot: the caller's
    // frame above its return address, same three-slot shape as syscalls.
    // The stack is still intact here - intercept_return pops after this.
    for (const std::uint64_t stack_slot :
         {std::uint64_t{8}, std::uint64_t{0x10}, std::uint64_t{0x18}}) {
        std::uint64_t value = 0;
        static_cast<void>(
            uc_mem_read(state.uc, read_rsp(state.uc) + stack_slot, &value, sizeof value));
        std::array<std::uint8_t, 8> bytes{};
        le::store_le64(bytes.data(), value);
        static_cast<void>(append_param_record(fields, cursor, ParamKind::kStackSlot, bytes));
    }
    const EventPreamble preamble{
        .seq = 0, .tid = state.current_tid, .pc = state.intercept_vas[slot]};
    state.event_sink(EventTypeId::kApiCall, preamble,
                     std::span<const std::uint8_t>{fields.data(), cursor});

    // When the intercepted export has an Nt equivalent
    // that resolves to a real syscall number, re-emit the operation as a
    // zero-record synthetic kSyscall - the loader route's Nt timeline then
    // matches what the snapshot route would observe. No parameters and no
    // shallow stack: nothing was observed at the Nt layer, so nothing is
    // fabricated. No success bit either - Win32 and NT success encodings
    // disagree; the status value speaks for itself.
    if (const auto nt_name = syscalls::win32_nt_equivalent(state.intercept_names[slot]);
        nt_name.has_value()) {
        const auto number = state.syscall_numbers_by_name.find(std::string{*nt_name});
        if (number != state.syscall_numbers_by_name.end()) {
            std::array<std::uint8_t, kSyscallFixedBytes> synth{};
            const SyscallFields synth_head{.number = number->second,
                                           .flags = kEventFlagSynthetic,
                                           .status = static_cast<std::uint32_t>(retval),
                                           .caller_retaddr = caller};
            if (encode_syscall_head(synth, synth_head).has_value()) {
                state.event_sink(EventTypeId::kSyscall, preamble,
                                 std::span<const std::uint8_t>{synth.data(), kSyscallFixedBytes});
            }
        }
    }
}

// An intercepted call has already computed its results; pop the return
// address and hand the leg back to the run loop. arg_bytes is the stdcall
// callee-clean count (x86 only; x64 callers leave the default 0).
void intercept_return(SyscallRunState& state, const std::uint64_t rax,
                      const std::uint64_t arg_bytes)
{
    // The event carries the handler's retval and the still-intact argument
    // frame; emit before the pop.
    emit_intercept_event(state, rax);
    std::uint64_t rsp = read_rsp(state.uc);
    std::uint64_t ret = 0;
    if (state.guest_mode == GuestMode::kX86) {
        ret = read_guest_u32(state.uc, rsp);
        rsp += 4 + arg_bytes;
        const auto eax = static_cast<std::uint32_t>(rax);
        uc_reg_write(state.uc, UC_X86_REG_EAX, &eax);
    } else {
        uc_mem_read(state.uc, rsp, &ret, sizeof ret);
        rsp += 8;
        uc_reg_write(state.uc, UC_X86_REG_RAX, &rax);
    }
    write_rsp(state.uc, rsp);
    write_rip(state.uc, ret);
    state.api_resume = true;
    uc_emu_stop(state.uc);
}

// Deterministic-stub call counting. The hook is
// range-scoped to each loader module; only an exact export-entry pc counts,
// so a stub call is exactly one hit regardless of stub body length. O(1)
// slot bump - no allocation on the hook path.
void on_stub_code([[maybe_unused]] uc_engine* uc, const std::uint64_t address, const std::uint32_t,
                  void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);
    if (const auto it = state->stub_slots.find(address); it != state->stub_slots.end()) {
        ++state->stub_entries[it->second].count;
    }
}

// The C++ accept unwind: the accepting __CxxFrameHandler4 drove the REAL
// ntdll!RtlUnwindEx as guest code. The unwind machinery is stack-address
// sensitive (its local-frame walk spans the dispatch stack) and cannot run
// against the staged callback's engine stack, so the engine retires the
// dispatch handshake and re-delivers the same fault through the real guest
// dispatcher: KiUserExceptionDispatcher re-walks the frames, the handler
// re-runs its search, RtlUnwindEx drives the unwind callbacks, the
// accepting frame is re-called with the target-unwind record and the catch
// protocol completes (catch funclet, continuation transfer) - all as guest
// code, exactly the fidelity-mode chain.
void on_rtl_unwind_ex(uc_engine* const uc, [[maybe_unused]] const std::uint64_t address,
                      [[maybe_unused]] const std::uint32_t size, void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);
    if (state->fidelity_dispatch) {
        if (diag::seh_on()) {
            std::uint64_t target_frame = 0;
            std::uint64_t target_ip = 0;
            uc_reg_read(uc, UC_X86_REG_RCX, &target_frame);
            uc_reg_read(uc, UC_X86_REG_RDX, &target_ip);
            diag::emit(sheller::log::level::kDebug, diag::file_on(),
                       "[seh-cb] fidelity unwind-ex tf={:x} ti={:x}", target_frame, target_ip);
        }
        return; // fidelity dispatch: execute the real function
    }
    if (!state->seh.active || !state->seh.awaiting_callback || state->seh.layers.empty()) {
        return; // not a dispatch callback: execute the real function
    }
    seh::retire_dispatch(state->seh);
    seh::restore_snapshot(uc, state->seh, false);
    auto& facts = state->exception;
    facts.valid = true;
    facts.unhandled = false;
    facts.code = state->seh.code;
    facts.pc = state->seh.pc;
    for (std::size_t i = 0; i < state->seh.information_count && i < std::size(facts.information);
         ++i) {
        facts.information[i] = state->seh.information[i];
    }
    facts.information_count = state->seh.information_count;
    facts.replay_in_guest = true;
    uc_emu_stop(uc);
}

// dispatch by the intercepted entry address (linear over <= 16 entries)
void on_intercept([[maybe_unused]] uc_engine* uc, const std::uint64_t address, const std::uint32_t,
                  void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);
    for (std::size_t i = 0; i < state->intercept_vas.size(); ++i) {
        if (state->intercept_vas[i] == address) {
            // identity for the event emitted in intercept_return
            state->pending_intercept = static_cast<std::int32_t>(i);
            const auto id = static_cast<InterceptId>(state->intercept_ids[i]);
            switch (id) {
            case InterceptId::kVirtualAlloc:
                intercept_virtual_alloc(*state);
                break;
            case InterceptId::kVirtualProtect:
                intercept_virtual_protect(*state);
                break;
            case InterceptId::kVirtualFree:
                intercept_virtual_free(*state);
                break;
            case InterceptId::kLoadLibraryA:
            case InterceptId::kLoadLibraryW:
                intercept_load_library(*state, id == InterceptId::kLoadLibraryW);
                break;
            case InterceptId::kDllLoadResume:
                dll_load_resume(*state);
                break;
            case InterceptId::kDisableThreadLibraryCalls:
                intercept_disable_thread_library_calls(*state);
                break;
            case InterceptId::kGetStdHandle:
                intercept_get_std_handle(*state);
                break;
            case InterceptId::kInitializeCriticalSection:
            case InterceptId::kInitializeCriticalSectionAndSpinCount:
            case InterceptId::kEnterCriticalSection:
            case InterceptId::kLeaveCriticalSection:
            case InterceptId::kDeleteCriticalSection:
                intercept_critical_section(*state, id);
                break;
            case InterceptId::kFlsAlloc:
            case InterceptId::kFlsFree:
            case InterceptId::kFlsSetValue:
            case InterceptId::kFlsGetValue:
            case InterceptId::kTlsAlloc:
            case InterceptId::kTlsFree:
            case InterceptId::kTlsSetValue:
            case InterceptId::kTlsGetValue:
            case InterceptId::kAddVectoredExceptionHandler:
            case InterceptId::kRemoveVectoredExceptionHandler:
                intercept_fls_tls(*state, id);
                break;
            case InterceptId::kGetProcAddress:
                intercept_get_proc_address(*state);
                break;
            case InterceptId::kGetModuleHandleA:
            case InterceptId::kGetModuleHandleW:
                intercept_get_module_handle(*state, id == InterceptId::kGetModuleHandleW);
                break;
            case InterceptId::kExitProcess:
                intercept_exit_process(*state);
                break;
            case InterceptId::kRtlAllocateHeap:
                intercept_rtl_allocate_heap(*state);
                break;
            case InterceptId::kRtlFreeHeap:
                intercept_rtl_free_heap(*state);
                break;
            case InterceptId::kRtlReAllocateHeap:
                intercept_rtl_re_allocate_heap(*state);
                break;
            case InterceptId::kRtlCreateHeap:
                intercept_rtl_create_heap(*state);
                break;
            case InterceptId::kRtlDestroyHeap:
                intercept_rtl_destroy_heap(*state);
                break;
            case InterceptId::kRtlSizeHeap:
                intercept_rtl_size_heap(*state);
                break;
            case InterceptId::kLdrLoadDll:
                intercept_ldr_load_dll(*state);
                break;
            case InterceptId::kRegOpenKeyEx:
                intercept_reg_open(*state, state->intercept_names[i].back() == 'W');
                break;
            case InterceptId::kRegQueryValueEx:
                intercept_reg_query(*state);
                break;
            case InterceptId::kRegCloseKey:
                intercept_reg_close(*state);
                break;
            case InterceptId::kStrlen:
                intercept_strlen(*state);
                break;
            }
            break;
        }
    }
}

} // namespace sheller::engine
