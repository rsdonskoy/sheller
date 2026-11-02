#include "run.h"

#include "avx_shim.h"
#include "diag_trace.h"
#include "dll_loader.h"
#include "dump_writer.h"
#include "engine_hooks.h"
#include "esp_target.h"
#include "exception_pipeline.h"
#include "intercept.h"
#include "syscall_dispatch.h"

#include "../syscalls/syscall_number_map.h"
#include "../syscalls/syscall_policy.h"

#include <sheller/log.h>
#include <unicorn/unicorn.h>

#include <algorithm>
#include <chrono>
#include <format>

namespace sheller::engine {
namespace {

struct BlockCounters {
    std::uint64_t blocks{};
    std::uint64_t entry_hits{};
    std::uint64_t entry_address{};
};

// Plain function pointer: the unicorn API takes callbacks as void* and the
// conversion from a lambda is not portable across compilers.
void on_block_callback(uc_engine*, const std::uint64_t address, const std::uint32_t,
                       void* const user_data)
{
    auto* block_counters = static_cast<BlockCounters*>(user_data);
    ++block_counters->blocks;
    if (address == block_counters->entry_address) {
        ++block_counters->entry_hits;
    }
}

} // namespace

// Entry proof: spin on the patched entry for a fixed instruction count.
std::expected<BoundedRun, RebuildFailure> run_entry_proof(PreparedGuest& guest)
{
    BlockCounters counters{
        .blocks = 0, .entry_hits = 0, .entry_address = guest.metadata.entry_address};
    uc_hook block_hook = 0;
    if (uc_hook_add(guest.unicorn.get(), &block_hook, UC_HOOK_BLOCK,
                    reinterpret_cast<void*>(on_block_callback), &counters, 1, 0) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }

    const auto entry = guest.metadata.entry_address;
    const uc_err run_error =
        uc_emu_start(guest.unicorn.get(), entry, 0, 0, kEntryProofInstructionCount);

    std::uint64_t final_rip = 0;
    if (uc_reg_read(guest.unicorn.get(), UC_X86_REG_RIP, &final_rip) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    const RebuildStats stats{.reached_entry = false,
                             .blocks = counters.blocks,
                             .entry_hits = counters.entry_hits,
                             .final_rip = final_rip};

    if (run_error != UC_ERR_OK) {
        return std::unexpected(RebuildFailure{RebuildError::kEmulationFailure,
                                              static_cast<std::uint32_t>(run_error), stats});
    }
    if (counters.entry_hits == 0 || final_rip != entry) {
        return std::unexpected(RebuildFailure{RebuildError::kEntryNotReached, 0, stats});
    }
    return BoundedRun{std::move(guest.unicorn), RebuildStats{.reached_entry = true,
                                                             .blocks = counters.blocks,
                                                             .entry_hits = counters.entry_hits,
                                                             .final_rip = final_rip}};
}

// Assembles the syscall-run state: restores the real entry bytes, wires the
// sinks and the run-scoped tables (intercepts, stubs, resolved Nt names),
// and reserves the engine-dispatch trampoline plus the deterministic
// allocator cursors.
std::expected<void, SyscallRunFailure> assemble_run_state(PreparedGuest& guest,
                                                          const SyscallRunOptions& options,
                                                          const FactChannel& facts,
                                                          SyscallRunState& state)
{
    // The syscall run executes the sample's real code, so the entry spin the
    // capture path wrote must go: restore the original bytes from the
    // snapshot metadata before the guest starts.
    if (uc_mem_write(guest.unicorn.get(), guest.metadata.entry_address,
                     guest.metadata.original_entry_bytes.data(),
                     guest.metadata.original_entry_bytes.size()) != UC_ERR_OK) {
        return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
    }

    state.policy = syscalls::PolicyTable{};
    // Guest output is the host's decision, not the engine's: an empty sink
    // means the bytes are dropped, and sink_trampoline's existing null check is
    // what makes that cost nothing at the call site - the same shape as every
    // other optional callback in SyscallRunOptions.
    state.sink = options.write_sink;
    state.event_sink = options.event_sink;
    state.behavior_sink = facts.behavior_sink;
    state.module_sink = facts.module_sink;
    state.region_map = &guest.map;
    state.relative_base = guest.relative_base;
    // The captured process's own current directory is the faithful base for
    // relative guest paths: PEB->ProcessParameters->CurrentDirectory (a
    // CURDIR {UNICODE_STRING, HANDLE}). The snapshot route photographs it,
    // so replay resolves exactly where the real process would have.
    {
        // RTL_USER_PROCESS_PARAMETERS->CurrentDirectory (Win11 24H2 x64:
        // the CURDIR sits at +0x38; its DosPath UNICODE_STRING buffer
        // pointer at +0x48). Verified against the captured packed sample.
        const auto peb = guest.metadata.peb_address;
        if (peb != 0) {
            std::uint64_t params = 0;
            std::uint64_t buffer = 0;
            std::uint16_t len = 0;
            if (uc_mem_read(guest.unicorn.get(), peb + 0x20, &params, sizeof params) == UC_ERR_OK &&
                params != 0 &&
                uc_mem_read(guest.unicorn.get(), params + 0x40, &len, sizeof len) == UC_ERR_OK &&
                uc_mem_read(guest.unicorn.get(), params + 0x48, &buffer, sizeof buffer) ==
                    UC_ERR_OK &&
                len >= 2 && len % 2 == 0) {
                // u16 (not wstring): std::u16string is a standard fs::path
                // source on every host; a wstring source compiles only on
                // Windows and aborts the Linux build.
                std::u16string wide(len / 2, u'\0');
                if (uc_mem_read(guest.unicorn.get(), buffer, wide.data(),
                                wide.size() * sizeof(char16_t)) == UC_ERR_OK) {
                    constexpr char16_t kSep = u'\\';
                    if (!wide.empty() && wide.back() != kSep) {
                        wide.push_back(kSep);
                    }
                    std::error_code ec;
                    const std::filesystem::path cwd{wide};
                    if (cwd.is_absolute() && std::filesystem::is_directory(cwd, ec)) {
                        state.relative_base = cwd;
                    }
                }
            }
        }
    }
    state.max_blocks = options.max_blocks;
    state.xfer_number = options.xfer_number;
    state.esp_stop_goal = options.esp_stop_goal;
    state.uc = guest.unicorn.get();
    state.guest_mode = guest.guest_mode;
    state.teb_base = guest.metadata.teb_address;
    state.loader_modules = guest.loader_modules;
    state.ldr_entry_vas = guest.ldr_entry_vas;
    state.loader_route = guest.loader_route;
    state.loader_exports = guest.loader_exports;
    state.diag_watch_entries = options.diag_watch_entries;
    state.diag_entry_hit = options.diag_entry_hit;
    state.diag_write_hit = options.diag_write_hit;
    state.diag_code_hit = options.diag_code_hit;
    // SHELLER_LOOP_GATE_TRACE: per-window loop-gate verdict detail plus the run-end
    // verdict distribution, both as kDebug records. Default off - nothing is rendered
    // and the event stream stays byte-identical; the verdict counters accumulate
    // either way (see SyscallRunState::loop_gate_counts). It is copied into the state
    // because the hook path reads it per probe window.
    state.loop_gate_trace = diag::loop_gate_on();
    state.intercept_vas.clear();
    state.intercept_ids.clear();
    for (const auto& [va, id] : guest.intercepts) {
        state.intercept_vas.push_back(va);
        state.intercept_ids.push_back(id);
    }

    // DLL-input route: the pending module travels into the run state and
    // the continuation-slot intercept arms (no-op without a pending block -
    // EXE/shellcode runs pay nothing).
    if (guest.pending.has_value()) {
        state.pending_module = &*guest.pending;
        state.loaded_modules = &guest.loaded_modules;
        arm_dll_resume_slot(state, guest.unicorn.get());
    }

    // Heap-family interception: the loader route points
    // PEB.ProcessHeap at the engine's deterministic heap region, which is
    // not a real _HEAP - real ntdll heap-manager code running against it
    // reads garbage internal pointers and dies (the packed corpus crashed
    // in RtlDestroyHeap with environment-string bytes as the handle).
    // Register the family at the mapped ntdll's export entries so every
    // caller - IAT or direct/hash-resolved - lands in the engine heap; the
    // handle value stays opaque to both sides.
    for (const auto& entry : state.loader_exports) {
        for (const auto& [name, id] : kHeapInterceptNames) {
            if (fold_name(entry.name) != fold_name(name)) {
                continue;
            }
            const auto registered = std::find(state.intercept_vas.begin(),
                                              state.intercept_vas.end(), entry.function_va);
            if (registered == state.intercept_vas.end()) {
                state.intercept_vas.push_back(entry.function_va);
                state.intercept_ids.push_back(static_cast<std::uint32_t>(id));
            }
        }
        for (const auto& [name, id] : kLdrInterceptNames) {
            if (fold_name(entry.name) != fold_name(name)) {
                continue;
            }
            const auto registered = std::find(state.intercept_vas.begin(),
                                              state.intercept_vas.end(), entry.function_va);
            if (registered == state.intercept_vas.end()) {
                state.intercept_vas.push_back(entry.function_va);
                state.intercept_ids.push_back(static_cast<std::uint32_t>(id));
            }
        }
    }
    state.fidelity_dispatch = options.windows_fidelity_dispatch;
    // Resolve each intercept's export name and
    // owning region-map module index for event emission. Every loader-route
    // export that is NOT intercepted is a deterministic stub - those join
    // the counting table (hook bumps a slot counter; the run end drains
    // once into options.stub_sink, off the hot path).
    state.stub_sink = options.stub_sink;
    // Resolve number -> Nt name once (real ntdll stubs
    // only; synthetic 0x1000+ numbers never collide). One allocation, off
    // the hook hot path.
    for (const auto& mod : state.loader_modules) {
        if (fold_name(std::string_view(mod.name.data())) != "ntdll") {
            continue;
        }
        for (const auto& entry :
             syscalls::enumerate_ntdll_syscalls(guest.unicorn.get(), mod.base)) {
            state.syscall_numbers_by_name.emplace(std::string(entry.name.data()), entry.number);
        }
        state.syscall_names.clear();
        for (const auto& [name, number] : state.syscall_numbers_by_name) {
            state.syscall_names.emplace(number, name);
        }
        break;
    }
    state.intercept_names.clear();
    state.intercept_modules.clear();
    state.stub_slots.clear();
    state.stub_entries.clear();
    const auto module_index_for_va = [&state](const std::uint64_t va) -> std::uint16_t {
        for (const auto& mod : state.loader_modules) {
            if (va >= mod.base && va < mod.base + mod.size) {
                if (state.region_map != nullptr) {
                    if (const auto idx = state.region_map->module_index_by_name(
                            fold_name(std::string_view(mod.name.data())));
                        idx.has_value()) {
                        return static_cast<std::uint16_t>(*idx);
                    }
                }
                break;
            }
        }
        return 0xFFFF; // kRuntimeIndex: no region-map owner resolved
    };
    for (std::size_t i = 0; i < state.intercept_vas.size(); ++i) {
        const auto va = state.intercept_vas[i];
        std::string name;
        for (const auto& entry : state.loader_exports) {
            if (entry.function_va == va) {
                name = entry.name;
                break;
            }
        }
        state.intercept_names.push_back(std::move(name));
        state.intercept_modules.push_back(module_index_for_va(va));
    }
    if (guest.directory_mode) {
        // directory mode counts ONLY the explicit whitelist (derived compat
        // stubs plus fallback synthetic exports) - the "every non-intercepted
        // export is a stub" inference is a synthetic-mode rule and would
        // miscount real bodies, data slots, syscall stubs and traps. Alias
        // names sharing one VA land in one slot: the first whitelist row is
        // the stable canonical name.
        for (const auto& entry : guest.stub_whitelist) {
            if (std::find(state.intercept_vas.begin(), state.intercept_vas.end(),
                          entry.function_va) != state.intercept_vas.end()) {
                continue;
            }
            if (state.stub_slots.find(entry.function_va) != state.stub_slots.end()) {
                continue; // shared VA alias: one slot, one count
            }
            const auto slot = static_cast<std::uint32_t>(state.stub_entries.size());
            state.stub_entries.push_back({module_index_for_va(entry.function_va), entry.name, 0});
            state.stub_slots.emplace(entry.function_va, slot);
        }
        state.boundary_trap_vas = guest.boundary_trap_vas;
        state.boundary_trap_names = guest.boundary_trap_names;
        state.directory_mode = true;
        state.api_set_ctx.mode = loader::ApiSetContext::Mode::kDirectoryMap;
        state.api_set_ctx.directory_map = &guest.api_set_map;
        for (const auto va : guest.boundary_trap_vas) {
            // an intercept registration on the same VA supersedes the trap:
            // the engine answers the call in the hook and the ud2 body is
            // never reached (the manifest row stays trap-classified; the
            // interception layer is the engine support landing on it)
            const auto intercepted =
                std::find(state.intercept_vas.begin(), state.intercept_vas.end(), va) !=
                state.intercept_vas.end();
            if (intercepted) {
                continue;
            }
            uc_hook trap_hook = 0;
            if (uc_hook_add(guest.unicorn.get(), &trap_hook, UC_HOOK_CODE,
                            reinterpret_cast<void*>(on_boundary_trap), &state, va,
                            va) != UC_ERR_OK) {
                return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
            }
        }
    } else {
        for (const auto& entry : state.loader_exports) {
            const auto intercepted = std::find(state.intercept_vas.begin(),
                                               state.intercept_vas.end(), entry.function_va);
            if (intercepted != state.intercept_vas.end()) {
                continue; // intercepted exports emit apicall events, not counts
            }
            const auto slot = static_cast<std::uint32_t>(state.stub_entries.size());
            state.stub_entries.push_back({module_index_for_va(entry.function_va), entry.name, 0});
            state.stub_slots.emplace(entry.function_va, slot);
        }
    }
    if (static_cast<bool>(state.stub_sink) && !state.stub_entries.empty()) {
        for (const auto& mod : state.loader_modules) {
            uc_hook stub_hook = 0;
            if (uc_hook_add(guest.unicorn.get(), &stub_hook, UC_HOOK_CODE,
                            reinterpret_cast<void*>(on_stub_code), &state, mod.base,
                            mod.base + mod.size) != UC_ERR_OK) {
                return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
            }
        }
    }
    // loader-route deterministic allocator cursors (zeroed for other routes)
    const auto& run_layout = layout_for(guest.guest_mode);
    // Engine dispatch: the trampoline page (int3 marker the callback
    // return address points at), per-layer scratch for the guest
    // EXCEPTION_RECORD/CONTEXT/DISPATCHER_CONTEXT structs, and per-layer
    // callback stacks. Reserved from the front of the deterministic alloc
    // bump range; both dispatch modes map it (only the engine mode consumes
    // it). The callback stacks deliberately do NOT ride the guest stack: a
    // captured snapshot's committed stack may not extend below the faulting
    // rsp, and a silent staging write to unmapped memory would zero the
    // handler's return address.
    const auto seh_trampoline = run_layout.alloc_base;
    if (uc_mem_map(guest.unicorn.get(), seh_trampoline, 0x21000, UC_PROT_ALL) != UC_ERR_OK) {
        return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
    }
    const std::uint8_t trampoline_marker = 0xCC; // int3: the INTR hook keys on the rip
    uc_mem_write(guest.unicorn.get(), seh_trampoline, &trampoline_marker, 1);
    state.seh.trampoline = seh_trampoline;
    state.seh.scratch = seh_trampoline + 0x1000;
    state.valloc_cursor = run_layout.alloc_base + 0x21000;
    state.heap_cursor = run_layout.heap_base;
    return {};
}

// Seeds the policy table with the built-in semantics (real numbers resolved
// from the guest ntdll), applies the caller's rejection overrides and runs
// the environment self-consistency passes. Returns the resolved ntdll base.
std::uint64_t seed_policy_and_normalize(PreparedGuest& guest, const SyscallRunOptions& options,
                                        SyscallRunState& state)
{
    // ucrt AppPolicy termination-mode pre-seed: RETIRED (2026-10-02). This block used to pre-seed
    // ucrtbase's AppPolicy cache with a synthesized desktop stub because the delay-load of
    // kernel.appcore.dll could not complete against a replayed loader. The native-aligned answer
    // surface (KnownDlls honest absence, the file-backed SEC_IMAGE section
    // path, the token/thread-query/perf-counter truths, and the QAF answer
    // that preserves the loader frame's GS cookie slot) lets the real
    // delay-load complete - the exit path resolves the REAL
    // AppPolicyGetProcessTerminationMethod from the mapped module and the
    // packed corpus's no-arg replay matches native byte-for-byte without the
    // seed. The SHELLER_NO_APPPOLICY_PRESEED diagnostic switch is gone with
    // it: there is no seed left to bypass.

    // Real-number registration: the build-specific
    // numbers of the seed functions come from the guest ntdll itself, so
    // the same builtin semantics answer real samples. Unknown names stay
    // default deny - full emulation, never pass-through.
    std::uint64_t ntdll_base = 0;
    if (const auto ntdll_index = guest.map.module_index_by_name("ntdll.dll")) {
        ntdll_base = guest.map.module(*ntdll_index).base;
    }
    if (ntdll_base != 0) {
        // The unpacking stubs' memory-management calls join as minimal
        // semantics: allocation maps deterministic
        // guest memory, the section family accepts so UPX-class stubs run
        // their course. The query/set family answers the policy and
        // mitigation checks ntdll's own dispatcher performs before it can
        // walk frames - a rejection there derails the real dispatch into
        // garbage (a known unwind crash). Unknown names stay default deny.
        // The six contract APIs are deliberately absent: their semantics come
        // from kSyntheticSyscalls below, matched by name, so an API cannot
        // answer with one builtin on the synthetic side and another here.
        static constexpr std::array<std::pair<std::string_view, syscalls::BuiltinHandler>, 20>
            kSeedBuiltins{
                std::pair<std::string_view, syscalls::BuiltinHandler>{
                    "NtAllocateVirtualMemory", syscalls::BuiltinHandler::kAllocateMemory},
                {"NtCreateSection", syscalls::BuiltinHandler::kCreateSection},
                {"NtOpenSection", syscalls::BuiltinHandler::kOpenSection},
                {"NtMapViewOfSection", syscalls::BuiltinHandler::kMapViewOfSection},
                {"NtQueryInformationProcess", syscalls::BuiltinHandler::kQueryZero},
                // The real Ldr's post-map policy
                // check reads the WNF-published loader policy state and
                // fails the load (FAST_FAIL path) when the query is denied
                // (packed corpus, 2026-09-30). Zeroed state = policy not
                // enforced - the deterministic desktop answer.
                {"NtQueryWnfStateData", syscalls::BuiltinHandler::kQueryZero},
                {"NtQueryWnfStateNameInformation", syscalls::BuiltinHandler::kQueryZero},
                // the post-map policy flow emits a trace event and maps a
                // denial of the emit into a fatal load failure
                {"NtTraceEvent", syscalls::BuiltinHandler::kAccept},
                {"NtQuerySystemInformation", syscalls::BuiltinHandler::kQueryZero},
                {"NtOpenEvent", syscalls::BuiltinHandler::kOpenEvent},
                {"NtSetInformationProcess", syscalls::BuiltinHandler::kAccept},
                {"NtQueryInformationJobObject", syscalls::BuiltinHandler::kQueryZero},
                {"NtQueryDebugFilterState", syscalls::BuiltinHandler::kAccept},
                {"NtSetSystemInformation", syscalls::BuiltinHandler::kAccept},
                {"NtProtectVirtualMemory", syscalls::BuiltinHandler::kProtectVirtualMemory},
                {"NtWaitForMultipleObjects", syscalls::BuiltinHandler::kWaitMultiple},
                {"NtRaiseException", syscalls::BuiltinHandler::kRaiseException},
                {"NtQueryVirtualMemory", syscalls::BuiltinHandler::kQueryVirtualMemory},
                // The loader's AppPolicy preamble queries the
                // calling thread (class 0x2a) between the token check and
                // the DLL open; the desktop answers it, a denial there is
                // an error branch native never walks
                {"NtQueryInformationThread", syscalls::BuiltinHandler::kQueryZero},
                // The loader's mapped-module path issues a QPC
                // after the file-backed map; the desktop answers it, a
                // rejection there ends the load
                {"NtQueryPerformanceCounter", syscalls::BuiltinHandler::kQueryPerformanceCounter}};
        for (const auto& resolved :
             syscalls::enumerate_ntdll_syscalls(guest.unicorn.get(), ntdll_base)) {
            for (const auto& seed : kSeedBuiltins) {
                if (std::string_view(resolved.name.data()) == seed.first) {
                    state.policy.set_builtin(resolved.number, seed.second);
                }
            }
            // The contract rows keep the builtin next to the name, so the real
            // number of the same API lands on the same semantics instead of a
            // second hand-written pair that can disagree with the first.
            for (const auto& synthetic : syscalls::kSyntheticSyscalls) {
                if (std::string_view(resolved.name.data()) == synthetic.name) {
                    state.policy.set_builtin(resolved.number, synthetic.builtin);
                }
            }
            // Heap-fidelity: the engine has no
            // filesystem, so the loader's DLL-load probes must fail with the
            // status real Windows uses for a missing object. The plain
            // ACCESS_DENIED default deny sends LdrpLoadDllInternal down an
            // unusual failure path whose cleanup dies on the packed corpus.
            // Real file semantics for the sample's
            // own opens - the payload's fopen must succeed with real bytes
            // for the work path to run. A missing host file answers
            // OBJECT_NAME_NOT_FOUND (the loader's DLL probes keep the real
            // failure path), NtReadFile serves the captured host bytes.
            if (std::string_view(resolved.name.data()) == "NtCreateFile" ||
                std::string_view(resolved.name.data()) == "NtOpenFile") {
                state.policy.set_builtin(resolved.number, syscalls::BuiltinHandler::kCreateFile);
            }
            if (std::string_view(resolved.name.data()) == "NtReadFile") {
                state.policy.set_builtin(resolved.number, syscalls::BuiltinHandler::kReadFile);
            }
            if (std::string_view(resolved.name.data()) == "NtQueryInformationFile") {
                state.policy.set_builtin(resolved.number,
                                         syscalls::BuiltinHandler::kQueryInformationFile);
            }
            if (std::string_view(resolved.name.data()) == "NtQueryAttributesFile") {
                state.policy.set_builtin(resolved.number,
                                         syscalls::BuiltinHandler::kQueryAttributesFile);
            }
            if (std::string_view(resolved.name.data()) == "NtClose") {
                state.policy.set_builtin(resolved.number, syscalls::BuiltinHandler::kClose);
            }
            // The loader's AppPolicy preamble opens the calling thread's
            // impersonation token before the DLL open; the native desktop
            // answer for a plain main thread is STATUS_NO_TOKEN. The old
            // default deny (ACCESS_DENIED) sent the replayed loader down an
            // error branch native never walks. A rejection with the honest
            // status keeps the probe shape (no side effects) - any caller
            // still fails, it just fails the way the desktop fails.
            if (std::string_view(resolved.name.data()) == "NtOpenThreadToken") {
                state.policy.set_entry(
                    resolved.number,
                    syscalls::PolicyEntry{.kind = syscalls::EntryKind::kReject,
                                          .reject_status = syscalls::kStatusNoToken,
                                          .builtin = syscalls::BuiltinHandler::kNone});
            }
            // the x86 fidelity dispatch resumes through NtContinue; the
            // engine-side dispatcher applies the context itself, so this
            // seed stays fidelity-only and x86-shaped
            if (state.fidelity_dispatch && state.guest_mode == GuestMode::kX86 &&
                std::string_view(resolved.name.data()) == "NtContinue") {
                state.policy.set_builtin(resolved.number, syscalls::BuiltinHandler::kContinue);
            }
        }
    }

    for (const auto& [number, status] : options.reject_overrides) {
        state.policy.set_entry(number, syscalls::PolicyEntry{.kind = syscalls::EntryKind::kReject,
                                                             .reject_status = status});
    }

    // Environment self-consistency: keep the modules'
    // baked CPU-feature caches agreeing with the masked CPUID.
    normalize_isa_feature_gates(guest.unicorn.get(), guest.map);

    // Same self-consistency class for the loader's
    // baked CFG dispatch behavior - the replayed ntdll runs the Win11
    // shadow-stack-compatible registration whose backing the replay lacks;
    // the gate flip presents the process as SCP-dispatch-off (the Windows 10
    // shape, and what the engine's own mitigation answers already claim).
    normalize_scp_cfg_gate(
        guest.unicorn.get(), ntdll_base,
        ntdll_base != 0 ? guest.map.module(*guest.map.module_index_by_name("ntdll.dll")).size : 0);
    return ntdll_base;
}

// Runs the TLS callback legs ahead of the entry, in array order. Each leg
// starts at the callback with a return address pointing at the entry; the
// leg stops the moment execution reaches it, so the callback's ret is the
// hand-off back to the scheduler.
std::expected<void, SyscallRunFailure> run_tls_callback_legs(PreparedGuest& guest)
{
    // TLS callbacks: run before the entry, in
    // array order. Each leg starts at the callback with a return address
    // pointing at the entry; the leg stops the moment execution reaches it,
    // so the callback's ret is the hand-off back to the scheduler.
    uc_err tls_error = UC_ERR_OK;
    for (const auto callback : guest.tls_callbacks) {
        constexpr std::uint64_t kTlsLegBudget = 1000000;
        const auto& layout = layout_for(guest.guest_mode);
        const std::uint64_t magic = guest.metadata.entry_address;
        std::uint64_t rsp = layout.stack_base + layout.stack_size - 0x1000;
        if (guest.guest_mode == GuestMode::kX86) {
            // stdcall callback(base, reason, reserved): args pushed on
            // the stack under the return slot, callee cleans them.
            rsp = (rsp - 4) & ~0x3ULL;
            rsp -= 4;
            uc_mem_write(guest.unicorn.get(), rsp, &magic, sizeof magic);
            const auto image_base32 = static_cast<std::uint32_t>(guest.metadata.image_base);
            rsp -= 4;
            uc_mem_write(guest.unicorn.get(), rsp, &image_base32, sizeof image_base32);
            const std::uint32_t reason = 1; // DLL_PROCESS_ATTACH
            rsp -= 4;
            uc_mem_write(guest.unicorn.get(), rsp, &reason, sizeof reason);
            const std::uint32_t reserved = 0;
            rsp -= 4;
            uc_mem_write(guest.unicorn.get(), rsp, &reserved, sizeof reserved);
            write_rsp(guest.unicorn.get(), rsp);
        } else {
            rsp = (rsp - 8) & ~0xFULL; // keep 16-byte alignment for the return slot
            rsp -= 8;
            uc_mem_write(guest.unicorn.get(), rsp, &magic, sizeof magic);
            write_rsp(guest.unicorn.get(), rsp);
            uc_reg_write(guest.unicorn.get(), UC_X86_REG_RCX, &guest.metadata.image_base);
            std::uint64_t reason = 1; // DLL_PROCESS_ATTACH
            uc_reg_write(guest.unicorn.get(), UC_X86_REG_RDX, &reason);
            std::uint64_t reserved = 0;
            uc_reg_write(guest.unicorn.get(), UC_X86_REG_R8, &reserved);
        }
        tls_error = uc_emu_start(guest.unicorn.get(), callback, magic, 0, kTlsLegBudget);
        if (tls_error != UC_ERR_OK) {
            return std::unexpected(SyscallRunFailure{SyscallRunError::kEmulationFailure,
                                                     static_cast<std::uint32_t>(tls_error)});
        }
    }
    return {};
}

// Registers the run-scoped unicorn hooks: the diagnostic windows, the
// syscall/cpuid/rdtsc instruction hooks, the behavior monitored windows,
// the block/intr/invalid-memory hooks, the per-intercept entry hooks and
// the C++ accept takeover on ntdll!RtlUnwindEx. The write-prot hook stays
// with the caller (it needs the caller-owned ledger).
std::expected<void, SyscallRunFailure> register_run_hooks(PreparedGuest& guest,
                                                          const SyscallRunOptions& options,
                                                          SyscallRunState& state,
                                                          std::uint64_t sample_image_size)
{
    // Diagnostic per-instruction code window: same gating shape as the
    // per-write window - a range-scoped hook costs nothing outside it.
    uc_hook diag_code_hook = 0;
    if (options.diag_code_hit && options.diag_code_window_lo != 0 &&
        options.diag_code_window_hi > options.diag_code_window_lo) {
        if (uc_hook_add(guest.unicorn.get(), &diag_code_hook, UC_HOOK_CODE,
                        reinterpret_cast<void*>(on_diag_code_window), &state,
                        options.diag_code_window_lo, options.diag_code_window_hi) != UC_ERR_OK) {
            return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
        }
    }

    // Diagnostic per-write window: registered
    // only when the harness gates it with a window and a callback - a
    // range-scoped hook costs nothing outside the window.
    uc_hook diag_write_hook = 0;
    if (options.diag_write_hit && options.diag_write_window_lo != 0 &&
        options.diag_write_window_hi > options.diag_write_window_lo) {
        if (uc_hook_add(guest.unicorn.get(), &diag_write_hook, UC_HOOK_MEM_WRITE,
                        reinterpret_cast<void*>(on_diag_write_window), &state,
                        options.diag_write_window_lo, options.diag_write_window_hi) != UC_ERR_OK) {
            return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
        }
    }

    uc_hook syscall_hook = 0;
    if (uc_hook_add(guest.unicorn.get(), &syscall_hook, UC_HOOK_INSN,
                    reinterpret_cast<void*>(on_syscall_callback), &state, 1, 0,
                    UC_X86_INS_SYSCALL) != UC_ERR_OK) {
        return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
    }

    uc_hook cpuid_hook = 0;
    if (uc_hook_add(guest.unicorn.get(), &cpuid_hook, UC_HOOK_INSN,
                    reinterpret_cast<void*>(on_cpuid_callback), &state, 1, 0,
                    UC_X86_INS_CPUID) != UC_ERR_OK) {
        return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
    }

    uc_hook rdtsc_hook = 0;
    if (uc_hook_add(guest.unicorn.get(), &rdtsc_hook, UC_HOOK_INSN,
                    reinterpret_cast<void*>(on_rdtsc_callback), &state, 1, 0,
                    UC_X86_INS_RDTSC) != UC_ERR_OK) {
        return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
    }

    uc_hook rdtscp_hook = 0;
    if (uc_hook_add(guest.unicorn.get(), &rdtscp_hook, UC_HOOK_INSN,
                    reinterpret_cast<void*>(on_rdtscp_callback), &state, 1, 0,
                    UC_X86_INS_RDTSCP) != UC_ERR_OK) {
        return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
    }

    // Behavior monitored windows: memory windows from
    // snapshot facts (TEB/PEB pages + KUSER) and the monitored code window
    // over the sample's own image. Everything outside stays unhooked.
    if (state.behavior_sink) {
        std::vector<std::uint64_t> read_windows;
        if (guest.metadata.teb_address != 0) {
            read_windows.push_back(guest.metadata.teb_address & ~(kLedgerPageSize - 1));
        }
        if (guest.metadata.peb_address != 0) {
            read_windows.push_back(guest.metadata.peb_address & ~(kLedgerPageSize - 1));
        }
        read_windows.push_back(0x7FFE0000); // KUSER_SHARED_DATA
        std::ranges::sort(read_windows);
        read_windows.erase(std::unique(read_windows.begin(), read_windows.end()),
                           read_windows.end());
        for (const auto page : read_windows) {
            uc_hook read_window = 0;
            if (uc_hook_add(guest.unicorn.get(), &read_window, UC_HOOK_MEM_READ,
                            reinterpret_cast<void*>(on_behavior_mem_read), &state, page,
                            page + kLedgerPageSize) != UC_ERR_OK) {
                return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
            }
        }
        if (sample_image_size != 0) {
            uc_hook code_window = 0;
            if (uc_hook_add(guest.unicorn.get(), &code_window, UC_HOOK_CODE,
                            reinterpret_cast<void*>(on_behavior_code), &state,
                            guest.metadata.image_base,
                            guest.metadata.image_base + sample_image_size) != UC_ERR_OK) {
                return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
            }
        }
    }

    uc_hook block_hook = 0;
    if (uc_hook_add(guest.unicorn.get(), &block_hook, UC_HOOK_BLOCK,
                    reinterpret_cast<void*>(on_syscall_run_block), &state, 1, 0) != UC_ERR_OK) {
        return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
    }

    uc_hook intr_hook = 0;
    if (uc_hook_add(guest.unicorn.get(), &intr_hook, UC_HOOK_INTR,
                    reinterpret_cast<void*>(on_intr_callback), &state, 1, 0) != UC_ERR_OK) {
        return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
    }

    uc_hook mem_invalid_hook = 0;
    if (uc_hook_add(guest.unicorn.get(), &mem_invalid_hook, UC_HOOK_MEM_INVALID,
                    reinterpret_cast<void*>(on_mem_invalid_callback), &state, 1, 0) != UC_ERR_OK) {
        return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
    }

    uc_hook insn_invalid_hook = 0;
    if (uc_hook_add(guest.unicorn.get(), &insn_invalid_hook, UC_HOOK_INSN_INVALID,
                    reinterpret_cast<void*>(on_insn_invalid_callback), &state, 1, 0) != UC_ERR_OK) {
        return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
    }

    // Loader-route API interception: one range-bound code hook per
    // intercepted entry, all sharing the by-address dispatcher.
    for (std::size_t i = 0; i < state.intercept_vas.size(); ++i) {
        uc_hook api_hook = 0;
        if (uc_hook_add(guest.unicorn.get(), &api_hook, UC_HOOK_CODE,
                        reinterpret_cast<void*>(on_intercept), &state, state.intercept_vas[i],
                        state.intercept_vas[i] + 1) != UC_ERR_OK) {
            return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
        }
    }

    // The C++ accept handoff hook on ntdll!RtlUnwindEx: an active engine
    // dispatch reaching this export means the accepting handler drove the
    // real unwind machinery - the hook retires the handshake and re-delivers
    // the fault through the guest dispatcher (intercept.cpp). Fidelity mode
    // only traces there. A missing export (synthetic ntdll) skips the hook -
    // the C++ unwind then degrades to the unhandled fallback, as scoped.
    if (guest.guest_mode == GuestMode::kX64) {
        const auto ntdll = guest.map.module_index_by_name("ntdll.dll");
        if (ntdll.has_value()) {
            const auto unwind_va = syscalls::resolve_export(
                guest.unicorn.get(), guest.map.module(*ntdll).base, "RtlUnwindEx");
            if (unwind_va.has_value() && unwind_va.value() != 0) {
                state.rtl_unwind_address = unwind_va.value();
                uc_hook unwind_hook = 0;
                if (uc_hook_add(guest.unicorn.get(), &unwind_hook, UC_HOOK_CODE,
                                reinterpret_cast<void*>(on_rtl_unwind_ex), &state,
                                state.rtl_unwind_address,
                                state.rtl_unwind_address + 1) != UC_ERR_OK) {
                    return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
                }
            }
        }
    }
    return {};
}

// Produces the run verdict: drains the stub tally, snapshots the stats,
// writes the exit-time dump for the four deterministic stops, and
// translates everything else (crash fallback, emulation error, budget or
// timeout expiry) into the typed failure.
std::expected<SyscallRunStats, SyscallRunFailure>
finish_run(SyscallRunState& state, PreparedGuest& guest, const SyscallRunOptions& options,
           std::uint64_t ntdll_base, uc_err run_error,
           const std::chrono::steady_clock::time_point run_started);

// Syscall run: rebuild, attach the policy, execute until the guest
// terminates or the budget/timeout expires.

std::expected<SyscallRunStats, SyscallRunFailure>
run_syscalls(PreparedGuest& guest, const SyscallRunOptions& options, const FactChannel& facts)
{
    // The module source table is a construction fact: deliver it before any
    // state assembly or hook registration can fail the run - a run that
    // never executes still carries its provenance.
    if (options.module_source_sink) {
        for (const auto& [name, source] : guest.module_sources) {
            options.module_source_sink(name, system_module_source_spelling(source));
        }
    }
    SyscallRunState state;
    if (const auto assembled = assemble_run_state(guest, options, facts, state); !assembled) {
        return std::unexpected(assembled.error());
    }
    std::uint64_t ntdll_base = seed_policy_and_normalize(guest, options, state);
    // Write ledger: every guest memory write marks its page
    // dirty in the owning snapshot region. Writer attribution needs the
    // sample's full image span (base + SizeOfImage from the module record
    // at the snapshot image base) - a capture splits the image into several
    // protection regions, so a bare base check would drop the body writes.
    std::uint64_t sample_image_size = 0;
    for (std::size_t i = 0; i < guest.map.module_count(); ++i) {
        if (guest.map.module(i).base == guest.metadata.image_base) {
            sample_image_size = guest.map.module(i).size;
            state.sample_module_known = true;
            state.sample_module_index = i;
            break;
        }
    }
    MemWriteLedger write_ledger(guest.regions, guest.metadata.image_base, sample_image_size);

    uc_hook mem_write_hook = 0;
    if (uc_hook_add(guest.unicorn.get(), &mem_write_hook, UC_HOOK_MEM_WRITE_PROT,
                    reinterpret_cast<void*>(on_mem_write_prot_callback), &state, 1,
                    0) != UC_ERR_OK) {
        return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
    }
    state.write_ledger = &write_ledger;

    if (const auto hooks = register_run_hooks(guest, options, state, sample_image_size); !hooks) {
        return std::unexpected(hooks.error());
    }
    if (const auto tls = run_tls_callback_legs(guest); !tls) {
        return std::unexpected(tls.error());
    }
    // The esp stop target: the entry face is the world's starting registers
    // (post TLS legs), the window comes from the static save-extent scan,
    // and a run that never asked for an esp goal returns without touching
    // the guest.
    esp_target::install(guest.unicorn.get(), guest, state);
    // Multi-leg loop: the first leg runs guest code; an exception stops the
    // leg and the next leg executes the real dispatcher (which itself runs
    // handlers and resumes the guest). Each leg is bounded by the full
    // instruction budget and wall-clock timeout; a guest cycling distinct
    // exceptions is therefore bounded by time, and repeated identical
    // deliveries by the dispatch guard.
    const auto entry = guest.metadata.entry_address;
    std::uint64_t begin = entry;
    uc_err run_error = UC_ERR_OK;
    const auto run_started = std::chrono::steady_clock::now();
    // The one host-side diagnostic at the point where every run route
    // converges: the snapshot replay and the loader run both arrive here
    // through run_syscalls, so a single record says "the emulation started"
    // for either. Level kDebug on purpose - the facade's installed threshold is
    // kWarning by default, so a host that never lowered it sees nothing and the
    // observable stream (artifacts, event ledger, goldens) stays byte-for-byte
    // untouched. It is also what makes the sink round-trip assertable across the
    // library boundary: this record is raised inside the shared library by code
    // it linked statically, and the exported log::set_sink is the only public
    // way to install the sink it lands in (see shared_api_test - a binary that
    // carried a second copy of that state would go empty here, which is exactly
    // the failure the one-binary-one-link-route rule exists to prevent).
    // The format sits behind the pre-check: with no sink installed, or a
    // threshold above kDebug (the default), the run pays one uncontended lock
    // and two integer compares instead of building a string that write() would
    // immediately drop.
    if (log::would_log(log::level::kDebug)) {
        log::debug(std::format("engine run start: entry=0x{:x} budget={} timeout_ms={}", entry,
                               options.max_instructions, options.timeout_ms));
    }
    // Legs run with timeout=0 and a bounded instruction count instead: every
    // uc_emu_start call with a live unicorn timeout arms the host alarm
    // timer, which costs a system-timer tick (~11ms on Windows) per leg -
    // and the fault-based write ledger plus the AVX shim make this loop
    // re-enter thousands of times. The wall-clock budget is enforced
    // host-side at leg boundaries; a leg is at most kLegInstructionCount
    // instructions (~tens of ms), which bounds the timeout granularity.
    constexpr std::uint64_t kLegInstructionCount = 1000000;
    // Deterministic virtual time: 1 guest ms per 128 executed instructions,
    // 16384 TSC ticks per instruction. Clock-based delay waits (KUSD
    // TickCount busy-waits, rdtsc/rdtscp deltas) complete in bounded
    // emulation time and replays stay host-independent. The rates are
    // ~24x native-delay compression: a 3s Sleep costs ~0.4M instructions.
    constexpr std::uint64_t kTscTicksPerInstruction = 16384;
    constexpr std::uint64_t kInstructionsPerGuestMs = 128;
    std::uint64_t remaining_instructions = options.max_instructions;
    // Scheduler: main thread is tid 0; the scheduler stays a pass-
    // through until a thread creation flips it on.
    auto& sched = state.scheduler;
    sched.uc = guest.unicorn.get();
    sched.mode = guest.guest_mode;
    sched.threads.push_back(SchedulerThread{.tid = 0,
                                            .context = nullptr,
                                            .teb_base = guest.metadata.teb_address,
                                            .rip_resume = begin,
                                            .stack_base = 0,
                                            .stack_limit = 0,
                                            .finished = false});
    sched.slice_size = options.thread_slice_blocks != 0 ? options.thread_slice_blocks : 10000;
    for (;;) {
        const std::uint64_t leg_count =
            remaining_instructions == 0 ? kLegInstructionCount
                                        : (std::min)(kLegInstructionCount, remaining_instructions);
        const std::uint64_t leg_start_blocks = state.blocks;
        // Advance the virtual clock and publish it into KUSER_SHARED_DATA
        // (TickCount fields the loader and delay stubs read) before the leg.
        state.virtual_instructions += leg_count;
        state.virtual_tsc = state.virtual_instructions * kTscTicksPerInstruction;
        state.virtual_ticks =
            static_cast<std::uint32_t>(state.virtual_instructions / kInstructionsPerGuestMs);
        const std::uint32_t kusd_ticks = state.virtual_ticks;
        for (const std::uint64_t kusd_field : {0x7FFE0004ULL, 0x7FFE0320ULL, 0x7FFE0324ULL}) {
            uc_mem_write(guest.unicorn.get(), kusd_field, &kusd_ticks, sizeof kusd_ticks);
        }
        run_error = uc_emu_start(guest.unicorn.get(), begin, 0, 0, leg_count);
        // A leg return carries one stop reason: the xfer hook stops before the
        // landing block runs, so no resume or exception flag can be set
        // alongside it. The esp read hook stops mid-block, but its leg can
        // never carry a pending write grant (a grant stops its own leg in the
        // write hook), so the same "one reason" invariant holds. This check
        // stays ahead of every trailing continue.
        if (state.xfer_stop_reached) {
            break;
        }
        if (state.esp_stop_reached) {
            break;
        }
        if (state.terminated) {
            // The terminate-side disposition: when the process dies with the
            // last dispatched exception's own code, that exception is what
            // ended it - the walk's UnhandledExceptionFilter absorbed the
            // delivery and its handler called NtTerminateProcess with the
            // status. Emit the last-chance event so the report distinguishes
            // this death from exceptions the sample absorbed and moved past.
            if (state.exit_code != 0 && state.exit_code == state.last_dispatch_code) {
                emit_exception_event(state, state.last_dispatch_code, state.last_dispatch_pc, true);
            }
            break;
        }
        if (state.iretq_pending) {
            // The v2 unwind tail's IRETQ: pop the machine frame the walk
            // pushed - {rip, cs, eflags, rsp, ss} - and continue at the
            // restored context. Done between legs so the register writes
            // stay consistent with the executing guest. The interrupted
            // context resumes: the exception ended handled. The dispatch
            // guard disarms - a later delivery of the same (pc, code) pair
            // is a legitimate fresh dispatch (sequential C++ throws share
            // both), not a re-raise of an unhandled walk.
            state.iretq_pending = false;
            state.dispatch_guard_armed = false;
            std::uint64_t new_rip = 0, new_rsp = 0;
            uc_mem_read(guest.unicorn.get(), state.iretq_rsp, &new_rip, sizeof new_rip);
            uc_mem_read(guest.unicorn.get(), state.iretq_rsp + 0x18, &new_rsp, sizeof new_rsp);
            write_rip(guest.unicorn.get(), new_rip);
            write_rsp(guest.unicorn.get(), new_rsp);
            begin = new_rip;
            continue;
        }
        if (state.exception.valid) {
            if (state.exception.unhandled) {
                emit_exception_event(state, state.exception.code, state.exception.pc, true);
                state.unhandled = true;
                break;
            }
            if (state.exception.replay_in_guest) {
                // The C++ accept handoff: the same fault re-delivered through
                // the real guest dispatcher, whose unwind machinery completes
                // the catch protocol (silent - the fault is already in the
                // ledger). synthesize_and_dispatch consumes the replay flag
                // with the rest of the exception state.
                switch (synthesize_and_dispatch(guest, state)) {
                case DispatchOutcome::kDispatched:
                    begin = read_rip(guest.unicorn.get());
                    continue;
                case DispatchOutcome::kUnhandled:
                    state.unhandled = true;
                    break;
                case DispatchOutcome::kEngineError:
                    return std::unexpected(SyscallRunFailure{SyscallRunError::kEmulationFailure});
                }
                break;
            }
            if (!state.fidelity_dispatch) {
                // Engine dispatch: first-chance event, then step the
                // state machine. Nested faults inside callbacks arrive here
                // too - begin_dispatch stacks a new layer.
                emit_exception_event(state, state.exception.code, state.exception.pc, false);
                const bool x86 = state.guest_mode == GuestMode::kX86;
                seh::begin_dispatch(
                    state.seh, guest.unicorn.get(), x86, state.exception.code, state.exception.pc,
                    state.exception.information_count >= 2 ? state.exception.information[1] : 0,
                    state.exception.information,
                    static_cast<std::uint32_t>(state.exception.information_count));
                state.exception = {};
                const auto step =
                    seh::step(guest.unicorn.get(), state.seh, x86, state.teb_base, guest.map);
                switch (step.action) {
                case seh::Step::RunCallback:
                    // the dispatcher staged a guest handler: report who is
                    // about to absorb the fault (engine-dispatch mode only;
                    // fidelity dispatch never knows the handler)
                    emit_handler_dispatch_event(state, seh::fault_code(state.seh),
                                                read_rip(guest.unicorn.get()),
                                                seh::fault_pc(state.seh));
                    begin = read_rip(guest.unicorn.get());
                    continue;
                case seh::Step::ResumeHandled:
                    begin = read_rip(guest.unicorn.get());
                    continue;
                case seh::Step::Unhandled:
                    emit_exception_event(state, seh::fault_code(state.seh),
                                         seh::fault_pc(state.seh), true);
                    state.unhandled = true;
                    break;
                case seh::Step::EngineError:
                    return std::unexpected(SyscallRunFailure{SyscallRunError::kEmulationFailure});
                }
                break;
            }
            switch (synthesize_and_dispatch(guest, state)) {
            case DispatchOutcome::kDispatched:
                begin = read_rip(guest.unicorn.get());
                continue;
            case DispatchOutcome::kUnhandled:
                state.unhandled = true;
                break;
            case DispatchOutcome::kEngineError:
                return std::unexpected(SyscallRunFailure{SyscallRunError::kEmulationFailure});
            }
            break;
        }
        if (!state.fidelity_dispatch && state.seh_unwind_resume) {
            // the C++ accept takeover: the frame handler
            // drove RtlUnwindEx and the engine owns the unwind pass now -
            // step the state machine (first UNWINDING callback staging)
            state.seh_unwind_resume = false;
            const bool x86 = state.guest_mode == GuestMode::kX86;
            const auto step =
                seh::step(guest.unicorn.get(), state.seh, x86, state.teb_base, guest.map);
            switch (step.action) {
            case seh::Step::RunCallback:
                emit_handler_dispatch_event(state, seh::fault_code(state.seh),
                                            read_rip(guest.unicorn.get()),
                                            seh::fault_pc(state.seh));
                begin = read_rip(guest.unicorn.get());
                continue;
            case seh::Step::ResumeHandled:
                begin = read_rip(guest.unicorn.get());
                continue;
            case seh::Step::Unhandled:
                emit_exception_event(state, seh::fault_code(state.seh), seh::fault_pc(state.seh),
                                     true);
                state.unhandled = true;
                break;
            case seh::Step::EngineError:
                return std::unexpected(SyscallRunFailure{SyscallRunError::kEmulationFailure});
            }
            break;
        }
        if (!state.fidelity_dispatch && state.seh.active && state.seh.callback_done) {
            // a staged callback returned through the trampoline: advance the
            // dispatch state machine. A leg stop while the callback is still
            // in flight (write-prot claims, shim resumes) must fall through
            // to those resume paths instead - stepping here would abandon
            // the running callback mid-frame.
            const bool x86 = state.guest_mode == GuestMode::kX86;
            const auto step =
                seh::step(guest.unicorn.get(), state.seh, x86, state.teb_base, guest.map);
            switch (step.action) {
            case seh::Step::RunCallback:
                // a follow-up callback staged (unwind scope handlers, nested
                // layers): report it the same way
                emit_handler_dispatch_event(state, seh::fault_code(state.seh),
                                            read_rip(guest.unicorn.get()),
                                            seh::fault_pc(state.seh));
                begin = read_rip(guest.unicorn.get());
                continue;
            case seh::Step::ResumeHandled:
                begin = read_rip(guest.unicorn.get());
                continue;
            case seh::Step::Unhandled:
                emit_exception_event(state, seh::fault_code(state.seh), seh::fault_pc(state.seh),
                                     true);
                state.unhandled = true;
                break;
            case seh::Step::EngineError:
                return std::unexpected(SyscallRunFailure{SyscallRunError::kEmulationFailure});
            }
            break;
        }
        if (state.avx_resume) {
            state.avx_resume = false;
            // The shim advances RIP past the unsupported instruction and the
            // aborting translation never commits to the code cache, so the
            // shim re-fires on every re-encounter without a flush. Flushing
            // here cost a full-cache retranslation per shim hit (~0.7s on
            // the packed corpus, ~5000 hits). If a unicorn base starts
            // caching aborting translations, this is the line to revisit.
            begin = read_rip(guest.unicorn.get());
            continue;
        }
        if (state.write_prot_resume) {
            state.write_prot_resume = false;
            // Apply the deferred page grants (outside the hook context),
            // then re-enter at the same RIP so the store executes natively.
            for (const auto& grant : state.pending_write_grants) {
                uc_mem_protect(guest.unicorn.get(), grant.first, kLedgerPageSize,
                               static_cast<std::uint32_t>(grant.second));
            }
            state.pending_write_grants.clear();
            begin = read_rip(guest.unicorn.get());
            continue;
        }
        if (state.api_resume) {
            state.api_resume = false;
            // an intercepted API call completed: resume at the caller's
            // return address the handler wrote into RIP
            begin = read_rip(guest.unicorn.get());
            continue;
        }
        if (state.loop_probe_pending) {
            // Burn-loop fast-forward: probe the detected cycle and force its
            // natural exit. The probe restores everything when the cycle
            // turns out to be real computation. The flag stays armed while
            // the probe emulates: its chunks re-enter the block hook with
            // hot_run still at the trigger count, and a cleared flag there
            // would re-trigger the probe mid-experiment (a truncated first
            // chunk plus a spurious second probe and leg - the historical
            // +2 block overshoot on budget-exhausted spins).
            run_loop_probe(state, guest.unicorn.get());
            state.loop_probe_pending = false;
            begin = read_rip(guest.unicorn.get());
            continue;
        }
        // The leg ran to its instruction count with no engine stop pending:
        // enforce the wall clock, then continue with the next leg. A guest
        // fault that no hook claimed surfaces as a non-OK uc_err and ends
        // the run - the exception paths above cover the
        // handled kinds.
        if (run_error != UC_ERR_OK) {
            break;
        }
        // A leg that returns OK without reaching its instruction count stopped
        // at the until address (0): the guest transferred control to rip 0.
        // That is a crash, not a full-count leg - re-entering here would
        // restart at rip 0 and burn the whole budget leg by leg with zero
        // execution (the deterministic budget stop, no dump, no diagnostics).
        if (read_rip(guest.unicorn.get()) == 0) {
            state.unhandled = true;
            break;
        }
        if (options.timeout_ms != 0 && std::chrono::steady_clock::now() - run_started >=
                                           std::chrono::milliseconds(options.timeout_ms)) {
            break; // timeout_stop below
        }
        if (remaining_instructions != 0) {
            remaining_instructions -= leg_count;
            if (remaining_instructions == 0) {
                break; // instruction budget expired
            }
        }
        // Scheduler: rotate threads at the leg boundary. The timeslice
        // is block-accounted (blocks executed this leg belong to the current
        // thread); a pending blocking yield (wait-class syscall) rotates
        // unconditionally.
        if (state.scheduler.enabled) {
            sched.slice_used += state.blocks - leg_start_blocks;
            if (sched.blocked || sched.slice_used >= sched.slice_size) {
                auto& cur = sched.cur();
                if (!sched.blocked) {
                    // slice yield: resume where the leg stopped. A blocked
                    // yield already set rip_resume past its syscall (the
                    // dispatch), and read_rip here would still point AT it.
                    cur.rip_resume = read_rip(guest.unicorn.get());
                }
                if (cur.context == nullptr &&
                    uc_context_alloc(guest.unicorn.get(), &cur.context) != UC_ERR_OK) {
                    return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
                }
                if (uc_context_save(guest.unicorn.get(), cur.context) != UC_ERR_OK) {
                    return std::unexpected(SyscallRunFailure{SyscallRunError::kUnicornFailure});
                }
                // pick the next non-finished thread (round-robin, may be us)
                std::size_t next = sched.current;
                for (std::size_t n = 1; n <= sched.threads.size(); ++n) {
                    const auto idx = (sched.current + n) % sched.threads.size();
                    if (!sched.threads[idx].finished) {
                        next = idx;
                        break;
                    }
                }
                sched.slice_used = 0;
                sched.blocked = false;
                if (next != sched.current) {
                    sched.current = next;
                    state.current_tid = sched.threads[next].tid;
                    apply_teb_switch(guest.unicorn.get(), sched.mode, sched.threads[next].teb_base);
                }
                uc_context_restore(guest.unicorn.get(), sched.threads[next].context);
                begin = sched.threads[next].rip_resume;
            } else {
                begin = read_rip(guest.unicorn.get());
            }
        } else {
            begin = read_rip(guest.unicorn.get());
        }
    }
    sched.shutdown();

    return finish_run(state, guest, options, ntdll_base, run_error, run_started);
}

// Produces the run verdict: drains the stub tally, snapshots the stats,
// writes the exit-time dump for the four deterministic stops, and
// translates everything else (crash fallback, emulation error, budget or
// timeout expiry) into the typed failure.
std::expected<SyscallRunStats, SyscallRunFailure>
finish_run(SyscallRunState& state, PreparedGuest& guest, const SyscallRunOptions& options,
           std::uint64_t ntdll_base, uc_err run_error,
           const std::chrono::steady_clock::time_point run_started)
{
    // Loop-gate verdict distribution: accumulated unconditionally per probe
    // window, rendered only under the trace switch - and then as one kDebug
    // record, because these pieces were always one line. The counters fill
    // either way, so the event stream and the dump stay byte-identical.
    if (diag::wanted(sheller::log::level::kDebug, state.loop_gate_trace)) {
        std::uint64_t total = 0;
        for (const auto count : state.loop_gate_counts) {
            total += count;
        }
        std::string line = std::format("[loop-gate] run summary: windows={}", total);
        if (const auto c = state.loop_gate_counts[native_gate::kAdmitZeroWriteSlot]; c != 0) {
            line += std::format(" admitted_zero_write={}", c);
        }
        if (const auto c = state.loop_gate_counts[native_gate::kAdmitComputeSlot]; c != 0) {
            line += std::format(" admitted_compute={}", c);
        }
        for (std::size_t slot = native_gate::kRejectSlotBase; slot < native_gate::kVerdictSlotCount;
             ++slot) {
            if (const auto c = state.loop_gate_counts[slot]; c != 0) {
                line += std::format(
                    " reject_{}={}",
                    native_gate::reject_reason_name(native_gate::reason_for_slot(slot)), c);
            }
        }
        sheller::log::write(sheller::log::level::kDebug, line);
    }

    // Drain the stub tally once, off the hook hot
    // path - one sink call per counted export, deterministic order (slot
    // fill order = loader export table order).
    if (static_cast<bool>(state.stub_sink)) {
        for (const auto& stub_entry : state.stub_entries) {
            if (stub_entry.count != 0) {
                state.stub_sink(stub_entry.module, stub_entry.name, stub_entry.count);
            }
        }
    }

    SyscallRunStats stats{.terminated = state.terminated,
                          .exit_code = state.exit_code,
                          .blocks = state.blocks,
                          .syscalls = state.syscalls,
                          .rejects = state.rejects,
                          .exceptions = state.exceptions,
                          .xfers = state.xfers,
                          .xfer_stop = state.xfer_stop_reached,
                          // esp+xfer's stop is taken by the xfer machinery at
                          // the transfer the confirmation armed - that stop is
                          // the esp goal's hit (xfer_stop rides alongside, and
                          // xfers carries the ordinal). A stop the arm never
                          // preceded is a plain xfer target's and leaves
                          // esp_stop clear.
                          .esp_stop = state.esp_stop_reached ||
                                      (state.esp_armed_next_xfer && state.xfer_stop_reached),
                          // DLL-input route: where the synthesized sample
                          // module landed (0 without a pending module).
                          .sample_module_base = state.dll_load.active ? state.dll_load.base : 0};
    // Exit-time dump pipeline: the five deterministic stop
    // kinds (normal exit, crash fallback, block budget, xfer target, esp
    // target) all land here; wall-clock timeout does not (non-deterministic,
    // excluded from baselines). A target stop vetoes the recomputed wall
    // clock: the clock is only read at leg boundaries, so it can cross the
    // threshold inside the very leg the target ends - whichever target got
    // there first owns the stop.
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - run_started)
                                .count();
    const bool target_stop_reached = state.xfer_stop_reached || state.esp_stop_reached;
    const bool timeout_stop = options.timeout_ms != 0 &&
                              elapsed_ms >= static_cast<std::int64_t>(options.timeout_ms) &&
                              !target_stop_reached;
    // The five deterministic stops dump: normal exit (state.terminated),
    // crash fallback (state.unhandled - via fastfail or via exception
    // dispatch, which keeps the interrupted leg's run_error: that stale
    // value must not veto the dump), budget expiry, and the xfer or esp
    // target (both keep run_error UC_ERR_OK). A stop with pending exception
    // facts is not converged.
    const bool dump_eligible =
        !timeout_stop &&
        (state.terminated || state.unhandled || (run_error == UC_ERR_OK && !state.exception.valid));
    if (dump_eligible && !options.dump_directory.empty()) {
        if (!sheller::engine::write_dump(options.dump_directory, *state.write_ledger,
                                         guest.unicorn.get())) {
            return std::unexpected(SyscallRunFailure{SyscallRunError::kIoFailure, 0, stats});
        }
    }

    // The boundary-trap stop: a deliberate, named termination - never a
    // crash, never a budget expiry, never a completed call.
    if (state.boundary_trap.fired) {
        stats.terminated = false;
        auto detail = std::format("boundary-trap: {}!{} (ordinal {}) at 0x{:x} called from 0x{:x}",
                                  state.boundary_trap.module, state.boundary_trap.name,
                                  state.boundary_trap.ordinal, state.boundary_trap.va,
                                  state.boundary_trap.caller);
        sheller::log::write(sheller::log::level::kWarning, "sheller run: " + detail);
        SyscallRunFailure failure{SyscallRunError::kBoundaryTrap, 0, stats};
        failure.detail = std::move(detail);
        return std::unexpected(failure);
    }
    // unicorn2 stops silently (UC_ERR_OK) when the count or the timeout
    // expires; only real emulation faults come back as errors here.
    if (state.unhandled) {
        if (state.uc != nullptr) {
            // Crash diagnostics: state for the SEH-dispatch audit.
            std::uint64_t rip = 0;
            uc_reg_read(state.uc, UC_X86_REG_RIP, &rip);
            std::array<std::uint8_t, 16> code_bytes{};
            uc_mem_read(state.uc, rip, code_bytes.data(), code_bytes.size());
            std::string hex;
            for (const auto b : code_bytes) {
                hex += std::format("{:02x} ", b);
            }
            std::uint64_t rsp = 0, rax = 0, rcx = 0, rdx = 0, rdi = 0;
            uc_reg_read(state.uc, UC_X86_REG_RSP, &rsp);
            uc_reg_read(state.uc, UC_X86_REG_RAX, &rax);
            uc_reg_read(state.uc, UC_X86_REG_RCX, &rcx);
            uc_reg_read(state.uc, UC_X86_REG_RDX, &rdx);
            uc_reg_read(state.uc, UC_X86_REG_RDI, &rdi);
            for (std::size_t i = 0; i < state.region_map->module_count(); ++i) {
                if (std::string_view(state.region_map->module(i).name.data()) == "ntdll.dll") {
                    ntdll_base = state.region_map->module(i).base;
                }
            }
            // The one engine diagnostic that is not a trace: a guest that died with
            // no handler is the operator's business even when nobody asked for
            // diagnostics, so the record goes at kWarning - the threshold the CLI's
            // own sink installs, which keeps the line reachable there while a host
            // that installed no sink stays silent, and no path writes a standard
            // stream on its own authority.
            // Probe the unicorn permission of the crashing page: a fetch fault
            // with bytes present is a permission story, and the probe settles
            // it in one line.
            std::string perm_probe;
            {
                uc_mem_region* regions = nullptr;
                std::uint32_t region_count = 0;
                if (uc_mem_regions(state.uc, &regions, &region_count) == UC_ERR_OK) {
                    for (std::uint32_t i = 0; i < region_count; ++i) {
                        if (rip >= regions[i].begin && rip < regions[i].begin + regions[i].end) {
                            perm_probe = std::format(" page-perm={:#x}", regions[i].perms);
                            break;
                        }
                    }
                    uc_free(regions);
                }
            }
            const auto crash = std::format(
                "sheller run: unhandled crash rip=0x{:x} rsp=0x{:x} rax=0x{:x} rcx=0x{:x} "
                "rdx=0x{:x} rdi=0x{:x} ntdll=0x{:x}{} bytes={}",
                rip, rsp, rax, rcx, rdx, rdi, ntdll_base, perm_probe, hex);
            sheller::log::write(sheller::log::level::kWarning, crash);
        }
        return std::unexpected(SyscallRunFailure{SyscallRunError::kUnhandledException, 0, stats});
    }
    if (run_error != UC_ERR_OK) {
        return std::unexpected(SyscallRunFailure{SyscallRunError::kEmulationFailure,
                                                 static_cast<std::uint32_t>(run_error), stats});
    }
    if (state.xfer_stop_reached) {
        return stats; // deliberate stop: success, guest did not terminate
    }
    if (state.esp_stop_reached) {
        return stats; // deliberate stop: success, guest did not terminate
    }
    if (!state.terminated) {
        // Distinguish the two silent expiry kinds by the same wall-clock
        // reading that gated the dump decision above.
        const auto expiry =
            timeout_stop ? SyscallRunError::kTimeout : SyscallRunError::kBudgetExhausted;
        return std::unexpected(SyscallRunFailure{expiry, 0, stats});
    }
    return stats;
}
} // namespace sheller::engine
