#include "run_plan.h"

#include "dll_loader.h"
#include "intercept.h"
#include "rebuild_state.h"
#include "run_facts.h"

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>

namespace sheller::engine {
namespace {

// Region-map module index for an export VA: the owner of the module span the
// VA lands in, or 0xFFFF when no owner resolves (the runtime sentinel). This
// is the pure counterpart of the old state-reading helper: it walks the
// construction tables instead of a half-filled run state.
std::uint16_t module_index_for_va(const PreparedGuest& guest, const std::uint64_t va)
{
    for (const auto& mod : guest.loader_modules) {
        if (va >= mod.base && va < mod.base + mod.size) {
            if (const auto idx =
                    guest.map.module_index_by_name(fold_name(std::string_view(mod.name.data())));
                idx.has_value()) {
                return static_cast<std::uint16_t>(*idx);
            }
            break;
        }
    }
    return 0xFFFF; // kRuntimeIndex: no region-map owner resolved
}

} // namespace

std::expected<RunPlan, SyscallRunFailure> build_run_plan(const PreparedGuest& guest,
                                                         [[maybe_unused]] const GuestFacts& facts,
                                                         const SyscallRunOptions& options)
{
    RunPlan plan;
    plan.directory_mode = guest.directory_mode;
    const auto registered = [&plan](const std::uint64_t va) {
        return std::find(plan.intercept_vas.begin(), plan.intercept_vas.end(), va) !=
               plan.intercept_vas.end();
    };

    // The declared intercept set, then the DLL-input continuation slot (the
    // apply stage arms it; the VA/id pair is decided here so the identity
    // tables below stay index-aligned with the hook list).
    for (const auto& [va, id] : guest.intercepts) {
        plan.intercept_vas.push_back(va);
        plan.intercept_ids.push_back(id);
    }
    if (guest.pending.has_value()) {
        plan.arm_resume_slot = true;
        plan.intercept_vas.push_back(kDllResumeSlotVa);
        plan.intercept_ids.push_back(static_cast<std::uint32_t>(InterceptId::kDllLoadResume));
    }

    // Heap-family interception: the loader route points PEB.ProcessHeap at the
    // engine's deterministic heap region, which is not a real _HEAP - real
    // ntdll heap-manager code running against it reads garbage internal
    // pointers and dies (the packed corpus crashed in RtlDestroyHeap with
    // environment-string bytes as the handle). Register the family at the
    // mapped ntdll's export entries so every caller - IAT or
    // direct/hash-resolved - lands in the engine heap; the handle value stays
    // opaque to both sides. LdrLoadDll joins for the same reason.
    for (const auto& entry : guest.loader_exports) {
        for (const auto& [name, id] : kHeapInterceptNames) {
            if (fold_name(entry.name) != fold_name(name)) {
                continue;
            }
            if (!registered(entry.function_va)) {
                plan.intercept_vas.push_back(entry.function_va);
                plan.intercept_ids.push_back(static_cast<std::uint32_t>(id));
            }
        }
        for (const auto& [name, id] : kLdrInterceptNames) {
            if (fold_name(entry.name) != fold_name(name)) {
                continue;
            }
            if (!registered(entry.function_va)) {
                plan.intercept_vas.push_back(entry.function_va);
                plan.intercept_ids.push_back(static_cast<std::uint32_t>(id));
            }
        }
    }

    // Intercept identity for event emission: the export spelling from the
    // loader export table and the owning region-map module index. The
    // continuation slot has neither (no export row; outside every module
    // span), which is exactly what the state carried before the split.
    for (const auto va : plan.intercept_vas) {
        std::string name;
        for (const auto& entry : guest.loader_exports) {
            if (entry.function_va == va) {
                name = entry.name;
                break;
            }
        }
        plan.intercept_names.push_back(std::move(name));
        plan.intercept_modules.push_back(module_index_for_va(guest, va));
    }

    if (plan.directory_mode) {
        // Directory mode counts ONLY the explicit whitelist (derived compat
        // stubs plus fallback synthetic exports) - the "every non-intercepted
        // export is a stub" inference is a synthetic-mode rule and would
        // miscount real bodies, data slots, syscall stubs and traps. Alias
        // names sharing one VA land in one slot: the first whitelist row is
        // the stable canonical name.
        for (const auto& entry : guest.stub_whitelist) {
            if (registered(entry.function_va)) {
                continue;
            }
            if (plan.stub_slots.find(entry.function_va) != plan.stub_slots.end()) {
                continue; // shared VA alias: one slot, one count
            }
            const auto slot = static_cast<std::uint32_t>(plan.stub_entries.size());
            plan.stub_entries.push_back(
                {module_index_for_va(guest, entry.function_va), entry.name});
            plan.stub_slots.emplace(entry.function_va, slot);
        }
        // An intercept registration on the same VA supersedes the trap: the
        // engine answers the call in the hook and the ud2 body is never
        // reached (the manifest row stays trap-classified; the interception
        // layer is the engine support landing on it).
        for (const auto va : guest.boundary_trap_vas) {
            if (!registered(va)) {
                plan.boundary_trap_vas.push_back(va);
            }
        }
    } else {
        for (const auto& entry : guest.loader_exports) {
            if (registered(entry.function_va)) {
                continue; // intercepted exports emit apicall events, not counts
            }
            const auto slot = static_cast<std::uint32_t>(plan.stub_entries.size());
            plan.stub_entries.push_back(
                {module_index_for_va(guest, entry.function_va), entry.name});
            plan.stub_slots.emplace(entry.function_va, slot);
        }
    }
    plan.needs_stub_hooks = static_cast<bool>(options.stub_sink) && !plan.stub_entries.empty();

    // Loader-route deterministic allocator cursors (zeroed for other routes)
    // plus the engine-dispatch trampoline page: int3 marker target for the
    // callback return address, per-layer scratch for the guest
    // EXCEPTION_RECORD/CONTEXT/DISPATCHER_CONTEXT structs, and per-layer
    // callback stacks. Reserved from the front of the deterministic alloc bump
    // range; both dispatch modes map it (only the engine mode consumes it).
    // The callback stacks deliberately do NOT ride the guest stack: a captured
    // snapshot's committed stack may not extend below the faulting rsp, and a
    // silent staging write to unmapped memory would zero the handler's return
    // address.
    const auto& layout = layout_for(guest.guest_mode);
    plan.seh_trampoline = layout.alloc_base;
    plan.seh_scratch = layout.alloc_base + 0x1000;
    plan.valloc_cursor = layout.alloc_base + 0x21000;
    plan.heap_cursor = layout.heap_base;
    return plan;
}

} // namespace sheller::engine
