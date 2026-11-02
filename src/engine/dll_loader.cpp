// DLL-input synthetic loading - see dll_loader.h for the contract.

#include "dll_loader.h"

#include "esp_target.h"
#include "intercept.h"

#include "../loader/imports.h"
#include "../loader/loader.h"

#include <sheller/log.h>

#include <algorithm>
#include <cstring>
#include <format>
#include <vector>

namespace sheller::engine {
namespace {

// LDR_DATA_TABLE_ENTRY field offsets (x64 Win10/11 shape, the same layout
// loader-env builds its synthetic world against): InLoadOrderLinks @0,
// InMemoryOrderLinks @0x10, InInitializationOrderLinks @0x20, DllBase @0x30,
// EntryPoint @0x38, SizeOfImage @0x40, FullDllName @0x48, BaseDllName @0x58
// (UNICODE_STRING: Length u16, MaximumLength u16, pad, Buffer u64).
// PEB_LDR_DATA list heads: InLoadOrder @+0x10, InMemoryOrder @+0x20,
// InInitializationOrder @+0x30.
constexpr std::uint64_t kLdrInLoadOrderOffset = 0x10;
constexpr std::uint64_t kLdrInMemoryOrderOffset = 0x20;
constexpr std::uint64_t kLdrInInitOrderOffset = 0x30;

// Deterministic base band for synthesized modules: the preferred base
// first when free, then a fixed band far from both the captured-world
// module band and the loader-route fixed band, walking up in 64K steps.
// The Ldr node page sits one meg below the band.
constexpr std::uint64_t kDllSynthBaseBand = 0x7F0000000000ULL;
constexpr std::uint64_t kDllNodePageVa = kDllSynthBaseBand - 0x100000;

std::uint64_t read_u64(uc_engine* const uc, const std::uint64_t address)
{
    std::uint64_t value = 0;
    if (uc_mem_read(uc, address, &value, sizeof value) != UC_ERR_OK) {
        return 0;
    }
    return value;
}

void write_u64(uc_engine* const uc, const std::uint64_t address, const std::uint64_t value)
{
    static_cast<void>(uc_mem_write(uc, address, &value, sizeof value));
}

bool span_unmapped(uc_engine* const uc, const std::uint64_t base, const std::uint64_t size)
{
    uc_mem_region* regions = nullptr;
    std::uint32_t count = 0;
    if (uc_mem_regions(uc, &regions, &count) != UC_ERR_OK) {
        return false; // cannot enumerate: refuse to place anything
    }
    const auto end = base + size;
    bool free_span = true;
    for (std::uint32_t i = 0; i < count; ++i) {
        // uc_mem_region::end is inclusive - the span ends at end-1.
        if (base < regions[i].end + 1 && regions[i].begin < end) {
            free_span = false;
            break;
        }
    }
    uc_free(regions);
    return free_span;
}

// Doubly-linked insert of `node` right after `head` (a LIST_ENTRY address).
bool link_after(uc_engine* const uc, const std::uint64_t head, const std::uint64_t node)
{
    const auto first = read_u64(uc, head); // head.Flink
    if (first == 0) {
        return false;
    }
    write_u64(uc, node, first);     // node.Flink = first
    write_u64(uc, node + 8, head);  // node.Blink = head
    write_u64(uc, first + 8, node); // first.Blink = node
    write_u64(uc, head, node);      // head.Flink = node
    return true;
}

bool unlink_node(uc_engine* const uc, const std::uint64_t links)
{
    const auto flink = read_u64(uc, links);
    const auto blink = read_u64(uc, links + 8);
    if (flink == 0 || blink == 0) {
        return false;
    }
    write_u64(uc, blink, flink);
    write_u64(uc, flink + 8, blink);
    return true;
}

// Arms one ATTACH-shaped frame (TLS callback or DllMain) from the saved
// call-base stack: rcx = base, rdx = DLL_PROCESS_ATTACH, r8 = NULL, return
// address = the resume slot. x64 ABI: at a function's first instruction rsp
// is 8 mod 16 (the call pushed the return address onto a 16-aligned stack),
// so the return slot sits at align_down(base,16) - 8.
void enter_frame(SyscallRunState& state, const std::uint64_t target)
{
    auto* const uc = state.uc;
    std::uint64_t frame = state.dll_load.call_base_rsp & ~0xFULL; // 16-aligned base
    frame -= 8;                                                   // return-address slot
    write_u64(uc, frame, state.dll_resume_slot);
    uc_reg_write(uc, UC_X86_REG_RSP, &frame);
    std::uint64_t rcx = state.dll_load.base;
    std::uint64_t rdx = 1; // DLL_PROCESS_ATTACH
    std::uint64_t r8 = 0;
    std::uint64_t rip = target;
    uc_reg_write(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_write(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_write(uc, UC_X86_REG_R8, &r8);
    uc_reg_write(uc, UC_X86_REG_RIP, &rip);
}

// The load's answer, shared by DllMain's verdict and the no-entry-point
// shape: the caller site is restored verbatim, only rax (handle or NULL)
// differs. loaded records whether a DllMain body actually ran and accepted.
// The caller site is passed in explicitly: the FALSE path's rollback wipes
// dll_load (including caller_rip/rsp) before the answer is delivered, so the
// caller must capture it first.
void finish_dll_load(SyscallRunState& state, const std::uint64_t handle, const bool loaded,
                     const std::uint64_t caller_rip, const std::uint64_t caller_rsp)
{
    auto* const uc = state.uc;
    state.dll_load.loaded = loaded;
    uc_reg_write(uc, UC_X86_REG_RAX, &handle);
    uc_reg_write(uc, UC_X86_REG_RIP, &caller_rip);
    uc_reg_write(uc, UC_X86_REG_RSP, &caller_rsp);
    uc_emu_stop(uc);
}

// TLS callbacks first (directory order), then DllMain. Each frame is built
// fresh from the saved call base - a TLS callback's stack use cannot leak
// into the next frame.
void enter_next_frame(SyscallRunState& state)
{
    if (state.dll_load.tls_cursor < state.dll_load.tls_pending.size()) {
        const auto target = state.dll_load.tls_pending[state.dll_load.tls_cursor++];
        state.dll_load.phase = SyscallRunState::DllLoadState::Phase::kTls;
        enter_frame(state, target);
        return;
    }
    if (!state.dll_load.has_entry) {
        // AddressOfEntryPoint == 0 is a legal loadable shape (resource or
        // data DLL). Entering base+0 would execute the image's MZ bytes, so
        // the load completes here: TLS already ran, the handle answers.
        finish_dll_load(state, state.dll_load.base, true, state.dll_load.caller_rip,
                        state.dll_load.caller_rsp);
        return;
    }
    state.dll_load.phase = SyscallRunState::DllLoadState::Phase::kDllMain;
    // The unpack-relevant entry scene is DllMain's - the frame goes up
    // FIRST (the window anchor must be the frame's own entry rsp, not
    // the intercepted call's), then the esp monitor re-arms on the live rsp
    // (no-op unless requested; the passive semantics stay out of this
    // condition).
    enter_frame(state, state.dll_load.entry);
    esp_target::reinstall_at(state.uc, state.dll_load.entry, state);
}

} // namespace

// One load transaction's unwind - the guest's own DllMain FALSE and a
// mid-construction failure share this. Unlinks the Ldr node, unmaps the
// node page AND the image, drops the per-section ledger regions, restores
// the writer span and the loader tables, and clears the sample identity.
// Region-map records are append-only by design: a rolled-back module leaves
// a stale attribution interval over unmapped memory (known limitation).
void rollback_dll_load(SyscallRunState& state)
{
    if (!state.dll_load.active) {
        return;
    }
    auto* const uc = state.uc;
    const auto base = state.dll_load.base;
    const auto size = state.dll_load.size;
    const auto node = state.dll_load.node_va;
    if (state.dll_load.node_mapped) {
        for (std::size_t i = 0; i < state.dll_load.linked.size(); ++i) {
            if (state.dll_load.linked[i]) {
                unlink_node(uc, node + i * 0x10);
            }
        }
        uc_mem_unmap(uc, node, 0x1000);
    }
    if (state.dll_load.image_mapped) {
        uc_mem_unmap(uc, base, static_cast<std::size_t>(size));
    }
    if (state.write_ledger != nullptr) {
        for (const auto ledger_base : state.dll_load.ledger_bases) {
            state.write_ledger->remove_region(ledger_base);
        }
        state.write_ledger->set_sample_span(state.dll_load.prev_sample_base,
                                            state.dll_load.prev_sample_size);
    }
    std::erase_if(state.loader_exports,
                  [base](const LoaderExportEntry& entry) { return entry.module_base == base; });
    std::erase_if(state.loader_modules,
                  [base](const mem_region::ModuleRecord& record) { return record.base == base; });
    state.sample_module_known = state.dll_load.prev_sample_known;
    state.sample_module_index = state.dll_load.prev_sample_index;
    state.dll_load = {};
}

void arm_dll_resume_slot(SyscallRunState& state, uc_engine* uc)
{
    if (state.pending_module == nullptr) {
        return;
    }
    // The heap interception returns cursor addresses from the
    // loader-route layout, but only the construction route pre-maps that
    // heap. A photographed-world guest has no mapping there - the first CRT
    // allocation would answer an unmapped address. Map the deterministic
    // heap band here (conflict-checked) and point the cursor at it.
    const auto& layout = layout_for(state.guest_mode);
    uc_mem_region* regions = nullptr;
    std::uint32_t count = 0;
    bool heap_free = true;
    if (uc_mem_regions(uc, &regions, &count) == UC_ERR_OK) {
        const auto heap_end = layout.heap_base + layout.heap_size;
        for (std::uint32_t i = 0; i < count; ++i) {
            // uc_mem_region::end is inclusive.
            if (layout.heap_base < regions[i].end + 1 && regions[i].begin < heap_end) {
                heap_free = false;
                break;
            }
        }
        uc_free(regions);
    }
    if (heap_free && uc_mem_map(uc, layout.heap_base, layout.heap_size,
                                UC_PROT_READ | UC_PROT_WRITE) == UC_ERR_OK) {
        state.heap_cursor = layout.heap_base;
        if (state.region_map != nullptr) {
            state.region_map->register_region(layout.heap_base, layout.heap_size, kPageReadwrite,
                                              kMemPrivate, false);
        }
    }

    if (uc_mem_map(uc, kDllResumeSlotVa, 0x1000, UC_PROT_READ | UC_PROT_EXEC) != UC_ERR_OK) {
        return; // already mapped (a second arm on one guest)
    }
    const std::uint8_t ret = 0xC3;
    static_cast<void>(uc_mem_write(uc, kDllResumeSlotVa, &ret, 1));
    state.dll_resume_slot = kDllResumeSlotVa;
    state.intercept_vas.push_back(kDllResumeSlotVa);
    state.intercept_ids.push_back(static_cast<std::uint32_t>(InterceptId::kDllLoadResume));
    state.intercept_names.emplace_back("DllLoadResume");
    state.intercept_modules.push_back(0);
}

std::optional<std::string> synthesize_pending_load(SyscallRunState& state)
{
    const auto* pending = state.pending_module;
    if (pending == nullptr) {
        return std::string{"no pending module travels with this container"};
    }
    if (state.dll_load.active) {
        // Repeat request while armed or completed: same base, no re-entry.
        return std::nullopt;
    }
    // The arrival name lands in the Ldr node page (twice - BaseDllName
    // and FullDllName buffers), so its shape is checked BEFORE anything is
    // mapped or registered.
    std::u16string wide(pending->name.begin(), pending->name.end());
    const bool ascii_only =
        std::all_of(pending->name.begin(), pending->name.end(), [](const char c) {
            const auto b = static_cast<unsigned char>(c);
            return b >= 0x20 && b < 0x7F;
        });
    if (wide.empty() || wide.size() > 64 || !ascii_only || pending->name.size() != wide.size()) {
        return std::format("arrival name unsupported ({} chars, ASCII only)", pending->name.size());
    }

    const auto info = loader::parse_pe(pending->bytes);
    if (!info) {
        return std::string{"pending module is not a parseable PE"};
    }
    auto image = loader::build_image(pending->bytes, *info);
    if (!image) {
        return std::string{"pending module image construction failed"};
    }

    auto* const uc = state.uc;
    std::uint64_t base = info->image_base;
    if (!span_unmapped(uc, base, info->image_size)) {
        base = kDllSynthBaseBand;
        while (!span_unmapped(uc, base, info->image_size)) {
            base += 0x10000;
        }
    }
    const auto delta = base - info->image_base;
    if (const auto moved = loader::apply_relocations(*image, *info, delta); !moved) {
        return std::string{"pending module relocations failed"};
    }
    // IAT resolution needs the resident modules' full bytes: forwarder
    // detection reads the export directory, which a name index cannot see
    // (an empty-image view would bind forwarder-string RVAs as code).
    // Unresolved thunks are a named load failure BEFORE any mapping or
    // registration - a half-usable IAT must not enter sample init.
    const std::vector<loader::LoadedModule> no_modules;
    const auto& resolve_against =
        state.loaded_modules != nullptr ? *state.loaded_modules : no_modules;
    std::vector<loader::UnresolvedImport> unresolved;
    // Directory mode resolves through the explicit API Set context (the
    // directory's map restored with the run tables); the synthetic routes
    // keep the prefix rules. The pending DLL's own name drives
    // importer-conditional map entries.
    if (!loader::resolve_imports(*image, resolve_against, &unresolved, state.api_set_ctx,
                                 std::string_view(pending->name))
             .has_value()) {
        return std::string{"pending module import resolution failed"};
    }
    if (!unresolved.empty()) {
        return std::format("pending module import unresolved: {}!{}", unresolved.front().dll_name,
                           unresolved.front().function_name);
    }

    // Everything below mutates the world; a failure - or the guest's own
    // DllMain FALSE - unwinds through rollback_dll_load as one transaction.
    auto& load = state.dll_load;
    load.active = true;
    load.base = base;
    load.size = info->image_size;
    load.name = fold_name(pending->name);
    load.node_va = kDllNodePageVa;
    load.prev_sample_known = state.sample_module_known;
    load.prev_sample_index = state.sample_module_index;
    if (state.write_ledger != nullptr) {
        const auto [prev_base, prev_size] = state.write_ledger->sample_span();
        load.prev_sample_base = prev_base;
        load.prev_sample_size = prev_size;
    }

    if (uc_mem_map(uc, base, info->image_size, UC_PROT_ALL) != UC_ERR_OK) {
        rollback_dll_load(state);
        return std::string{"pending module mapping failed"};
    }
    load.image_mapped = true;
    if (uc_mem_write(uc, base, image->data(), image->size()) != UC_ERR_OK) {
        rollback_dll_load(state);
        return std::string{"pending module bytes could not be written"};
    }
    // The per-section protection pass was attempted and REVERTED.
    // UPX's crafted section tables (all-zero characteristics, bogus raw
    // pointers) make per-section derivation map the stub's own code/data
    // read-only, and the stub then faults before decompression - the
    // failure mode did not yield to a same-day root-cause. The whole-image
    // ERW accounting below is the pe-loader spec's documented shape for
    // such images; a faithful per-section scheme for hostile section tables
    // stays open.
    if (uc_mem_protect(uc, base, static_cast<std::size_t>(info->image_size),
                       UC_PROT_READ | UC_PROT_EXEC) != UC_ERR_OK) {
        rollback_dll_load(state);
        return std::string{"pending module write stripping failed"};
    }
    if (state.write_ledger != nullptr) {
        state.write_ledger->add_region(base, info->image_size, kPageExecuteReadwrite, kMemImage);
        load.ledger_bases.push_back(base);
        // The synthesized module IS the sample from here on: writer
        // attribution (sample-code test in the write-prot hook) follows.
        state.write_ledger->set_sample_span(base, info->image_size);
    }

    // Region-map module registration: the attribution layer (module!section)
    // and the sample identity ride on it. (No undo: region records are
    // append-only by design - a rolled-back module leaves a stale interval
    // over unmapped memory, recorded in the design's known limitations.)
    if (state.region_map != nullptr) {
        mem_region::ModuleImage module_image;
        module_image.module.base = base;
        module_image.module.size = info->image_size;
        const std::string folded = fold_name(pending->name);
        std::memcpy(module_image.module.name.data(), folded.c_str(),
                    (std::min)(folded.size(), module_image.module.name.size() - 1));
        module_image.header_bytes.assign(
            image->begin(), image->begin() + (std::min<std::size_t>(image->size(), 0x1000)));
        state.dll_load.module_index = state.region_map->register_module_image(module_image);
        if (state.module_sink) {
            state.module_sink(state.dll_load.module_index, module_image);
        }
    }

    // Ldr linkage: one node page in the engine band, inserted at the head of
    // all three lists (deterministic position, sample-first walk order).
    // The name is validated ASCII and <= 64 units up front; the staging
    // buffer is page-sized and the two name buffers sit at +0x80 / +0x200,
    // far enough apart that 64 units (+ NUL) cannot touch anything else.
    if (uc_mem_map(uc, kDllNodePageVa, 0x1000, UC_PROT_READ | UC_PROT_WRITE) != UC_ERR_OK) {
        rollback_dll_load(state);
        return std::string{"Ldr node page could not be mapped"};
    }
    load.node_mapped = true;
    {
        std::vector<std::uint8_t> node(0x1000, 0);
        const auto store8 = [&node](const std::uint64_t offset, const std::uint64_t value) {
            std::memcpy(node.data() + offset, &value, sizeof value);
        };
        const auto store2 = [&node](const std::uint64_t offset, const std::uint16_t value) {
            std::memcpy(node.data() + offset, &value, sizeof value);
        };
        store8(0x30, base);                                        // DllBase
        store8(0x38, base + info->entry_rva);                      // EntryPoint
        store8(0x40, info->image_size);                            // SizeOfImage
        const std::uint64_t base_name_va = kDllNodePageVa + 0x80;  // up to +0x1FF
        const std::uint64_t full_name_va = kDllNodePageVa + 0x200; // up to +0x37F
        // BaseDllName @0x58: Length u16, MaximumLength u16, Buffer u64.
        store2(0x58, static_cast<std::uint16_t>(wide.size() * 2));
        store2(0x5A, static_cast<std::uint16_t>(wide.size() * 2 + 2));
        store8(0x60, base_name_va);
        std::memcpy(node.data() + 0x80, wide.c_str(), wide.size() * 2 + 2);
        // FullDllName @0x48: the world has no filesystem path; the arrival
        // name stands in so standard walks read a consistent string.
        store2(0x48, static_cast<std::uint16_t>(wide.size() * 2));
        store2(0x4A, static_cast<std::uint16_t>(wide.size() * 2 + 2));
        store8(0x50, full_name_va);
        std::memcpy(node.data() + 0x200, wide.c_str(), wide.size() * 2 + 2);
        if (uc_mem_write(uc, kDllNodePageVa, node.data(), node.size()) != UC_ERR_OK) {
            rollback_dll_load(state);
            return std::string{"Ldr node could not be written"};
        }
    }
    const auto peb = read_u64(uc, state.teb_base + 0x60);     // x64: gs:[0x60]
    const auto ldr = peb != 0 ? read_u64(uc, peb + 0x18) : 0; // PEB.Ldr
    if (ldr == 0) {
        rollback_dll_load(state);
        return std::string{"guest Ldr is not reachable"};
    }
    const std::array offsets{kLdrInLoadOrderOffset, kLdrInMemoryOrderOffset, kLdrInInitOrderOffset};
    for (std::size_t i = 0; i < offsets.size(); ++i) {
        if (!link_after(uc, ldr + offsets[i], kDllNodePageVa + i * 0x10)) {
            rollback_dll_load(state);
            return std::string{"guest Ldr chains could not be linked"};
        }
        load.linked[i] = true;
    }

    // Loader tables: the module joins name lookup and export resolution
    // (GetProcAddress on the loaded sample must answer).
    {
        loader::LoadedModule self;
        self.base = base;
        self.image = *image;
        const std::string folded = fold_name(pending->name);
        std::memcpy(self.name.data(), folded.c_str(),
                    (std::min)(folded.size(), self.name.size() - 1));
        if (loader::index_exports(self).has_value()) {
            for (const auto& [name, va] : self.exports) {
                state.loader_exports.push_back({base, va, name});
            }
        }
        mem_region::ModuleRecord record;
        record.base = base;
        record.size = info->image_size;
        std::memcpy(record.name.data(), folded.c_str(),
                    (std::min)(folded.size(), record.name.size() - 1));
        state.loader_modules.push_back(record);
    }

    // Validate the complete relocated array before scheduling any callbacks.
    // The shared loader walk permits partial arrays; DLL initialization must
    // instead reject a missing terminator, including at the callback limit.
    std::vector<std::uint64_t> tls;
    if (info->tls_directory_rva != 0) {
        const auto directory = static_cast<std::size_t>(info->tls_directory_rva);
        if (directory > image->size() || image->size() - directory < 40) {
            rollback_dll_load(state);
            return std::string{"pending module TLS directory truncated"};
        }
        std::uint64_t array_va = 0;
        std::memcpy(&array_va, image->data() + directory + 0x18, sizeof array_va);
        // A NULL AddressOfCallBacks means there are no callbacks.
        if (array_va != 0) {
            if (array_va < base || array_va - base >= image->size()) {
                rollback_dll_load(state);
                return std::string{"pending module TLS array outside the module image"};
            }
            auto offset = static_cast<std::size_t>(array_va - base);
            for (;;) {
                if (image->size() - offset < sizeof(std::uint64_t)) {
                    rollback_dll_load(state);
                    return std::string{"pending module TLS array missing terminator"};
                }
                std::uint64_t callback = 0;
                std::memcpy(&callback, image->data() + offset, sizeof callback);
                if (callback == 0) {
                    break;
                }
                if (tls.size() == 64) {
                    rollback_dll_load(state);
                    return std::string{"pending module TLS callback limit exceeded"};
                }
                if (callback < base || callback - base >= image->size()) {
                    rollback_dll_load(state);
                    return std::string{"pending module TLS callback outside the module image"};
                }
                tls.push_back(callback);
                offset += sizeof callback;
            }
        }
    }

    state.dll_load.entered = true;
    state.dll_load.has_entry = info->entry_rva != 0;
    state.dll_load.entry = base + info->entry_rva;
    state.dll_load.tls_pending = std::move(tls);
    state.dll_load.tls_cursor = 0;
    state.dll_load.phase = SyscallRunState::DllLoadState::Phase::kIdle;
    // Sample identity moves to the synthesized module; the runner main
    // image is infrastructure from here on.
    state.sample_module_known = true;
    state.sample_module_index = state.dll_load.module_index;

    enter_next_frame(state);
    return std::nullopt;
}

void dll_load_resume(SyscallRunState& state)
{
    auto* const uc = state.uc;
    std::uint64_t rax = 0;
    uc_reg_read(uc, UC_X86_REG_RAX, &rax);

    // The phase decides what returned - a TLS callback's exit is void
    // (rax is garbage), only DllMain's verdict answers the load. Every
    // next frame rebuilds from the saved call base, so no stack leaks
    // between callbacks.
    if (state.dll_load.phase == SyscallRunState::DllLoadState::Phase::kTls) {
        enter_next_frame(state);
        uc_emu_stop(uc);
        return;
    }
    if (state.dll_load.phase != SyscallRunState::DllLoadState::Phase::kDllMain) {
        return; // out of place: nothing armed
    }

    // DllMain's verdict completes the LoadLibrary answer. The caller site is
    // restored verbatim - only rax (the handle or NULL) differs.
    const auto caller_rip = state.dll_load.caller_rip;
    const auto caller_rsp = state.dll_load.caller_rsp;
    if (rax != 0) {
        finish_dll_load(state, state.dll_load.base, true, caller_rip, caller_rsp);
        return;
    }

    // FALSE: one transaction unwind - unlink the Ldr node, unmap the
    // node page AND the image, drop the tables, remove the ledger's
    // per-section regions and restore the writer span - then answer NULL.
    // A later same-name request re-enters the full synthesis with no
    // residue (the probe's "retry fails on the mapped node page" and "dump
    // reads unmapped ledger addresses" both died here).
    rollback_dll_load(state);
    finish_dll_load(state, 0, false, caller_rip, caller_rsp);
}

} // namespace sheller::engine
