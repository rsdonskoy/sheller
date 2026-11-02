#include "engine_hooks.h"

#include "diag_trace.h"

#include <algorithm>
#include <array>
#include <format>
#include <string>
#include <vector>

namespace sheller::engine {
namespace {

// Deterministic base for guest runtime allocations: far
// below the captured image bases and page aligned. Collisions walk up by
// the allocation size, so the same replay walks the same sequence.
constexpr std::uint64_t kAllocationBaseStart = 0x7F0000000000ULL;

// GPR index order shared by the cycle detector's known-loop cache and the
// probe's brute force.
constexpr uc_x86_reg kLoopGprRegs[16] = {
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX, UC_X86_REG_RSP, UC_X86_REG_RBP,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15};
constexpr std::size_t kLoopRspIndex = 4;
// A remembered burn loop re-enters and is force-exited almost instantly.
constexpr std::uint64_t kKnownLoopFastBlocks = 512;

} // namespace

// Block hook of the syscall run: bumps the block counter and, when an event
// sink is attached, emits block-exec with the block start address (the hook
// address is the block start). Hot path: no allocation, no IO.
// Mem-write hook body: page-granular dirty marking over the snapshot
// regions. Hot path: one binary search, no allocation.
// Fault-based dirty tracking: writable regions are mapped
// without write permission, so the FIRST guest write to each page lands
// here. The ledger marks the page, the hook performs the store itself
// (returning true makes unicorn skip its own access) and re-grants write -
// one callback per page instead of per store.
bool on_mem_write_prot_callback(uc_engine* const uc, const uc_mem_type, const std::uint64_t address,
                                const std::uint32_t size, const std::int64_t, void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);
    auto* ledger = state->write_ledger;
    auto protection = ledger->writable_protection_at(address);
    if (protection == 0 && state->write_ledger != nullptr) {
        // A PAGE_GUARD|PAGE_READWRITE region on the guest stack is the
        // kernel's auto-commit stack — the first touch below the committed
        // limit commits the page silently (no STATUS_GUARD_PAGE to the user
        // for the thread's own stack). Clear the guard and grant the write.
        if (const auto region = state->write_ledger->find_region(address);
            region.has_value() && (region->protection & engine::kPageGuard) != 0 &&
            (region->protection & engine::kPageReadwrite) != 0) {
            state->write_ledger->set_writable(region->base, region->size);
            protection = engine::kPageReadwrite;
        }
    }
    if (protection == 0) {
        if (const auto region = state->write_ledger->find_region(address); region.has_value()) {
            sheller::log::warning(std::format(
                "write-prot: untracked write at 0x{:x} (region 0x{:x} prot=0x{:x} writable={})",
                address, region->base, region->protection, region->writable));
        } else {
            sheller::log::warning(
                std::format("write-prot: untracked write at 0x{:x} (no region)", address));
        }
        return false; // read-only or untracked: the invalid-write path applies
    }
    // Writer attribution: only writes by the sample's own code (its image
    // or private-executable memory) dirty the ledger; system-module writes
    // (dispatch, heap machinery) are infrastructure. The same verdict rides
    // the fact so the report can keep infrastructure writes out of the
    // default detail column.
    const bool sample_writer = ledger->writer_is_sample_code(read_rip(uc));
    if (sample_writer) {
        ledger->on_write(address, size);
    }
    if (state->behavior_sink) {
        BehaviorFact fact;
        fact.kind = BehaviorFact::Kind::kMemWrite;
        fact.pc = read_rip(uc);
        fact.addr = address;
        fact.size = size;
        fact.writer_sample_code = sample_writer;
        state->behavior_sink(fact);
    }
    // Defer the permission grant to the run loop: mutating mappings from
    // inside a memory hook is unsafe. The store itself is skipped here and
    // re-executed natively after the re-entry (the page is writable then).
    // The grant ORs write onto the captured perms: the ledger keeps the
    // captured protection (the dump manifest records it), so a protect-
    // flipped read-only page - an unpacking stub restoring its PE header -
    // derives R-only here and the retried store would fault forever.
    const std::uint64_t first_page = address & ~(kLedgerPageSize - 1);
    const std::uint64_t last_page = (address + size - 1) & ~(kLedgerPageSize - 1);
    for (auto page = first_page; page <= last_page; page += kLedgerPageSize) {
        state->pending_write_grants.push_back(
            {page, static_cast<std::uint32_t>(protection_to_perms(protection) | UC_PROT_WRITE)});
    }
    state->write_prot_resume = true;
    uc_emu_stop(uc);
    return true;
}
// Block hook of the syscall run: bumps the block counter and, when an event
// sink is attached, emits block-exec with the block start address (the hook
// address is the block start). Hot path: no allocation, no IO.
void on_boundary_trap(uc_engine* uc, const std::uint64_t address, const std::uint32_t,
                      void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);
    if (state->boundary_trap.fired) {
        return;
    }
    auto& diagnosis = state->boundary_trap;
    diagnosis.fired = true;
    diagnosis.va = address;
    const auto named = state->boundary_trap_names.find(address);
    if (named != state->boundary_trap_names.end()) {
        diagnosis.module = std::get<0>(named->second);
        diagnosis.name = std::get<1>(named->second);
        diagnosis.ordinal = std::get<2>(named->second);
    }
    std::uint64_t caller = 0;
    static_cast<void>(uc_mem_read(uc, read_rsp(uc), &caller, sizeof caller));
    diagnosis.caller = caller;
    // the deliberate stop: not a crash, not a completed call - the caller's
    // successor instructions never execute
    state->terminated = false;
    state->exit_code = 0;
    uc_emu_stop(uc);
}

void on_syscall_run_block(uc_engine* uc, const std::uint64_t address, const std::uint32_t,
                          void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);
    ++state->blocks;
    state->last_block_address = address;

    // Burn-loop cycle detection: a block already inside the recent-cycle
    // ring extends the run; a new address shifts the ring. The syscall path
    // resets the run (a side effect = real behavior). Reaching the trigger
    // stops the leg so the decoder-free probe runs between legs.
    bool in_ring = false;
    for (std::size_t i = 0; i < state->hot_ring_len; ++i) {
        if (state->hot_ring[i] == address) {
            in_ring = true;
            break;
        }
    }
    if (in_ring) {
        ++state->hot_run;
    } else {
        for (std::size_t j = 7; j > 0; --j) {
            state->hot_ring[j] = state->hot_ring[j - 1];
        }
        state->hot_ring[0] = address;
        if (state->hot_ring_len < std::size(state->hot_ring)) {
            ++state->hot_ring_len;
        }
        state->hot_run = 1;
    }
    // A remembered burn loop re-entering: apply its exit state right here -
    // the block re-executes with the counter at its exit value and the
    // branch falls through, costing nothing.
    if (state->hot_run >= kKnownLoopFastBlocks) {
        if (const auto it = state->known_burn_loops.find(address);
            it != state->known_burn_loops.end()) {
            const auto exit_value = it->second.second;
            uc_reg_write(uc, kLoopGprRegs[it->second.first], &exit_value);
            state->hot_run = 0;
            return;
        }
    }
    if (state->hot_run >= state->hot_trigger && !state->loop_probe_pending) {
        state->loop_probe_pending = true;
        uc_emu_stop(uc);
    }

    // Diagnostic entry watch: a block start
    // landing exactly on a watched entry fires the diagnostic callback.
    if (state->diag_watch_entries != nullptr && !state->diag_watch_entries->empty() &&
        state->diag_entry_hit) {
        if (std::binary_search(state->diag_watch_entries->begin(), state->diag_watch_entries->end(),
                               address)) {
            state->diag_entry_hit(address, uc);
        }
    }

    // Execution transfer: a block landing in a different
    // attribution identity than the previous block is a candidate; the
    // edge rules decide. Only sample-territory pairs emit - sample image
    // section -> sample image section, sample image -> sample-allocated
    // memory, sample-allocated memory -> sample image. System-module
    // crossings in both directions, allocation-to-allocation hops, and
    // entries into system-issued (infrastructure) memory stay silent: xfer
    // is the OEP-jump signal, not an API-call trace. Hot path: one map
    // query, no allocation, no IO. The tracking opens for the consumers
    // that stop on it: an event sink, a nonzero xfer ordinal, or the
    // esp+xfer goal (which sets the ordinal only when its restore confirms,
    // so the gate must already be open when the source block runs - an
    // identity the gate skipped is a transition it can never count). The
    // esp hit form keeps the gate closed: nothing in it reads xfers.
    if (state->region_map != nullptr && (state->event_sink || state->xfer_number != 0 ||
                                         state->esp_stop_goal == EspStopGoal::kArmThenNextXfer)) {
        const auto attribution = state->region_map->query(address);
        if (attribution.has_value()) {
            const auto previous_identity = state->last_identity;
            const auto previous_territory = state->last_territory;
            const bool previous_valid = state->last_identity_valid;
            state->last_identity = attribution->identity;
            state->last_territory = mem_region::xfer_territory(
                *attribution, state->sample_module_known ? state->sample_module_index
                                                         : mem_region::kNoModuleIndex);
            state->last_identity_valid = true;
            if (previous_valid &&
                mem_region::is_xfer_transition(previous_identity, attribution->identity) &&
                mem_region::is_xfer_edge(previous_territory, state->last_territory)) {
                // Counting ignores the burn-loop probe: its speculative
                // chunks re-enter this hook from a restored register file and
                // may be rolled back afterwards. The stop below keys off this
                // count, so it inherits the same exclusion without a second
                // guard.
                if (!state->loop_probe_pending) {
                    ++state->xfers;
                }
                if (state->event_sink) {
                    const auto [from_module, from_section] =
                        mem_region::xfer_payload_slots(previous_identity);
                    const auto [to_module, to_section] =
                        mem_region::xfer_payload_slots(attribution->identity);
                    std::array<std::uint8_t, 8> fields{};
                    le::store_le16(fields.data(), from_module);
                    le::store_le16(fields.data() + 2, from_section);
                    le::store_le16(fields.data() + 4, to_module);
                    le::store_le16(fields.data() + 6, to_section);
                    const EventPreamble preamble{
                        .seq = 0, .tid = state->current_tid, .pc = address};
                    state->event_sink(EventTypeId::kXfer, preamble, fields);
                }
                if (state->xfer_number != 0 && state->xfers == state->xfer_number) {
                    state->xfer_stop_reached = true;
                    uc_emu_stop(uc);
                }
            }
        }
    }

    // Block-count budget: deterministic stop once the block
    // budget is exhausted, counting the block that just started.
    if (state->max_blocks != 0 && state->blocks >= state->max_blocks) {
        uc_emu_stop(uc);
    }

    if (!state->event_sink) {
        return;
    }
    std::array<std::uint8_t, sizeof(std::uint64_t)> fields{};
    le::store_le64(fields.data(), address);
    const EventPreamble preamble{.seq = 0, .tid = state->current_tid, .pc = address};
    state->event_sink(EventTypeId::kBlockExec, preamble, fields);
}

// Issuer attribution of one allocation/protect (direct-issuance, the write
// ledger's rule applied to the alloc seams): the allocation is the sample's
// own action when the syscall's stack carries a return address in sample
// territory - the sample image or an already-registered sample region. The
// syscall's direct caller is the ntdll stub and one frame up sits
// kernelbase, so the scan walks a bounded window of stack slots looking for
// the issuing frame (sample -> kernel32 -> kernelbase -> stub is three
// returns deep in the classic unpacker chain). No sample-side frame in the
// window means system-issued machinery (CRT/CLR JIT): infrastructure -
// mapped and answered, but event-silent (no runtime sentinel, no arming,
// no signals).
bool stack_carries_sample_frame(uc_engine* const uc, const std::uint64_t rsp, const bool x64,
                                const mem_region::MemRegionMap* region_map,
                                const SyscallRunState& state)
{
    constexpr std::uint64_t kCallerScanSlots = 64;
    const auto sample_index =
        state.sample_module_known ? state.sample_module_index : mem_region::kNoModuleIndex;
    const std::uint64_t slot_size = x64 ? 8 : 4;
    for (std::uint64_t slot = 0; slot < kCallerScanSlots; ++slot) {
        const std::uint64_t addr = rsp + slot * slot_size;
        std::uint64_t value = 0;
        if (x64) {
            value = read_guest_u64(uc, addr);
        } else {
            value = read_guest_u32(uc, addr);
        }
        if (value == 0) {
            continue;
        }
        const auto attr = region_map->query(value);
        if (!attr.has_value()) {
            continue;
        }
        if (attr->runtime_registered) {
            return true; // chained from sample-issued memory (shellcode allocates)
        }
        if (attr->kind != mem_region::AttributionKind::kRegion &&
            attr->module_index == sample_index) {
            return true; // the issuing frame is the sample image
        }
    }
    return false;
}

bool allocation_sample_issued(uc_engine* const uc, const syscalls::SyscallFrame& frame,
                              const mem_region::MemRegionMap* region_map,
                              const SyscallRunState& state)
{
    if (region_map == nullptr) {
        return true; // no map attached: legacy behavior, nothing to classify
    }
    return stack_carries_sample_frame(uc, frame.rsp, state.guest_mode == GuestMode::kX64,
                                      region_map, state);
}

void apply_guest_allocation(uc_engine* const uc, const syscalls::SyscallFrame& frame,
                            syscalls::SyscallOutcome& outcome, SyscallRunState& state,
                            const bool sample_issued)
{
    auto* const ledger = state.write_ledger;
    auto* const region_map = state.region_map;
    auto base = outcome.map_base != 0 ? outcome.map_base : kAllocationBaseStart;
    // Record and honor the requested protection: the shellcode pattern
    // allocates PAGE_EXECUTE_* and jumps straight in, and a fetch fault on a
    // fresh allocation has no handler to claim it. The ledger keeps the true
    // value so the write-prot grant preserves the execute bit; the unicorn
    // mapping stays non-writable so the fault-based dirty tracking still sees
    // the first write.
    const auto protection =
        outcome.alloc_protection != 0 ? outcome.alloc_protection : kPageReadWrite;
    const auto perms = protection_to_perms(protection) & ~UC_PROT_WRITE;
    for (int attempt = 0; attempt < 64; ++attempt) {
        if (uc_mem_map(uc, base, outcome.map_size, perms) == UC_ERR_OK) {
            const std::uint64_t mapped_base = base;
            uc_mem_write(uc, frame.rdx, &mapped_base, sizeof mapped_base);
            uc_mem_write(uc, frame.r9, &outcome.map_size, sizeof outcome.map_size);
            ledger->add_region(base, outcome.map_size, protection, kMemPrivate);
            // The allocation joins the attribution map when sample-issued:
            // xfer sees the landing, protection flips carve it, MBI answers
            // commit. Infrastructure allocations map and answer only.
            if (region_map != nullptr) {
                region_map->register_region(base, outcome.map_size, protection, kMemPrivate,
                                            sample_issued);
            }
            return;
        }
        base += outcome.map_size;
    }
    outcome.status = kStatusNoMemory; // no deterministic slot: answered, not crashed
}

// Behavior monitored-window callbacks: pure-data facts out of the
// engine hooks - the read value and the instruction bytes are read here, in
// the hook context, so the behavior layer never touches unicorn.
// Registered only when a behavior consumer is attached.
void on_behavior_mem_read(uc_engine* const uc, const uc_mem_type, const std::uint64_t address,
                          const std::uint32_t size, const std::int64_t, void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);
    if (!state->behavior_sink) {
        return;
    }
    // Reader attribution, sample-origin only: reads by any module other
    // than the sample image are that module's internals reacting to a
    // sample call - LdrLoadDll walking InLoadOrderModuleList is not the
    // sample walking the PEB. Readers without a module attribution and
    // readers in runtime-registered regions (the registered shellcode/
    // payload allocations) sit in sample-controlled memory and are
    // recorded; snapshot-captured non-sample regions stay dropped.
    const auto rip = read_rip(uc);
    if (state->sample_module_known && state->region_map != nullptr) {
        const auto attribution = state->region_map->query(rip);
        if (attribution.has_value() && attribution->module_index != state->sample_module_index &&
            !attribution->runtime_registered) {
            return;
        }
    }
    BehaviorFact fact;
    fact.kind = BehaviorFact::Kind::kMemRead;
    fact.pc = rip;
    fact.addr = address;
    fact.size = size;
    fact.aux = 0;
    uc_mem_read(uc, address, &fact.aux, size);
    state->behavior_sink(fact);
}

void on_behavior_code(uc_engine* const uc, const std::uint64_t address, const std::uint32_t size,
                      void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);
    if (!state->behavior_sink) {
        return;
    }
    BehaviorFact fact;
    fact.kind = BehaviorFact::Kind::kCode;
    fact.pc = address;
    fact.length = static_cast<std::uint8_t>(size < fact.bytes.size() ? size : fact.bytes.size());
    if (uc_mem_read(uc, address, fact.bytes.data(), fact.length) != UC_ERR_OK) {
        return;
    }
    state->behavior_sink(fact);
}

// Per-write window watch: unicorn calls this
// on every store inside the hook's range, before the store lands - the
// value parameter carries the written data (narrow stores). Void return:
// the store proceeds untouched.
void on_diag_write_window(uc_engine* const uc, const uc_mem_type, const std::uint64_t address,
                          const std::uint32_t size, const std::int64_t value, void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);
    if (!state->diag_write_hit) {
        return;
    }
    state->diag_write_hit(read_rip(uc), address, size, static_cast<std::uint64_t>(value));
}

// Diagnostic code-window watch: unicorn calls this for every instruction
// executed inside the hook's range. Void return: execution proceeds.
void on_diag_code_window(uc_engine* const uc, const std::uint64_t address, const std::uint32_t,
                         void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);
    if (!state->diag_code_hit) {
        return;
    }
    state->diag_code_hit(address, uc);
}

// rdtsc environment semantics: the fixed-delta clock reads
// identically every time - consecutive reads differing by zero is itself
// the tell - plus the rdtsc event for the behavior burst counter.
bool on_rdtsc_callback(uc_engine* const uc, void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);
    // Loop-gate evidence bit: the probe reads this to reject clock-fed
    // cycles from native admission. Pure bookkeeping - no event change.
    state->probe_insn_fired = true;
    // Deterministic virtual TSC: advanced by executed instructions (the leg
    // loop), so rdtsc-based delay waits complete in bounded emulation time
    // and replays stay host-independent (the host TSC leaked through before).
    const std::uint64_t tsc = state->virtual_tsc;
    // uc_reg_write reads the full register width from the buffer, so both
    // halves are zero-extended u64s - a u32 local makes unicorn pull adjacent
    // host stack into the guest-visible high half (per-process entropy).
    const std::uint64_t low = tsc & 0xFFFFFFFF;
    const std::uint64_t high = tsc >> 32;
    uc_reg_write(uc, UC_X86_REG_RAX, &low);
    uc_reg_write(uc, UC_X86_REG_RDX, &high);
    if (state->event_sink) {
        const EventPreamble preamble{.seq = 0, .tid = state->current_tid, .pc = read_rip(uc)};
        state->event_sink(EventTypeId::kRdtsc, preamble, {});
    }
    return true;
}

// RDTSCP shares the virtual TSC; ECX reads TSC_AUX (zero - the deterministic
// system has no AUX seed). Without this hook RDTSCP executes natively and
// leaks the host counter through.
bool on_rdtscp_callback(uc_engine* const uc, void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);
    state->probe_insn_fired = true; // loop-gate evidence, see on_rdtsc_callback
    const std::uint64_t tsc = state->virtual_tsc;
    const std::uint64_t low = tsc & 0xFFFFFFFF;
    const std::uint64_t high = tsc >> 32;
    const std::uint64_t aux = 0;
    uc_reg_write(uc, UC_X86_REG_RAX, &low);
    uc_reg_write(uc, UC_X86_REG_RDX, &high);
    uc_reg_write(uc, UC_X86_REG_RCX, &aux);
    if (state->event_sink) {
        const EventPreamble preamble{.seq = 0, .tid = state->current_tid, .pc = read_rip(uc)};
        state->event_sink(EventTypeId::kRdtsc, preamble, {});
    }
    return true;
}

// -- burn-loop fast-forward ------------------------------------------------------

namespace {

struct WriteJournal {
    // (address, size, bytes before the write) per guest write this cycle
    std::vector<std::array<std::uint8_t, 8>> before{};
    std::vector<std::pair<std::uint64_t, std::uint32_t>> sites{};
    bool any{};
};

void on_probe_write(uc_engine* uc, const uc_mem_type, const std::uint64_t address,
                    const std::uint32_t size, const std::int64_t, void* const user_data)
{
    auto* journal = static_cast<WriteJournal*>(user_data);
    journal->any = true;
    std::array<std::uint8_t, 8> bytes{};
    const auto width = size < 8 ? size : 8;
    if (uc_mem_read(uc, address, bytes.data(), width) == UC_ERR_OK) {
        journal->before.push_back(bytes);
    } else {
        journal->before.push_back({});
    }
    journal->sites.emplace_back(address, size);
}

// Probe-local read log: a read from the deterministic shared time page marks
// the cycle clock-sensitive even when its static bytes look clean. Hook is
// registered with the write journal for the one probe cycle and deleted with
// it.
struct ProbeReadLog {
    bool kusd_read{};
};

void on_probe_read(uc_engine*, const uc_mem_type, const std::uint64_t address, const std::uint32_t,
                   const std::int64_t, void* const user_data)
{
    static_cast<ProbeReadLog*>(user_data)->kusd_read |=
        address >= kLoaderKUser && address < kLoaderKUser + 0x1000;
}

// Byte reader for the gate's static scan: uc_mem_read fails wholesale when
// the request straddles a mapping edge, so walk the length down - the gate
// only needs the bytes its instructions actually occupy.
std::size_t probe_read_bytes(void* const context, const std::uint64_t va, std::uint8_t* const out,
                             const std::size_t size)
{
    auto* uc = static_cast<uc_engine*>(context);
    for (std::size_t take = size; take > 0; --take) {
        if (uc_mem_read(uc, va, out, take) == UC_ERR_OK) {
            return take;
        }
    }
    return 0;
}

bool journal_hit_loop_bytes(const WriteJournal& journal, const native_gate::GateVerdict& verdict)
{
    for (const auto& [address, size] : journal.sites) {
        for (std::size_t e = 0; e < verdict.extent_count; ++e) {
            if (address < verdict.extents[e].end && verdict.extents[e].start < address + size) {
                return true; // self-modification observed in the probe cycle
            }
        }
    }
    return false;
}

bool exit_observed(const native_gate::GateVerdict& verdict, const std::uint64_t rip)
{
    for (std::size_t i = 0; i < verdict.exit_target_count; ++i) {
        if (verdict.exit_targets[i] == rip) {
            return true;
        }
    }
    return false;
}

bool in_cycle_set(const SyscallRunState& state, const std::uint64_t rip)
{
    for (std::size_t i = 0; i < state.hot_ring_len; ++i) {
        if (state.hot_ring[i] == rip) {
            return true;
        }
    }
    return false;
}

// Trial hook: stop on the first instruction that is a static loop exit. The
// hot ring is a sliding window and can hold the enclosing loop's blocks, so
// a fall-through into that enclosing loop reads as "still in the cycle" and
// never leaves the ring. The gate's exit targets are the transfers out of
// the scanned set; landing on one is the natural post-loop path.
struct TrialExit {
    const native_gate::GateVerdict* verdict{};
    bool left{};
    std::uint64_t address{};
};

void on_trial_code(uc_engine* const uc, const std::uint64_t address, const std::uint32_t,
                   void* const user_data)
{
    auto* trial = static_cast<TrialExit*>(user_data);
    if (exit_observed(*trial->verdict, address)) {
        trial->left = true;
        trial->address = address;
        uc_emu_stop(uc);
    }
}

} // namespace

void run_loop_probe(SyscallRunState& state, uc_engine* uc)
{
    constexpr std::size_t kGprCount = 16;
    constexpr std::uint32_t kProbeChunk = 16;
    constexpr std::uint32_t kProbeMaxSteps = 512;

    const std::uint64_t start_rip = read_rip(uc);
    // The block hook that stopped the leg; the known-loop cache must key on a
    // block the hook actually sees again (direct chaining can skip others).
    // The ring count at the stop is the skip's report aux - the probe's own
    // emulation moves hot_run before the fact is emitted.
    const std::uint64_t detection_block = state.last_block_address;
    const std::uint64_t trigger_count = state.hot_run;

    // 1. snapshot the register file
    std::array<std::uint64_t, kGprCount> saved{};
    for (std::size_t i = 0; i < kGprCount; ++i) {
        uc_reg_read(uc, kLoopGprRegs[i], &saved[i]);
    }

    // 2. emulate one cycle under a full write journal and a read log
    state.probe_insn_fired = false; // gate evidence window: this cycle only
    WriteJournal journal;
    ProbeReadLog reads;
    uc_hook write_hook = 0;
    if (uc_hook_add(uc, &write_hook, UC_HOOK_MEM_WRITE, reinterpret_cast<void*>(on_probe_write),
                    &journal, 1, 0) != UC_ERR_OK) {
        state.hot_run = 0;
        return;
    }
    uc_hook read_hook = 0;
    if (uc_hook_add(uc, &read_hook, UC_HOOK_MEM_READ, reinterpret_cast<void*>(on_probe_read),
                    &reads, 1, 0) != UC_ERR_OK) {
        uc_hook_del(uc, write_hook);
        state.hot_run = 0;
        return;
    }
    auto rip = start_rip;
    std::uint32_t steps = 0;
    while (steps < kProbeMaxSteps) {
        uc_emu_start(uc, rip, 0, 0, kProbeChunk);
        rip = read_rip(uc);
        steps += kProbeChunk;
        if (steps >= kProbeChunk && in_cycle_set(state, rip)) {
            break; // one full cycle emulated, back at a cycle block
        }
    }
    uc_hook_del(uc, read_hook);
    uc_hook_del(uc, write_hook);

    // 2b. gate verdict: static closed-CFG scan over the ring's blocks, then
    // the probe's dynamic evidence downgrades what the bytes alone cannot
    // see. Pure bookkeeping in this slice - every path below keeps the
    // pre-gate behavior byte-identical; the ledger only decides what the
    // trace prints and what the go/no-go report counts.
    native_gate::GateVerdict verdict =
        native_gate::scan(state.hot_ring, state.hot_ring_len,
                          state.guest_mode == GuestMode::kX64 ? native_gate::MachineMode::kX64
                                                              : native_gate::MachineMode::kX86,
                          probe_read_bytes, uc);
    const auto downgrade = [&verdict](const native_gate::RejectReason reason) {
        verdict = native_gate::GateVerdict{};
        verdict.reason = reason;
    };
    if (!native_gate::rejected(verdict)) {
        // Register-indirect stores are unresolvable statically; the journal
        // saw exactly where the cycle's writes landed.
        if (journal_hit_loop_bytes(journal, verdict)) {
            downgrade(native_gate::RejectReason::kSelfWrite);
        } else if (reads.kusd_read) {
            downgrade(native_gate::RejectReason::kClockSensitiveRead);
        } else if (state.probe_insn_fired) {
            downgrade(native_gate::RejectReason::kHookSensitiveInsn);
        } else if (journal.any) {
            verdict.category = native_gate::Verdict::kAdmitCompute;
        }
    }
    const auto record = [&state, &journal, start_rip](const native_gate::GateVerdict& v) {
        ++state.loop_gate_counts[native_gate::verdict_slot(v)];
        if (diag::wanted(sheller::log::level::kDebug, state.loop_gate_trace)) {
            // One record per window. The line was assembled from several partial
            // writes precisely because it is one line, and a window summary split
            // across seven records would interleave with everything else the host's
            // sink is handed. Rendering happens inside the test above, so a disabled
            // trace pays a bool and allocates nothing.
            std::string line =
                std::format("[loop-gate] window@{:x} blocks={} [", start_rip, state.hot_ring_len);
            for (std::size_t i = 0; i < state.hot_ring_len; ++i) {
                line += std::format("{:s}{:x}", i == 0 ? "" : ",", state.hot_ring[i]);
            }
            line += std::format("] writes={} verdict={}", journal.sites.size(),
                                native_gate::verdict_name(v.category));
            if (native_gate::rejected(v)) {
                line += std::format(" reason={}", native_gate::reject_reason_name(v.reason));
            }
            line += std::format(" exits={} [", v.exit_target_count);
            for (std::size_t i = 0; i < v.exit_target_count; ++i) {
                line += std::format("{:s}{:x}", i == 0 ? "" : ",", v.exit_targets[i]);
            }
            line += "]";
            sheller::log::write(sheller::log::level::kDebug, line);
        }
    };

    if (journal.any) {
        record(verdict);
        // Real computation (the rolling-decryptor class writes its output):
        // re-arm further out and continue from the advanced state untouched.
        state.hot_trigger = (std::min)(state.hot_trigger * 4, std::uint64_t{1} << 32);
        state.hot_run = 0;
        return;
    }

    // 3. zero-write cycle: pure-counter delay. Force the natural exit by
    // setting each changed GPR to the loop-exit value; the cycle's own
    // branch then falls through with a consistent register file. The trial
    // stops at the first static exit target: the hot ring can still carry
    // the enclosing loop's blocks, so "left the ring" misreads the fall-out
    // of a nested loop. Without a static exit set the pre-gate ring check
    // stays the fallback.
    bool exited = false;
    std::uint64_t exit_pc = 0;
    TrialExit trial;
    trial.verdict = &verdict;
    uc_hook trial_hook = 0;
    if (verdict.exit_target_count != 0 &&
        uc_hook_add(uc, &trial_hook, UC_HOOK_CODE, reinterpret_cast<void*>(on_trial_code), &trial,
                    1, 0) != UC_ERR_OK) {
        trial_hook = 0;
    }
    const bool static_exits = trial_hook != 0;

    std::array<std::uint64_t, kGprCount> delta{};
    for (std::size_t i = 0; i < kGprCount; ++i) {
        uc_reg_read(uc, kLoopGprRegs[i], &delta[i]);
        delta[i] -= saved[i];
    }
    for (std::size_t i = 0; i < kGprCount && !exited; ++i) {
        if (i == kLoopRspIndex || delta[i] == 0) {
            continue; // stack frame and untouched registers are not the counter
        }
        for (const std::uint64_t candidate : {std::uint64_t{1}, std::uint64_t{0}}) {
            for (std::size_t k = 0; k < kGprCount; ++k) {
                uc_reg_write(uc, kLoopGprRegs[k], &saved[k]);
            }
            const auto exit_value = candidate;
            uc_reg_write(uc, kLoopGprRegs[i], &exit_value);
            trial.left = false;
            trial.address = 0;
            uc_emu_start(uc, start_rip, 0, 0, 128);
            const auto reached_exit =
                static_exits ? trial.left : !in_cycle_set(state, read_rip(uc));
            if (reached_exit) {
                exited = true;
                exit_pc = static_exits ? trial.address : read_rip(uc);
                // Key by the block whose hook triggered this probe: direct
                // chaining can skip other blocks, so a key the hook never
                // re-enters would never apply the cached exit.
                state.known_burn_loops[detection_block] = {static_cast<std::uint32_t>(i),
                                                           exit_value};
                break;
            }
        }
    }
    if (trial_hook != 0) {
        uc_hook_del(uc, trial_hook);
    }
    if (exited) {
        // Cross-validation: the force-exit experiment's observed fall-out
        // must be one of the static scan's exits. A mismatch means the bytes
        // or the decode disagree with the executed shape - closure escape.
        if (!native_gate::rejected(verdict) && !exit_observed(verdict, exit_pc)) {
            downgrade(native_gate::RejectReason::kClosureEscape);
        }
        record(verdict);
        if (state.behavior_sink) {
            BehaviorFact fact;
            fact.kind = BehaviorFact::Kind::kLoopSkip;
            fact.pc = start_rip;
            fact.aux = trigger_count;
            state.behavior_sink(fact);
        }
        state.hot_run = 0;
        return; // keep the exited state: the natural post-loop path runs on
    }

    // Not exitable by register state (the counter feeds from a source the
    // cycle recomputes): re-arm further out. The virtual clock covers the
    // clock-fed shapes; the pure-counter shapes exit above.
    record(verdict);
    for (std::size_t k = 0; k < kGprCount; ++k) {
        uc_reg_write(uc, kLoopGprRegs[k], &saved[k]);
    }
    write_rip(uc, start_rip);
    state.hot_trigger = (std::min)(state.hot_trigger * 4, std::uint64_t{1} << 32);
    state.hot_run = 0;
}

// CPUID feature masking (full emulation over an honest
// environment). Unicorn 2.x's TCG (QEMU 5 base) cannot translate the VEX
// encodings behind AVX/AVX2 - executing them lands in the single-
// instruction AVX shim below. The hook reports a TCG-complete Intel
// baseline instead: SSE4.2-class features, no AVX / XSAVE family, no
// hypervisor leaf. Runtime CPUID consumers (unpacking stubs, shellcode,
// feature-gated code) then stay on translatable paths, and the results are
// host-independent. Dispatch decided before the capture - ntdll resolves
// its AVX2 routines during process init, outside this run - is untouched.
// Registers hold 32-bit results; unicorn skips the two-byte instruction
// when the hook returns true.
bool on_cpuid_callback(uc_engine* const uc, void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);
    state->probe_insn_fired = true; // loop-gate evidence: environment-fed cycle
    std::uint64_t leaf = 0;
    std::uint64_t subleaf = 0;
    uc_reg_read(uc, UC_X86_REG_RAX, &leaf);
    uc_reg_read(uc, UC_X86_REG_RCX, &subleaf);
    std::uint32_t eax = 0;
    std::uint32_t ebx = 0;
    std::uint32_t ecx = 0;
    std::uint32_t edx = 0;
    switch (static_cast<std::uint32_t>(leaf)) {
    case 0: // max leaf plus the GenuineIntel vendor string
        eax = 7;
        ebx = 0x756E6547; // "uneG"
        edx = 0x49656E69; // "Ieni"
        ecx = 0x6C65746E; // "letn"
        break;
    case 1: // family 6 model 0x3C: SSE4.2 baseline, no FMA/XSAVE/OSXSAVE/AVX
        eax = 0x000306C3;
        ebx = 0x00000800; // CLFLUSH line 64 bytes, APIC id 0
        ecx = 0x02982203; // SSE3 PCLMULQDQ SSSE3 CX16 SSE4.1 SSE4.2 POPCNT AES
        edx = 0xBFEBFBFF; // FPU..SSE2 HTT, the classic baseline mask
        break;
    case 7: // structured extended features: none (no AVX2/BMI/FSGSBASE family)
        if (static_cast<std::uint32_t>(subleaf) == 0) {
            eax = 0; // no further subleaves
        }
        break;
    case 0x80000000: // extended limit
        eax = 0x80000001;
        break;
    case 0x80000001: // long mode, syscall, NX; no extended features
        // x86 guests must not see long mode (EDX bit 29) - the wow64 CPUID
        // contract stops at SSE3-class features plus syscall/NX
        edx = state->guest_mode == GuestMode::kX86 ? 0x00100800 : 0x20100800;
        break;
    default: // every other leaf: absent
        break;
    }
    uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    uc_reg_write(uc, UC_X86_REG_EBX, &ebx);
    uc_reg_write(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &edx);
    if (state->event_sink) {
        const EventPreamble preamble{.seq = 0, .tid = state->current_tid, .pc = read_rip(uc)};
        state->event_sink(EventTypeId::kCpuid, preamble, {});
    }
    if (state->behavior_sink) {
        BehaviorFact fact;
        fact.kind = BehaviorFact::Kind::kCpuidLeaf;
        fact.aux = static_cast<std::uint32_t>(leaf);
        state->behavior_sink(fact);
    }
    return true;
}

// TEB switch: x64 rewrites GS_BASE; x86 swaps the live FS descriptor
// base on the pinned GDT page and reloads the selector (the descriptor is
// cached at selector-load time, so memory-only edits do not take effect).
void apply_teb_switch(uc_engine* const uc, const GuestMode mode, const std::uint64_t teb_base)
{
    if (mode == GuestMode::kX64) {
        uc_reg_write(uc, UC_X86_REG_GS_BASE, &teb_base);
        return;
    }
    std::array<std::uint8_t, 8> desc{};
    desc[0] = 0xFF;
    desc[1] = 0xFF;
    desc[2] = static_cast<std::uint8_t>(teb_base & 0xFF);
    desc[3] = static_cast<std::uint8_t>((teb_base >> 8) & 0xFF);
    desc[4] = static_cast<std::uint8_t>((teb_base >> 16) & 0xFF);
    desc[5] = 0x92; // data segment, writable, present
    desc[6] = 0xCF; // 4K granularity, 32-bit (B), limit high 0xF
    desc[7] = static_cast<std::uint8_t>((teb_base >> 24) & 0xFF);
    uc_mem_write(uc, kX86GdtBase + 8, desc.data(), desc.size()); // entry 1 = FS
    const std::uint16_t fs_selector = 0x08;
    uc_reg_write(uc, UC_X86_REG_FS, &fs_selector);
}

// Thread creation (NtCreateThreadEx engine side): reserve a TEB page
// plus a stack from the deterministic bump, initialize the TEB from the
// main thread's (PEB pointer copied, own stack/self/tid fields), then build
// the new thread's starting register state with the save-hijack-save dance.
// The resume RIP is the start routine; the x86 entry convention is
// [esp] = null return, [esp+4] = argument (stdcall start, must terminate
// via NtTerminateThread - a synthetic thread has no return target).
// resume_rip: where the CALLING thread continues (x64 syscall = rip+2; x86
// int 2e = the hook-time rip, which unicorn already advanced past the int).
void apply_thread_creation(SyscallRunState* state, uc_engine* const uc,
                           const syscalls::SyscallFrame& frame, syscalls::SyscallOutcome& outcome,
                           const std::uint64_t resume_rip)
{
    auto& sched = state->scheduler;
    constexpr std::uint64_t kThreadStackSize = 0x40000;
    constexpr std::uint64_t kThreadTebSize = 0x1000;
    const auto& layout = layout_for(state->guest_mode);
    const std::uint64_t total = kThreadTebSize + kThreadStackSize;
    const std::uint64_t base = (state->valloc_cursor + 0xFF) & ~static_cast<std::uint64_t>(0xFF);
    if (base + total > layout.alloc_end) {
        outcome.status = kStatusNoMemory;
        outcome.thread_create = false;
        return;
    }
    state->valloc_cursor = base + total;
    if (uc_mem_map(uc, base, static_cast<std::size_t>(total), UC_PROT_ALL) != UC_ERR_OK) {
        outcome.status = kStatusNoMemory;
        outcome.thread_create = false;
        return;
    }
    // TEB + stack join the attribution map as infrastructure private data:
    // control flow never enters them (xfer silence is structural), but the
    // MBI answer for these pages becomes a real commit instead of the
    // MEM_FREE fallback.
    if (state->region_map != nullptr) {
        state->region_map->register_region(base, total, kPageReadWrite, kMemPrivate, false);
    }
    const std::uint64_t teb_base = base;
    const std::uint64_t stack_top = base + total;

    // save the live (calling) thread before the register hijack
    auto& cur = sched.cur();
    if (cur.context == nullptr && uc_context_alloc(uc, &cur.context) != UC_ERR_OK) {
        outcome.status = kStatusNoMemory;
        outcome.thread_create = false;
        return;
    }
    cur.rip_resume = resume_rip; // past syscall (x64) / past int (x86)
    if (uc_context_save(uc, cur.context) != UC_ERR_OK) {
        outcome.status = kStatusNoMemory;
        outcome.thread_create = false;
        return;
    }

    // new thread's initial registers
    const std::uint64_t stack_top_aligned = (stack_top - 0x10) & ~static_cast<std::uint64_t>(0xF);
    uc_reg_write(uc, UC_X86_REG_RSP, &stack_top_aligned);
    uc_reg_write(uc, UC_X86_REG_RIP, &outcome.thread_start);
    if (state->guest_mode == GuestMode::kX86) {
        // [esp] = null return, [esp+4] = argument
        const std::uint32_t null_ret = 0;
        const std::uint32_t arg32 = static_cast<std::uint32_t>(outcome.thread_argument);
        uc_mem_write(uc, stack_top_aligned - 8, &null_ret, sizeof null_ret);
        uc_mem_write(uc, stack_top_aligned - 4, &arg32, sizeof arg32);
        const std::uint64_t rsp_x86 = stack_top_aligned - 8;
        uc_reg_write(uc, UC_X86_REG_ESP, &rsp_x86);
    } else {
        uc_reg_write(uc, UC_X86_REG_RCX, &outcome.thread_argument);
    }
    SchedulerThread nt{.tid = sched.next_tid,
                       .context = nullptr,
                       .teb_base = teb_base,
                       .rip_resume = outcome.thread_start,
                       .stack_base = stack_top,
                       .stack_limit = stack_top - kThreadStackSize,
                       .finished = false};
    sched.next_tid += 1;
    if (uc_context_alloc(uc, &nt.context) != UC_ERR_OK) {
        outcome.status = kStatusNoMemory;
        outcome.thread_create = false;
        uc_context_restore(uc, cur.context);
        return;
    }
    uc_context_save(uc, nt.context); // captures the starting register state

    // minimal TEB: stack region, self, own tid, PEB pointer from the main TEB
    const auto main_teb = sched.threads[0].teb_base;
    const bool x86 = state->guest_mode == GuestMode::kX86;
    if (x86) {
        const std::uint32_t sb = static_cast<std::uint32_t>(stack_top);
        const std::uint32_t sl = static_cast<std::uint32_t>(nt.stack_limit);
        const std::uint32_t self = static_cast<std::uint32_t>(teb_base);
        const std::uint32_t peb = read_guest_u32(uc, main_teb + 0x30);
        uc_mem_write(uc, teb_base + 0x04, &sb, sizeof sb);         // NtTib.StackBase
        uc_mem_write(uc, teb_base + 0x08, &sl, sizeof sl);         // NtTib.StackLimit
        uc_mem_write(uc, teb_base + 0x18, &self, sizeof self);     // Self
        uc_mem_write(uc, teb_base + 0x24, &nt.tid, sizeof nt.tid); // ClientId.TID
        uc_mem_write(uc, teb_base + 0x30, &peb, sizeof peb);       // PEB
    } else {
        const auto sb = static_cast<std::uint32_t>(stack_top);
        const auto sl = static_cast<std::uint32_t>(nt.stack_limit);
        const std::uint32_t peb = read_guest_u32(uc, main_teb + 0x60);
        uc_mem_write(uc, teb_base + 0x08, &sb, sizeof sb);         // NtTib.StackBase
        uc_mem_write(uc, teb_base + 0x10, &sl, sizeof sl);         // NtTib.StackLimit
        uc_mem_write(uc, teb_base + 0x30, &nt.tid, sizeof nt.tid); // ClientId.TID
        uc_mem_write(uc, teb_base + 0x60, &peb, sizeof peb);       // PEB
    }

    uc_context_restore(uc, cur.context); // calling thread continues
    sched.threads.push_back(std::move(nt));
    sched.enabled = true;

    // the synthetic handle encodes the tid ((value - 0x100) = tid)
    if (outcome.thread_handle_ptr != 0) {
        const std::uint64_t handle = 0x100 + outcome.thread_start * 0 + nt.tid;
        if (x86) {
            const auto h32 = static_cast<std::uint32_t>(handle);
            uc_mem_write(uc, outcome.thread_handle_ptr, &h32, sizeof h32);
        } else {
            uc_mem_write(uc, outcome.thread_handle_ptr, &handle, sizeof handle);
        }
    }
    if (state->event_sink) {
        std::array<std::uint8_t, 12> fields{};
        le::store_le32(fields.data(), nt.tid);
        le::store_le64(fields.data() + 4, outcome.thread_start);
        const EventPreamble preamble{.seq = 0, .tid = state->current_tid, .pc = frame.rip};
        state->event_sink(EventTypeId::kThreadCreate, preamble, fields);
    }
    outcome.thread_start = nt.tid; // engine->caller channel: the assigned tid
}

// Thread exit: end the calling thread; the loop-bottom rotation picks
// the next live thread (round-robin skips finished ones). When the last
// live thread exits via NtTerminateThread the process dies with its code.
// The restore itself happens at the rotation - doing it here would run
// before the dispatcher's caller synthesized the syscall ABI and corrupt
// the restored registers.
void scheduler_thread_exit(SyscallRunState* state, const std::uint32_t exit_code)
{
    auto& sched = state->scheduler;
    sched.cur().finished = true;
    bool any_live = false;
    for (const auto& t : sched.threads) {
        if (!t.finished) {
            any_live = true;
            break;
        }
    }
    if (!any_live) {
        state->terminated = true;
        state->exit_code = exit_code;
        uc_emu_stop(state->uc);
        return;
    }
    sched.blocked = true; // force the loop bottom to rotate
    uc_emu_stop(state->uc);
}

} // namespace sheller::engine
