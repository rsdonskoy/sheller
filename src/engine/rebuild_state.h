// Shared foundation of the rebuild TUs: the loader-route layout constants,
// the guest register shapes, the snapshot-rebuild value types, and the
// syscall-run state every engine hook and dispatch helper operates on.
// Everything here is engine-private; the public surface stays in
// <sheller/rebuild.h>, <sheller/syscallrun.h>, and <sheller/peloader.h>.

#ifndef SHELLER_ENGINE_REBUILD_STATE_H
#define SHELLER_ENGINE_REBUILD_STATE_H

#include "../loader/boundary_derive.h"
#include "../loader/imports.h"
#include "../syscalls/syscall_policy.h"
#include "behavior_fact.h"
#include "boundary_metadata.h"
#include "exception_layout.h"
#include "mem_region_map.h"
#include "native_gate.h"
#include "seh_dispatcher.h"
#include "write_ledger.h"
#include <sheller/events.h>
#include <sheller/rebuild.h>
#include <sheller/snapshot.h>
#include <sheller/syscallrun.h>

#include <unicorn/unicorn.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace sheller::engine {

// The reader layer rejects anything but 64-bit snapshots already; this is
// the unicorn spelling of that fact.
inline constexpr uc_mode kGuestMode = UC_MODE_64;
// uc_mem_map granularity in unicorn2 matches the Win32 page size, and
// VirtualQueryEx only ever yields page-granular regions.
inline constexpr std::uint64_t kMapAlignment = 0x1000;
// Loader route: NULL-guard page, KUSER page, deterministic stack.
// Every other base lives in a per-mode layout below: the x86 layout
// must stay under 4GB, with system modules in the real SysWOW64 range so
// HIGHLOW relocations never wrap a 32-bit delta.
inline constexpr std::uint64_t kLoaderNullBytes = 0x10000;
inline constexpr std::uint64_t kLoaderKUser = 0x7FFE0000;
// Synthetic-module loader route remap target: a sample whose preferred base
// exceeds 4GB (UPX-stub citizens bake base-relative pointers, and consuming
// one through a 32-bit slot drops the high dword - rip=0x95480 for
// base=0x140000000+rva 0x95480). Mapped at a sub-4GB base, the relocated
// pointers read back intact from any 32-bit slot.
inline constexpr std::uint64_t kLoaderSampleBase = 0x400000;
// The wow64 transition stub page (x86): int 2Eh + ret, seeded over the real
// Wow64Transition so every SysWOW64 service call lands in the engine's
// native int-2E answer. The int sits at base+0, so its post-instruction rip
// is base+2 - the int-2E hook keys the argument convention off that rip.
inline constexpr std::uint64_t kLoaderWow64StubBase = 0x7FFD0000;
inline constexpr std::uint64_t kLoaderStackBase = 0x300000000ULL;
inline constexpr std::uint64_t kLoaderStackSize = 0x100000;
inline constexpr std::uint64_t kLoaderStackTop = kLoaderStackBase + kLoaderStackSize;
inline constexpr std::uint64_t kLoaderEnvBase = 0x330000000ULL;
inline constexpr std::uint64_t kLoaderEnvBlockSize = 0x13000;

enum class GuestMode { kX64, kX86 };

// Loader-route address layout, one deterministic plan per mode: NULL page
// and KUSER are shared, everything else is mode-specific.
struct LoaderLayout {
    std::uint64_t stack_base{};
    std::uint64_t stack_size{};
    std::uint64_t env_base{};
    std::uint64_t env_block_size{};
    std::uint64_t alloc_base{}; // VirtualAlloc bump range
    std::uint64_t alloc_end{};
    std::uint64_t heap_base{}; // Rtl heap region
    std::uint64_t heap_size{};
};
inline constexpr LoaderLayout kLayout64{kLoaderStackBase,    kLoaderStackSize, kLoaderEnvBase,
                                        kLoaderEnvBlockSize, 0x310000000ULL,   0x400000000ULL,
                                        0x320000000ULL,      0x1000000};
// x86-only: the GDT page backing the fs segment descriptor (unicorn
// UC_MODE_32 needs the base via the descriptor table).
inline constexpr std::uint64_t kX86GdtBase = 0x00100000;
inline constexpr std::uint64_t kX86GdtSize = 0x1000;
inline constexpr LoaderLayout kLayout86{0x00200000, 0x100000,   0x02000000, kLoaderEnvBlockSize,
                                        0x08000000, 0x30000000, 0x04000000, 0x1000000};

constexpr const LoaderLayout& layout_for(const GuestMode mode)
{
    return mode == GuestMode::kX64 ? kLayout64 : kLayout86;
}

// System module fixed bases, per mode; order ntdll/kernel32/kernelbase/
// advapi32/user32 matches kSystemModules below. The x86 trio sits in the
// real SysWOW64 range, so HIGHLOW relocations never wrap a 32-bit delta.
// Slots 3-4 (advapi32, user32 - the tier-2 reserved pair) sit on the FAR
// SIDE of the extras ladder: x64 extras ascend from the third core base
// (7FFB upward), so the reserved pair sits below the whole core band; x86
// extras descend from it (74000000 downward), so the pair sits above the
// highest core base. The ladder can never reach a reserved slot at any
// extra count: a reserved base on the ladder's path made an extra
// overwrite the reserved module's mapping (user32's 0x7FFF slot was the
// ladder's fifth member; advapi32's 0x7FFB its first).
inline constexpr std::uint64_t kBases64[5] = {
    0x7FF800000000ULL, 0x7FF900000000ULL, 0x7FFA00000000ULL, 0x7FF600000000ULL, 0x7FF700000000ULL};
inline constexpr std::uint64_t kBases86[5] = {0x77000000ULL, 0x76000000ULL, 0x75000000ULL,
                                              0x79000000ULL, 0x78000000ULL};
// The ladder-independence of the reserved pair is a structural fact: each
// reserved base sits beyond the ladder's direction of travel and off the
// trio's slots, so no extra count can ever assign it.
static_assert(kBases64[3] < kBases64[2] && kBases64[4] < kBases64[2] &&
                  kBases64[3] != kBases64[0] && kBases64[3] != kBases64[1] &&
                  kBases64[4] != kBases64[0] && kBases64[4] != kBases64[1],
              "x64 reserved slots must be unreachable by the ascending extra ladder");
static_assert(kBases86[3] > kBases86[2] && kBases86[4] > kBases86[2] &&
                  kBases86[3] != kBases86[0] && kBases86[3] != kBases86[1] &&
                  kBases86[4] != kBases86[0] && kBases86[4] != kBases86[1],
              "x86 reserved slots must be unreachable by the descending extra ladder");

inline constexpr std::uint64_t kLoaderAllocBase = 0x310000000ULL; // VirtualAlloc bump base
inline constexpr std::uint64_t kLoaderAllocEnd = 0x400000000ULL;
inline constexpr std::uint64_t kLoaderHeapBase = 0x320000000ULL; // Rtl heap region
inline constexpr std::uint64_t kLoaderHeapSize = 0x1000000;
inline constexpr int kEntryProofInstructionCount = 16;

// Win32 PAGE_* values are stable ABI numbers; the snapshot stores them as
// captured facts and the engine owns the interpretation. Guard pages never
// carried content (the capture path records them as content-absent), so they
// end up UC_PROT_NONE regardless of their base protection.
// GPR access is mode-shaped: x64 uses the full 16-slot R-register set, x86
// the 8-slot E-register set (contract R8..R15 stay zero there).
inline constexpr std::array<uc_x86_reg, snapshot::kGprCount> kGprRegisters64{
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX, UC_X86_REG_RSP, UC_X86_REG_RBP,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15};
inline constexpr std::array<uc_x86_reg, 8> kGprRegisters86{
    UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
    UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI};

constexpr std::size_t gpr_count_for(const GuestMode mode)
{
    return mode == GuestMode::kX64 ? snapshot::kGprCount : 8;
}

constexpr uc_x86_reg gpr_register_for(const GuestMode mode, const std::size_t index)
{
    return mode == GuestMode::kX64 ? kGprRegisters64[index] : kGprRegisters86[index];
}

std::uint32_t protection_to_perms(const std::uint32_t protection);

// RAII wrapper of the unicorn engine handle: uc_close on every exit path.
class UnicornEngine {
  public:
    explicit UnicornEngine(uc_engine* const handle) : handle_(handle)
    {
    }
    UnicornEngine(UnicornEngine&& other) noexcept : handle_(std::exchange(other.handle_, nullptr))
    {
    }
    UnicornEngine& operator=(UnicornEngine&& other) noexcept
    {
        if (this != &other) {
            if (handle_ != nullptr) {
                uc_close(handle_);
            }
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }
    ~UnicornEngine()
    {
        if (handle_ != nullptr) {
            uc_close(handle_);
        }
    }
    UnicornEngine(const UnicornEngine&) = delete;
    UnicornEngine& operator=(const UnicornEngine&) = delete;
    [[nodiscard]] uc_engine* get() const
    {
        return handle_;
    }

  private:
    uc_engine* handle_;
};

struct LoadedSnapshot {
    snapshot::Header header{};
    snapshot::Registers registers{};
    snapshot::Metadata metadata{};
    std::vector<snapshot::Region> regions{};
    // Present exactly when the container is v2 (DLL-input route); a v2
    // container without a complete pending block fails to load.
    std::optional<snapshot::PendingModule> pending{};
    // The bilateral directory-mode inspection's verdict (design D6):
    // nullopt when both sides are absent (the legacy route), the decoded
    // record when the container carries the mode.
    std::optional<boundary_metadata::MetadataInput> replay_metadata{};
};

inline RebuildFailure failure(const RebuildError error, const std::uint32_t unicorn_code = 0)
{
    return {error, unicorn_code, {}};
}

// Named failure: the detail text replaces the generic rebuild_error_message
// wording on the consumer side (the DLL-input construction names the
// rejected dependency).
inline RebuildFailure failure(const RebuildError error, std::string detail)
{
    RebuildFailure out{};
    out.error = error;
    out.detail = std::move(detail);
    return out;
}

// Fold an export/module name to its lower-case spelling - the canonical
// form every resident-module lookup compares against.
std::string fold_name(std::string_view name);

// A rebuilt guest ready to run: live Unicorn instance plus the metadata the
// run paths need (entry address, TEB).
struct LoaderExportEntry {
    std::uint64_t module_base{};
    std::uint64_t function_va{};
    std::string name;
};

// Where a resident system module's bytes came from - the module source
// table's values (change real-dll-module-dir). The synthetic and host
// routes mark every row with the existing classes; directory mode adds the
// strict tiers and the explicit fallback mark.
enum class SystemModuleSource {
    kSynthetic,          // the existing synthetic-route modules
    kHostSystem,         // the existing Windows-host System32 fallback route
    kDirectoryRealBytes, // directory mode: the directory DLL's own bytes
    kDirectoryDerived,   // directory mode: boundary-pair derived stub image
    kFallbackSynthetic,  // directory mode + fallback: synthetic module, marked
};

// The report-facing spelling of a source class (the module source sink
// carries strings so the public option header stays free of engine enums).
inline constexpr std::string_view system_module_source_spelling(SystemModuleSource source)
{
    switch (source) {
    case SystemModuleSource::kSynthetic:
        return "synthetic";
    case SystemModuleSource::kHostSystem:
        return "host-system";
    case SystemModuleSource::kDirectoryRealBytes:
        return "directory-real-bytes";
    case SystemModuleSource::kDirectoryDerived:
        return "directory-derived";
    case SystemModuleSource::kFallbackSynthetic:
        return "fallback-synthetic";
    }
    return "unknown";
}

struct PreparedGuest {
    UnicornEngine unicorn{nullptr};
    GuestMode guest_mode{GuestMode::kX64};
    snapshot::Metadata metadata{};
    mem_region::MemRegionMap map;
    std::vector<mem_region::ModuleImage> images;
    std::vector<mem_region::RegionRecord> regions;
    std::vector<std::uint64_t> tls_callbacks{}; // loader route: absolute VAs, entry-before order
    std::vector<mem_region::ModuleRecord> loader_modules{};
    std::vector<LoaderExportEntry> loader_exports{};
    // intercepted API entries (VA + stable handler id) for the run loop
    std::vector<std::pair<std::uint64_t, std::uint32_t>> intercepts{};
    // guest VA of each loader module's synthetic LDR entry, index-aligned
    // with loader_modules (LdrLoadDll handle source)
    std::vector<std::uint64_t> ldr_entry_vas{};
    // relative guest file paths resolve against this directory (snapshot
    // route: the sample's own directory; loader route: the PE's directory)
    std::filesystem::path relative_base{};
    // The loader route replays against a synthetic
    // Ldr whose runtime structures the real load paths read and die on, so
    // its LdrLoadDll miss must stay a DLL_NOT_FOUND answer. The snapshot
    // route replays the real captured loader - a miss falls through to the
    // real Ldr, whose native resolution path (API set, KnownDll probe, file
    // search) runs against the engine's aligned syscall answers.
    bool loader_route{false};
    // DLL-input route: the sample's bytes plus arrival name from a v2
    // container. Empty for every EXE/shellcode input - the synthetic load
    // never arms.
    std::optional<snapshot::PendingModule> pending{};
    // Full module bytes for the resident-world tables (attach_resident_world
    // fills these alongside loader_exports): the pending module's IAT
    // resolution follows export forwarders, which needs the export
    // directories' bytes, not just the name index.
    std::vector<loader::LoadedModule> loaded_modules{};
    // Directory-mode world facts (change real-dll-module-dir): empty map and
    // sources in the synthetic/host routes - behavior stays byte-identical.
    bool directory_mode{false};
    // folded module name -> source class, the construction's module source
    // table (report face + metadata persistence)
    std::vector<std::pair<std::string, SystemModuleSource>> module_sources{};
    // folded boundary module name -> its applicability-checked manifest
    // rules (the derived boundary modules only)
    std::map<std::string, std::vector<loader::BoundaryRule>> boundary_rules{};
    // the directory's API Set map, loaded against the raw ntdll's anchor;
    // the explicit resolution context points at it
    loader::ApiSetMapView api_set_map{};
    // the decoded replay-side metadata record (design D6): present exactly
    // when the container carries the bilateral directory-mode marks
    std::optional<boundary_metadata::MetadataInput> directory_metadata{};
    // Directory-mode counting whitelist and trap stop points (change
    // real-dll-module-dir): the whitelist is the explicit (module base, VA,
    // name) set whose stub entries count - derived compat stubs plus the
    // fallback synthetic modules' exports; the trap VAs are the (c)-class
    // unsupported exports whose entry terminates the run. Empty in the
    // synthetic/host routes.
    std::vector<LoaderExportEntry> stub_whitelist{};
    std::vector<std::uint64_t> boundary_trap_vas{};
    // trap VA -> (folded module name, export spelling, ordinal) for the
    // named boundary-trap diagnosis
    std::map<std::uint64_t, std::tuple<std::string, std::string, std::uint32_t>>
        boundary_trap_names{};
};

// Section objects: the engine plays the object
// manager's section directory. NtOpenSection resolves \KnownDlls\<name>
// against the mapped module set, NtCreateSection hands out pagefile-backed
// objects, NtMapViewOfSection carves the view from the deterministic bump
// range. Handles are table-index derived - deterministic, non-zero, never
// reused within a run.
struct SectionObject {
    std::uint64_t view_size{};
    std::array<char, 48> name{};       // folded; empty = anonymous
    bool known_dll{};                  // host content backfill attempted at map time
    std::vector<std::uint8_t> content; // built image bytes (KnownDLL only)
    // File-backed creates carry the bound host file's
    // raw bytes; the map builds (and relocates) the image from these instead
    // of the System32 name lookup the KnownDLL backfill uses.
    std::vector<std::uint8_t> source_bytes;
};

inline constexpr std::uint64_t kSectionHandleBase = 0x5EC70001;
inline constexpr std::uint64_t kSectionHandleStride = 8;
inline constexpr std::uint64_t kMaxSectionBytes = 0x2000000; // 32 MiB sanity bound

// file-object handles (deterministic, base + index *
// stride); shared with the section family's file-backed creates.
inline constexpr std::uint64_t kFileHandleBase = 0x5EC90001;
inline constexpr std::uint64_t kFileHandleStride = 8;

// Deterministic guest allocation answers: the WIN32
// PAGE_READWRITE spelling the ledger regions carry, and the NTSTATUS the
// deterministic allocators answer when the bump range is exhausted.
inline constexpr std::uint32_t kPageReadWrite = 0x04; // WIN32 PAGE_READWRITE
inline constexpr std::uint32_t kStatusNoMemory = 0xC0000017;

// Cooperative scheduler: one unicorn instance, one
// uc_context per thread. A thread yields on blocking syscalls, when its
// block slice runs out, or when it terminates. With no second thread the
// scheduler is a pass-through (single-thread streams stay byte-identical).
struct SchedulerThread {
    std::uint32_t tid{};
    uc_context* context{nullptr}; // null until the thread's first yield
    std::uint64_t teb_base{};     // x64 GS_BASE value / x86 descriptor base
    std::uint64_t rip_resume{};   // where the thread's next slice starts
    std::uint64_t stack_base{};
    std::uint64_t stack_limit{};
    bool finished{};
};

struct ThreadScheduler {
    uc_engine* uc{nullptr};
    GuestMode mode{GuestMode::kX64};
    std::vector<SchedulerThread> threads; // [0] = main (tid 0)
    std::size_t current{0};
    std::uint32_t next_tid{1}; // created threads: 1..N
    std::uint64_t slice_size{10000};
    std::uint64_t slice_used{}; // blocks the current thread has run
    bool blocked{};             // the current thread asked to block (wait)
    bool enabled{false};        // flips true on the first thread creation

    SchedulerThread& cur()
    {
        return threads[current];
    }
    SchedulerThread* by_tid(const std::uint32_t tid)
    {
        for (auto& t : threads) {
            if (t.tid == tid) {
                return &t;
            }
        }
        return nullptr;
    }
    // frees every allocated context (run teardown)
    void shutdown()
    {
        for (auto& t : threads) {
            if (t.context != nullptr) {
                uc_context_free(t.context);
                t.context = nullptr;
            }
        }
    }
};

// Syscall run state: policy table plus the observable statistics the
// hooks accumulate, the engine-facing event sink, and
// the exception plumbing: hooks record the facts and stop
// the emulation, the run loop synthesizes the dispatch between legs.
struct SyscallRunState {
    GuestMode guest_mode{GuestMode::kX64}; // selects register shapes + TEB base
    std::uint32_t current_tid{0};          // 0 = main thread (keeps event bytes
                                           // identical); created threads get 1..N
    ThreadScheduler scheduler;             // cooperative scheduler (owns contexts)
    std::uint64_t teb_base{};              // the executing thread's TEB (stack
                                           // growth reads the live limit from here)
    // Loader route (synthetic Ldr) vs snapshot route
    // (real captured loader) - gates the LdrLoadDll miss semantics
    bool loader_route{false};
    std::uint64_t blocks_at_last_exception{};
    std::uint32_t consecutive_exceptions{}; // nested-dispatch cascade guard
    syscalls::PolicyTable policy{};
    std::function<void(const std::uint8_t*, std::size_t)> sink{};
    std::function<void(EventTypeId, const EventPreamble&, std::span<const std::uint8_t>)>
        event_sink{};
    ModuleImageSink module_sink{}; // runtime module names, delivered at registration
    std::function<void(const BehaviorFact&)> behavior_sink{}; // the internal fact channel's
                                                              // sink (behavior_fact.h), not a
                                                              // public option
    uc_engine* uc{nullptr};                                   // loader-route interception handlers
    std::vector<std::uint64_t> intercept_vas;                 // intercepted API entry addresses
    std::vector<std::uint32_t> intercept_ids;                 // parallel handler ids
    // Resolved intercept identity (export name +
    // region-map module index) parallel to intercept_vas, the index of the
    // intercept in flight (event emission happens in intercept_return where
    // the retval exists), and the deterministic-stub counting table - the
    // hook bumps a slot counter (O(1), allocation-free); the run end drains
    // the slots into the options' stub sink.
    std::vector<std::string> intercept_names;
    std::vector<std::uint16_t> intercept_modules;
    std::int32_t pending_intercept{-1};
    struct StubEntry {
        std::uint16_t module{};
        std::string name;
        std::uint64_t count{};
    };
    std::map<std::uint64_t, std::uint32_t> stub_slots{}; // export VA -> stub_entries slot
    std::vector<StubEntry> stub_entries{};
    std::function<void(std::uint16_t, std::string_view, std::uint64_t)> stub_sink{};
    // Number -> Nt name resolved once at run start from
    // the mapped ntdll's stub immediats; dispatch consults it to pick the
    // decoded (signature-arity) or raw emission tier. Empty on synthetic
    // numbers / unresolved builds - the raw tier.
    std::map<std::uint32_t, std::string> syscall_names{};
    // Name -> number inverse (built alongside), the
    // interception layer's re-emission lookup
    std::map<std::string, std::uint32_t> syscall_numbers_by_name{};
    const std::vector<std::uint64_t>*
        diag_watch_entries{}; // diagnostic entry watch (harness-owned)
    std::function<void(std::uint64_t, void*)> diag_entry_hit; // diagnostic callback
    std::function<void(std::uint64_t, std::uint64_t, std::uint32_t, std::uint64_t)>
        diag_write_hit; // per-write window watch (harness-gated)
    std::function<void(std::uint64_t, void*)>
        diag_code_hit;             // per-instruction code window watch (harness-gated)
    bool api_resume{};             // an intercepted call returned: resume at rip
    std::uint64_t valloc_cursor{}; // loader-route deterministic allocators
    std::uint64_t heap_cursor{};
    std::vector<SectionObject> sections; // section handle table (index-derived handles)
    // Registry key table. Handle = deterministic
    // bijection of (folded root, folded subkey); reopen returns the same
    // handle, Close removes the entry (invalid thereafter). Win32 LONG
    // error-code semantics (advapi32 family reports via retval, not
    // NTSTATUS): 0 success, 2 file-not-found, 6 invalid-handle.
    std::map<std::pair<std::uint32_t, std::string>, std::uint64_t> registry_keys{};
    // Open file objects. Handle = kFileHandleBase +
    // index*stride, byte offset advances per read; content comes from the
    // host filesystem at open time (Windows-host capture route only).
    struct FileObject {
        std::vector<std::uint8_t> content;
        std::uint64_t offset{};
        // A directory/drive-root open: the real loader's DLL search-path
        // iteration probes those to succeed (attributes only, no data
        // reads) - reads answer EOF and the standard-info query reports
        // Directory=TRUE.
        bool directory{};
    };
    std::vector<FileObject> files;
    // FLS/TLS interception storage: deterministic indices, values keyed by
    // index (one table serves both families - they never mix indices in
    // practice, and the CRT only stores opaque pointers).
    std::map<std::uint32_t, std::uint64_t> tls_slots{};
    std::uint64_t tls_next_index{1};
    // relative guest paths resolve against the snapshot sample's directory
    // (the replay has no captured CWD; the sample's own directory is the
    // faithful base a real run launched from there would have)
    std::filesystem::path relative_base;
    std::vector<mem_region::ModuleRecord> loader_modules; // folded names for lookup
    // Region-map module index of the sample's own image (base == image_base).
    // Behavior facts attribute their reader PC against it: reads from any
    // other module are that module's internals, not sample behavior.
    bool sample_module_known{};
    std::size_t sample_module_index{};
    // Deterministic virtual time, advanced by executed instructions: drives
    // RDTSC/RDTSCP answers and the KUSER_SHARED_DATA TickCount fields, so
    // clock-based delay loops complete in bounded emulation time instead of
    // hanging on the frozen clock.
    std::uint64_t virtual_instructions{};
    std::uint64_t virtual_tsc{};
    std::uint32_t virtual_ticks{};
    // Burn-loop fast-forward: a small block cycle spinning with zero
    // guest-visible writes and no syscalls is a delay loop (pure-counter
    // family). The block hook grows hot_run while blocks stay inside the
    // recent-cycle ring; the syscall path resets it (a side effect = real
    // behavior). At the trigger the leg loop runs the decoder-free probe.
    // Probed loops are remembered (head -> gpr index + exit value) so later
    // invocations of the same delay are skipped almost instantly.
    std::uint64_t hot_ring[8]{};
    std::size_t hot_ring_len{};
    std::uint64_t hot_run{};
    std::uint64_t hot_trigger{8000};
    bool loop_probe_pending{};
    std::uint64_t last_block_address{};
    std::map<std::uint64_t, std::pair<std::uint32_t, std::uint64_t>> known_burn_loops{};
    // Loop-native-gate (slice 0): every probe window lands in exactly one
    // verdict slot - unconditionally accumulated so the admission-rate data
    // exists with the switch off; only the printing is env-gated. The INSN
    // flag is the probe-window evidence bit (rdtsc/rdtscp/cpuid hooks set
    // it; the probe clears it before its cycle and reads it after), and the
    // trace switch comes from SHELLER_LOOP_GATE_TRACE.
    std::uint64_t loop_gate_counts[native_gate::kVerdictSlotCount]{};
    bool probe_insn_fired{};
    bool loop_gate_trace{};
    std::vector<std::uint64_t> ldr_entry_vas;      // LdrLoadDll handle source
    std::vector<LoaderExportEntry> loader_exports; // all mapped-module exports
    // DLL-input synthetic loading (dll_loader.*): the pending module from a
    // v2 container, zero cost when absent.
    const snapshot::PendingModule* pending_module{};
    // Full module bytes behind the resident tables (forwarder-capable IAT
    // resolution reads export directories, not just the name index).
    const std::vector<loader::LoadedModule>* loaded_modules{};
    std::uint64_t dll_resume_slot{}; // continuation-slot intercept VA
    struct DllLoadState {
        bool active{};        // armed or completed: name lookups reuse the base
        bool entered{};       // ATTACH/TLS frames armed (may still be running)
        bool loaded{};        // DllMain returned TRUE
        std::uint64_t base{}; // synthesized module base (the handle value)
        std::uint64_t size{};
        std::uint64_t entry{};                  // DllMain VA
        bool has_entry{};                       // false: AddressOfEntryPoint == 0 (no init to run)
        std::string name;                       // folded arrival name
        std::vector<std::uint64_t> tls_pending; // absolute VAs, entry-before order
        std::size_t tls_cursor{};               // next TLS callback to enter
        // Which frame the resume slot will see next: a TLS callback's return
        // is void (chain advances); only DllMain's verdict answers the load.
        enum class Phase { kIdle, kTls, kDllMain } phase{Phase::kIdle};
        std::uint64_t node_va{}; // guest VA of the LDR node page (rollback)
        bool image_mapped{};     // resources owned by this load transaction
        bool node_mapped{};
        std::array<bool, 3> linked{};
        bool prev_sample_known{};
        std::size_t prev_sample_index{};
        std::vector<std::uint64_t> ledger_bases{}; // per-section ledger regions (rollback)
        std::uint64_t prev_sample_base{};          // writer-attribution span to restore on rollback
        std::uint64_t prev_sample_size{};
        std::uint64_t caller_rip{}; // the intercepted LoadLibrary return site
        std::uint64_t caller_rsp{};
        std::uint64_t call_base_rsp{}; // aligned frame base every frame builds from
        std::size_t module_index{};    // region-map module index of the sample module
    } dll_load;
    std::uint64_t blocks{};
    std::uint64_t max_blocks{};             // block-count budget; 0 = unlimited
    mem_region::MemRegionMap* region_map{}; // attribution for xfer detection; the
                                            // memory-map seams register allocations
                                            // and protection flips through it
    MemWriteLedger* write_ledger{};         // page-dirty tracking
    // Identity of the previous block's attribution interval - the stable
    // value key (module/section or origin/class), not the positional index:
    // splits and re-sorts must not forge or swallow transfer events. The
    // territory rides beside it: the xfer edge rules fire only on the
    // sample-territory pairs (image->image, image->sample-alloc,
    // sample-alloc->image).
    mem_region::AttributionIdentity last_identity{};
    mem_region::XferTerritory last_territory{};
    bool last_identity_valid{};
    std::uint64_t xfer_number{}; // 1-based stop ordinal; 0 = off
    std::uint64_t xfers{};       // counted outside burn-loop probes
    bool xfer_stop_reached{};
    // ESP-law stop target (esp_target.h): the static entry save window and
    // the confirmation flags. All of it is dead unless the host requested an
    // esp goal; the window hook is range-scoped, so an unrequested run pays
    // nothing on the read path either.
    EspStopGoal esp_stop_goal{}; // kStopAtRestore / kArmThenNextXfer / kNone
    std::uint64_t esp_window_lo{};
    std::uint64_t esp_window_hi{}; // the entry rsp (S); window is [lo, hi)
    std::uint32_t esp_slot_width{};
    uc_hook esp_read_hook{0}; // the range-scoped window hook's handle
    bool esp_monitor_armed{};
    bool esp_armed_next_xfer{}; // esp+xfer: restore confirmed, stop armed
    bool esp_stop_reached{};
    std::uint64_t esp_stop_rip{}; // the confirmed read's rip (stop-face evidence)
    std::uint64_t esp_stop_rsp{};
    std::uint64_t syscalls{};
    std::uint64_t rejects{};
    std::uint64_t exceptions{};
    bool terminated{};
    std::uint32_t exit_code{};
    bool unhandled{};         // crash fallback: fastfail, unregistered vector, or repeat delivery
    bool avx_resume{};        // shim handled a translated-but-unsupported instruction:
                              // stop and re-enter at the advanced RIP
    bool write_prot_resume{}; // a first-touch store was granted write; retry it
    std::vector<std::pair<std::uint64_t, std::uint32_t>> pending_write_grants;
    struct ExceptionFacts {
        bool valid{};
        bool unhandled{}; // fastfail or an unregistered vector: no dispatch
        std::uint32_t code{};
        std::uint64_t pc{};
        std::uint64_t information[exceptions::kRecordMaxParameters]{};
        std::size_t information_count{};
        // The C++ accept handoff: the same fault re-delivered through the
        // real guest dispatcher (the unwind machinery is stack-address
        // sensitive and cannot run against the staged callback's engine
        // stack). The fault is already in the ledger - no second event.
        bool replay_in_guest{};
    };
    ExceptionFacts exception{};
    // Repeat-dispatch guard: the previous delivery's facts. A second delivery
    // of the same pair means the ExceptionList walked to its end and ntdll
    // re-raised - nothing left to dispatch.
    std::uint64_t last_dispatch_pc{};
    std::uint32_t last_dispatch_code{};
    bool dispatch_guard_armed{};
    std::uint64_t dispatcher_address{};
    // The v2 unwind tail's IRETQ: the INTR hook flags it and the run
    // loop pops the machine frame between legs.
    bool iretq_pending{};
    std::uint64_t iretq_rsp{};
    // Fidelity dispatch mode + engine-side SEH dispatch state.
    bool fidelity_dispatch{};
    seh::SehDispatchState seh;
    // Directory-mode boundary runtime (change real-dll-module-dir): the
    // trap stop points (exact-entry hooks), the fired stop's diagnosis, and
    // the explicit API Set resolution context (directory map; empty in the
    // synthetic routes — the runtime DLL binding and the dynamic queries
    // resolve through it instead of the prefix rules).
    std::vector<std::uint64_t> boundary_trap_vas{};
    std::map<std::uint64_t, std::tuple<std::string, std::string, std::uint32_t>>
        boundary_trap_names{};
    loader::ApiSetContext api_set_ctx{};
    bool directory_mode{false};
    struct BoundaryTrapDiagnosis {
        bool fired{};
        std::uint64_t va{};
        std::uint64_t caller{};
        std::string module;
        std::string name;
        std::uint32_t ordinal{};
    };
    BoundaryTrapDiagnosis boundary_trap;
    // The C++ accept handoff arms the exception replay through the real
    // guest dispatcher at ntdll!RtlUnwindEx (intercept.cpp); the export
    // address is resolved once per run for the by-address hook.
    std::uint64_t rtl_unwind_address{};
    bool seh_unwind_resume{};
    // Trace-only per-instruction hook over the faulting module while the
    // fidelity dispatch runs (SHELLER_SEH_TRACE): the guest-side picture the
    // staged-callback trace shows in engine mode.
    std::uint64_t fidelity_trace_hook{};
};

void sink_trampoline(void* const context, const std::uint8_t* data, const std::size_t size);

// unicorn2 in UC_MODE_32 no-ops the 64-bit RIP/RSP/BASE register ids:
// the 32-bit guests must use the E-register spellings.
uc_mode guest_query_mode(uc_engine* const uc);

std::uint64_t read_rip(uc_engine* const uc);

void write_rip(uc_engine* const uc, const std::uint64_t value);

std::uint64_t read_rsp(uc_engine* const uc);

void write_rsp(uc_engine* const uc, const std::uint64_t value);

std::uint64_t read_guest_u64(uc_engine* const uc, const std::uint64_t address);

std::uint32_t read_guest_u32(uc_engine* const uc, const std::uint64_t address);

} // namespace sheller::engine

#endif // SHELLER_ENGINE_REBUILD_STATE_H
