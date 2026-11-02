// Loader-route API interception:
// intercepted kernel32/Rtl entries are replaced wholesale by built-in
// implementations - args from the x64 call registers, result in rax, return
// address popped off the stack. The uc_emu_stop + api_resume hands the leg
// back to the run loop, which re-enters at the return address.

#ifndef SHELLER_ENGINE_INTERCEPT_H
#define SHELLER_ENGINE_INTERCEPT_H

#include "rebuild_state.h"

#include <array>
#include <optional>
#include <string_view>

namespace sheller::engine {

enum class InterceptId : std::uint32_t {
    kVirtualAlloc = 0,
    kVirtualProtect,
    kVirtualFree,
    kLoadLibraryA,
    kLoadLibraryW,
    kGetProcAddress,
    kGetModuleHandleA,
    kGetModuleHandleW,
    kExitProcess,
    kRtlAllocateHeap,
    kRtlFreeHeap,
    kRtlReAllocateHeap,
    kRtlCreateHeap,
    kRtlDestroyHeap,
    kRtlSizeHeap,
    kLdrLoadDll,
    // DLL-input route: the synthetic load's continuation slot - DllMain's
    // verdict turns into the in-flight LoadLibrary's answer.
    kDllLoadResume,
    // DllMain-support family: answered in-engine because their real bodies
    // walk ntdll internals the emulated world does not provision.
    kDisableThreadLibraryCalls,
    kGetStdHandle,
    // Critical-section family: the CRT init inside real DllMain bodies
    // enters its own static lock before any sample code runs; the emulated
    // world has no lock machinery, so the family answers in-engine.
    kInitializeCriticalSection,
    kInitializeCriticalSectionAndSpinCount,
    kEnterCriticalSection,
    kLeaveCriticalSection,
    kDeleteCriticalSection,
    // FLS/TLS family: the CRT init inside real DllMain bodies dynamically
    // resolves these; their real ntdll bodies walk TEB storage the emulated
    // world does not provision. Engine-side slot tables answer instead.
    kFlsAlloc,
    kFlsFree,
    kFlsSetValue,
    kFlsGetValue,
    kTlsAlloc,
    kTlsFree,
    kTlsSetValue,
    kTlsGetValue,
    // Vectored handlers: the CRT registers one during DllMain init; letting
    // the real ntdll registration path run against the emulated world
    // corrupts the dispatch chain. The in-engine registration keeps the
    // list empty (CRT diagnostics handlers are not needed for analysis).
    kAddVectoredExceptionHandler,
    kRemoveVectoredExceptionHandler,
    // Tier 2 behavior surface: the registry
    // family. A/W share one id - the implementation dispatches on the
    // resolved export name.
    kRegOpenKeyEx,
    kRegQueryValueEx,
    kRegCloseKey,
    // Directory mode's real bodies (kernelbase's string family and the
    // CRT-in-ntdll spellings) call ntdll!strlen; the derived image's trap
    // body never runs - this handler answers the length from guest memory.
    kStrlen,
};

// intercept-set membership by resolved final function name
std::optional<std::uint32_t> intercept_id_for(std::string_view name);

// Heap-family export names: registered unconditionally at
// the mapped ntdll so every caller - IAT or direct/hash-resolved - lands in
// the engine heap instead of the real heap-manager code, which cannot run
// against the loader route's synthetic PEB.ProcessHeap.
inline constexpr std::array<std::pair<std::string_view, InterceptId>, 6> kHeapInterceptNames{
    std::pair<std::string_view, InterceptId>{"RtlCreateHeap", InterceptId::kRtlCreateHeap},
    {"RtlDestroyHeap", InterceptId::kRtlDestroyHeap},
    {"RtlAllocateHeap", InterceptId::kRtlAllocateHeap},
    {"RtlFreeHeap", InterceptId::kRtlFreeHeap},
    {"RtlReAllocateHeap", InterceptId::kRtlReAllocateHeap},
    {"RtlSizeHeap", InterceptId::kRtlSizeHeap}};

// Ldr entry points whose real load/teardown paths read structures the
// synthetic environment does not provide (packed corpus died in
// LdrpLoadDllInternal's cleanup) - resolved against the resident module set
// instead.
inline constexpr std::array<std::pair<std::string_view, InterceptId>, 1> kLdrInterceptNames{
    std::pair<std::string_view, InterceptId>{"LdrLoadDll", InterceptId::kLdrLoadDll}};

// The apicall event for the intercept in flight: name-in-band + module
// index + flags + retval (the handler's result) + caller (stack return
// address, still intact at this point) + kind-encoded parameters.
void emit_intercept_event(SyscallRunState& state, const std::uint64_t retval);

// An intercepted call has already computed its results; pop the return
// address and hand the leg back to the run loop. arg_bytes is the stdcall
// callee-clean count (x86 only; x64 callers leave the default 0).
void intercept_return(SyscallRunState& state, const std::uint64_t rax,
                      const std::uint64_t arg_bytes);

// Deterministic-stub call counting. The hook is
// range-scoped to each loader module; only an exact export-entry pc counts,
// so a stub call is exactly one hit regardless of stub body length. O(1)
// slot bump - no allocation on the hook path.
void on_stub_code([[maybe_unused]] uc_engine* uc, const std::uint64_t address, const std::uint32_t,
                  void* const user_data);

// The C++ accept takeover: the frame handler drove
// RtlUnwindEx as guest code. During an active engine dispatch the engine
// converts that call into its own unwind pass; every other caller falls
// through and the real function runs.
void on_rtl_unwind_ex(uc_engine* const uc, [[maybe_unused]] const std::uint64_t address,
                      [[maybe_unused]] const std::uint32_t size, void* const user_data);

// dispatch by the intercepted entry address (linear over <= 16 entries)
void on_intercept([[maybe_unused]] uc_engine* uc, const std::uint64_t address, const std::uint32_t,
                  void* const user_data);

} // namespace sheller::engine

#endif // SHELLER_ENGINE_INTERCEPT_H
