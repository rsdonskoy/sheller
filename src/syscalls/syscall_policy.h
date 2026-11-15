// Guest syscall policy table - data-driven dispatch for intercepted syscalls
// (default deny, per-number overrides, rejections are
// observable). The table maps a syscall number to either a built-in handler
// or a rejection code; the dispatch function interprets entries against the
// guest machine state.

#ifndef SHELLER_SYSCALLS_POLICY_H
#define SHELLER_SYSCALLS_POLICY_H

#include <array>
#include <cstdint>
#include <map>
#include <string_view>

// Opaque unicorn handle, mirrored from unicorn/unicorn.h (tag uc_struct,
// typedef uc_engine) so this header stays free of that include; identical
// typedef declarations merge per the C++ rules.
struct uc_struct;
typedef struct uc_struct uc_engine;

namespace sheller::syscalls {

using SyscallNumber = std::uint32_t;
using NtStatus = std::uint32_t;

inline constexpr NtStatus kStatusSuccess = 0x00000000;
inline constexpr NtStatus kStatusInvalidParameter = 0xC000000D;
inline constexpr NtStatus kStatusAccessDenied = 0xC0000022;
inline constexpr NtStatus kStatusAccessViolation = 0xC0000005;
inline constexpr NtStatus kStatusNoMemory = 0xC0000017;
inline constexpr NtStatus kStatusInvalidHandle = 0xC0000008;
inline constexpr NtStatus kStatusInfoLengthMismatch = 0xC0000004;
inline constexpr NtStatus kStatusObjectNameNotFound = 0xC0000034;
inline constexpr NtStatus kStatusPending = 0x00000103;
// The loader's AppPolicy preamble opens the calling
// thread's impersonation token; the native desktop answer for a plain main
// thread is STATUS_NO_TOKEN (not ACCESS_DENIED - the real denial sends the
// caller down an error branch the desktop never walks).
inline constexpr NtStatus kStatusNoToken = 0xC000007C;

// Synthetic numbers shared with the ml64 sample (
// real Windows numbers drift per build and join as plain data entries later).
inline constexpr SyscallNumber kNumberWriteFile = 0x1000;
inline constexpr SyscallNumber kNumberDelayExecution = 0x1001;
inline constexpr SyscallNumber kNumberTerminateProcess = 0x1002;
// Thread-class synthetic numbers (sample contract)
inline constexpr SyscallNumber kNumberCreateThreadEx = 0x1003;
inline constexpr SyscallNumber kNumberTerminateThread = 0x1004;
inline constexpr SyscallNumber kNumberWaitSingle = 0x1005;

enum class EntryKind : std::uint8_t {
    kHandler, // built-in minimal handler
    kReject,  // refuse with the entry's NTSTATUS
};

// Semantic handler of a kHandler entry: dispatch runs the table entry's
// builtin, never the raw syscall number, so the same semantics can be
// registered on any number (synthetic or the real build-specific one).
enum class BuiltinHandler : std::uint8_t {
    kNone, // registered without semantics: defaults to deny
    kWriteFile,
    kDelayExecution,
    kTerminateProcess,
    kAccept, // succeed with no side effects
    kAllocateMemory,
    kQueryZero,
    kProtectVirtualMemory,
    // Thread-class semantics
    kCreateThreadEx,  // real thread creation (engine applies)
    kTerminateThread, // end the calling thread only
    kWaitSingle,      // block-yield once, then satisfied
    kWaitMultiple,    // same shape as kWaitSingle
    // NtRaiseException - the kernel re-dispatches the passed record
    // against the passed context and a last-chance raise never returns. The
    // engine applies both (ntdll's no-handler path calls it directly; a
    // plain rejection makes ntdll's raise path recurse forever).
    kRaiseException,
    // NtQueryVirtualMemory - ntdll's image-lookup fallback for
    // PCs outside every registered function table queries the memory region
    // (the loader route's ntdll data is never populated, so the dispatch
    // walk depends on this answer). The engine answers MemoryBasicInformation
    // from its region map.
    kQueryVirtualMemory,
    // NtContinue - x86 dispatch resumes the interrupted context
    // through this syscall (KiUserExceptionDispatcher's tail). The engine
    // applies the passed CONTEXT to the machine and resumes at its Eip;
    // like NtRaiseException it never returns into the caller's flow.
    kContinue,
    // Section objects and mapped views. The
    // handlers only parse - the engine owns the deterministic section handle
    // table, issues the handles and maps the views.
    kOpenSection,      // NtOpenSection: named open, existence required
    kCreateSection,    // NtCreateSection: pagefile-backed create, optional name
    kMapViewOfSection, // NtMapViewOfSection: map the bound view
    // Minimal file semantics. The handler parses the
    // request; the engine owns the deterministic file handle table and the
    // host-side byte source (same split as the section family).
    kCreateFile,           // NtCreateFile/NtOpenFile: open the named host file
    kReadFile,             // NtReadFile: serve bytes from the bound host file
    kClose,                // NtClose: release the deterministic handle
    kQueryInformationFile, // NtQueryInformationFile: FileStandardInformation
    kQueryAttributesFile,  // NtQueryAttributesFile: existence + basic attrs
    // NtOpenEvent of a named notification event the
    // real loader's post-map policy flow checks for. The engine has no event
    // object namespace; the answer is a deterministic constant handle that
    // nothing dereferences (NtClose is unconditional, kWaitSingle is a
    // bounded no-op) - a denial makes the loader treat the check as fatal.
    kOpenEvent, // NtOpenEvent: deterministic handle, no event state
    // NtQueryPerformanceCounter(PLARGE_INTEGER out
    // rcx, PLARGE_INTEGER frequency out rdx). The loader's mapped-module
    // path issues it; the replay answers "time stands still" - deterministic
    // zeros, no host clock reads.
    kQueryPerformanceCounter,
};

// The synthetic numbers: a block reserved above every number a real ntdll
// stub carries, so a sample that writes its own syscall immediate keys the
// policy on a constant no Windows build can shift. One row is the whole
// agreement for one number - the policy registers the builtin, the renders
// take the name - so a number cannot enter the dispatch table unnamed. The
// stub enumeration cannot produce these: nothing in the guest carries them.
struct SyntheticSyscall {
    SyscallNumber number{};
    std::string_view name{};
    BuiltinHandler builtin{BuiltinHandler::kNone};
};

// Keys reference the constants above so each number stays declared once. The
// sample asm writes the same values as instruction immediates; those are
// frozen corpus data (captured snapshots and the golden streams carry them),
// which is why the block never moves.
inline constexpr std::array<SyntheticSyscall, 6> kSyntheticSyscalls{{
    {kNumberWriteFile, "NtWriteFile", BuiltinHandler::kWriteFile},
    {kNumberDelayExecution, "NtDelayExecution", BuiltinHandler::kDelayExecution},
    {kNumberTerminateProcess, "NtTerminateProcess", BuiltinHandler::kTerminateProcess},
    {kNumberCreateThreadEx, "NtCreateThreadEx", BuiltinHandler::kCreateThreadEx},
    {kNumberTerminateThread, "NtTerminateThread", BuiltinHandler::kTerminateThread},
    {kNumberWaitSingle, "NtWaitForSingleObject", BuiltinHandler::kWaitSingle},
}};

struct PolicyEntry {
    EntryKind kind{EntryKind::kReject};
    NtStatus reject_status{kStatusAccessDenied};
    BuiltinHandler builtin{BuiltinHandler::kNone};
};

// Register state at the syscall interception point, laid out for handlers.
struct SyscallFrame {
    std::uint32_t number{}; // eax
    std::uint32_t tid{0};   // executing thread (scheduler; 0 = main)
    std::uint64_t rip{};    // address of the syscall instruction itself
    std::uint64_t rcx{};
    std::uint64_t r10{};
    std::uint64_t rdx{};
    std::uint64_t r8{};
    std::uint64_t r9{};
    std::uint64_t rsp{};
};

struct SyscallOutcome {
    NtStatus status{kStatusSuccess};
    bool rejected{};  // answered with a rejection code
    bool terminate{}; // NtTerminateProcess: engine must stop
    std::uint32_t exit_code{};
    // kAllocateMemory (NtAllocateVirtualMemory): the handler only parses the
    // request - rounded size plus requested base (0 = caller has no base
    // preference). The engine owns guest address space: it maps the range,
    // writes the out-parameters and joins the region to the write ledger
    // (new-write and new-allocation regions both dump).
    std::uint64_t map_base{};
    std::uint64_t map_size{};
    // kAllocateMemory: the requested page protection ( Protect stack arg) -
    // the behavior layer's RWX-request signal reads it.
    std::uint32_t alloc_protection{};
    // kProtectVirtualMemory: the handler parses the request (page base and
    // byte size); the engine flips the ledger region writable so the
    // fault-based dirty tracking lets the next write through. The requested
    // protection value rides along for the behavior layer's RWX signal.
    std::uint64_t protect_base{};
    std::uint64_t protect_size{};
    std::uint32_t protect_protection{};
    // Thread-class outcomes. The handler parses the request; the
    // engine applies it (same split as kAllocateMemory).
    bool terminate_thread{};      // kTerminateThread: end the calling thread
    bool blocking{};              // kWait*: yield once, resume satisfied
    bool thread_create{};         // kCreateThreadEx: engine builds the thread
    std::uint64_t thread_start{}; // start routine
    std::uint64_t thread_argument{};
    std::uint64_t thread_handle_ptr{}; // guest ThreadHandle* out-parameter
    // kRaiseException: the engine re-dispatches the raised record
    // against the raised context (first chance) or lands the crash fallback
    // (last chance); the syscall itself never resumes guest control flow.
    bool raise{};
    // kQueryVirtualMemory: the engine answers MemoryBasicInformation
    // from its region map; other information classes are rejected.
    bool query_virtual{};
    // kContinue: the engine applies the passed CONTEXT and resumes at
    // its Eip; the syscall never resumes the caller's flow.
    bool continue_ctx{};
    // The handler parses the request; the engine
    // owns the section handle table (issues handles, maps views).
    bool open_section{};                // kOpenSection: named open, must exist
    bool create_section{};              // kCreateSection: pagefile-backed create
    bool map_view{};                    // kMapViewOfSection
    std::uint64_t section_handle_out{}; // guest *Handle out-parameter
    std::uint64_t section_objattr{};    // guest OBJECT_ATTRIBUTES pointer
    std::uint64_t section_maxsize{};    // *MaximumSize (create; 0 = unparsed)
    // NtCreateSection's FileHandle (stack argument 7).
    // Non-zero means the image-section create is file-backed - the engine
    // binds the section to the captured host file bytes instead of the
    // pagefile zero-fill, which is the shape the real loader's non-KnownDll
    // DLL loads arrive in.
    std::uint64_t section_file_handle{};
    std::uint64_t map_view_handle{};   // SectionHandle in
    std::uint64_t map_view_base_ptr{}; // guest *BaseAddress in/out
    std::uint64_t map_view_size_ptr{}; // guest *ViewSize in/out
    // kCreateFile: NtCreateFile/NtOpenFile request. ObjectName is a guest
    // UNICODE_STRING* (OBJECT_ATTRIBUTES.ObjectName at +0x10); the engine
    // resolves it against the host filesystem and writes the out-handle.
    bool create_file{};
    std::uint64_t file_handle_out{}; // guest *FileHandle out-parameter
    std::uint64_t file_io_status{};  // guest IO_STATUS_BLOCK*
    std::uint64_t file_objattr{};    // guest OBJECT_ATTRIBUTES*
    // kReadFile: NtReadFile request. The engine copies host file bytes into
    // the caller's buffer and fills the IO_STATUS_BLOCK.
    bool read_file{};
    std::uint64_t read_handle{};    // FileHandle in
    std::uint64_t read_buffer{};    // guest Buffer
    std::uint64_t read_length{};    // Length
    std::uint64_t read_io_status{}; // guest IO_STATUS_BLOCK*
    // kQueryInformationFile: the engine answers FileStandardInformation
    // (file size) from the bound host file; other classes reject.
    bool query_file{};
    std::uint64_t query_file_handle{}; // FileHandle in
    std::uint64_t query_file_class{};  // FileInformationClass
    std::uint64_t query_file_out{};    // guest FileInformation buffer
    std::uint64_t query_file_len{};    // Length
    std::uint64_t query_file_iosb{};   // guest IO_STATUS_BLOCK*
    // kQueryAttributesFile: the engine resolves OBJECT_ATTRIBUTES against
    // the host filesystem and fills FILE_NETWORK_OPEN_INFORMATION.
    bool query_attributes{};
    std::uint64_t attributes_objattr{}; // guest OBJECT_ATTRIBUTES*
    std::uint64_t attributes_out{};     // guest FILE_NETWORK_OPEN_INFORMATION*
    // kQueryPerformanceCounter: the handler parses the request; the engine
    // answers the counter from the virtual clock (base + per-block delta at
    // the current block position) and the frequency from the clock policy.
    bool query_performance{};
    std::uint64_t qpc_counter_ptr{};   // guest PLARGE_INTEGER Counter
    std::uint64_t qpc_frequency_ptr{}; // guest PLARGE_INTEGER Frequency (optional)
};

class PolicyTable {
  public:
    PolicyTable();

    void set_entry(SyscallNumber number, const PolicyEntry& entry);

    // Registers a kHandler entry with the given builtin semantics.
    void set_builtin(SyscallNumber number, BuiltinHandler handler);

    // Unregistered numbers read as default deny (STATUS_ACCESS_DENIED).
    const PolicyEntry& entry_for(SyscallNumber number) const;

  private:
    std::map<SyscallNumber, PolicyEntry> entries_;
};

struct WriteSink {
    void* context{};
    void (*write)(void* context, const std::uint8_t* data, std::size_t size);
    void write_bytes(const std::uint8_t* data, std::size_t size) const
    {
        if (write != nullptr) {
            write(context, data, size);
        }
    }
};

// Executes one intercepted syscall against the policy table. Handlers may
// read guest memory and stop the emulation through the unicorn handle.
SyscallOutcome dispatch_syscall(const PolicyTable& table, uc_engine* uc, const SyscallFrame& frame,
                                const WriteSink& sink);

} // namespace sheller::syscalls

#endif // SHELLER_SYSCALLS_POLICY_H
