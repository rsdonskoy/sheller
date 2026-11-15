#include "syscall_policy.h"

#include <unicorn/unicorn.h>

#include <array>
#include <vector>

namespace sheller::syscalls {
namespace {

// Real NT ABI: arguments 5+ travel on the guest stack, the first of them at
// RSP + 0x28 (0x20 shadow space + 0x8 return address).
constexpr std::uint64_t kStackArgsOffset = 0x28;
constexpr std::size_t kStackArgCount = 5;

constexpr std::uint64_t kAllocationPageMask = 0xFFF;

// NtQuery* output shapes vary, but the verdict fields the dispatch and its
// anti-debug checks read all mean "none / zero / no" when zeroed. Zeroing a
// bounded prefix of the information buffer plus the return-length out-param
// answers every query in that family with the honest no-debugger
// environment, without per-info-class tables.
constexpr std::size_t kQueryZeroBytes = 0x40;

bool read_guest_memory(uc_engine* uc, const std::uint64_t va, void* const dst,
                       const std::size_t size)
{
    return uc_mem_read(uc, va, dst, size) == UC_ERR_OK;
}

} // namespace

PolicyTable::PolicyTable()
{
    for (const auto& synthetic : kSyntheticSyscalls) {
        set_builtin(synthetic.number, synthetic.builtin);
    }
}

void PolicyTable::set_builtin(const SyscallNumber number, const BuiltinHandler handler)
{
    set_entry(number, PolicyEntry{EntryKind::kHandler, kStatusSuccess, handler});
}

void PolicyTable::set_entry(const SyscallNumber number, const PolicyEntry& entry)
{
    entries_[number] = entry;
}

const PolicyEntry& PolicyTable::entry_for(const SyscallNumber number) const
{
    static const PolicyEntry kDefaultDeny{};
    const auto it = entries_.find(number);
    return it != entries_.end() ? it->second : kDefaultDeny;
}

SyscallOutcome dispatch_syscall(const PolicyTable& table, uc_engine* uc, const SyscallFrame& frame,
                                const WriteSink& sink)
{
    const auto& entry = table.entry_for(frame.number);
    if (entry.kind == EntryKind::kReject) {
        return SyscallOutcome{.status = entry.reject_status, .rejected = true};
    }
    if (entry.builtin == BuiltinHandler::kNone) {
        // A handler entry registered without semantics: deny, loudly
        // deterministic, never fall through to number guessing.
        return SyscallOutcome{.status = kStatusAccessDenied, .rejected = true};
    }

    SyscallOutcome outcome{.status = kStatusSuccess};
    switch (entry.builtin) {
    case BuiltinHandler::kTerminateProcess:
        // NtTerminateProcess(NULL) marks the process terminating and returns
        // STATUS_PENDING to the surviving caller - the full teardown
        // (LdrShutdownProcess, DLL detach callbacks) then continues on the
        // native path before the final NtTerminateProcess(-1). Only the
        // explicit current-process handle (-1) ends the replay here.
        if (frame.rcx == 0) {
            outcome.status = kStatusPending;
            break;
        }
        outcome.terminate = true;
        outcome.exit_code = static_cast<std::uint32_t>(frame.rdx);
        break;
    case BuiltinHandler::kDelayExecution:
        break; // no-op by contract: the guest keeps running immediately
    case BuiltinHandler::kWriteFile: {
        std::array<std::uint64_t, kStackArgCount> stack_args{};
        if (!read_guest_memory(uc, frame.rsp + kStackArgsOffset, stack_args.data(),
                               sizeof stack_args)) {
            outcome.status = kStatusAccessViolation;
            break;
        }
        const auto buffer_va = stack_args[1]; // argument 6: Buffer
        const auto length = stack_args[2];    // argument 7: Length
        if (length > 0) {
            std::vector<std::uint8_t> bytes(static_cast<std::size_t>(length));
            if (!read_guest_memory(uc, buffer_va, bytes.data(), bytes.size())) {
                outcome.status = kStatusAccessViolation;
                break;
            }
            sink.write_bytes(bytes.data(), bytes.size());
        }
        break;
    }
    case BuiltinHandler::kAccept:
        break; // succeed with no side effects
    case BuiltinHandler::kAllocateMemory: {
        // NtAllocateVirtualMemory(ProcessHandle, *BaseAddress, ZeroBits,
        // *RegionSize, AllocationType, Protect): args in r10/rdx/r8/r9,
        // AllocationType at [rsp+0x28] and Protect at [rsp+0x30]. Parse the
        // request only; the engine maps the range and answers the
        // out-parameters. The Protect value rides along in the outcome for
        // the behavior layer's RWX-request signal.
        std::uint64_t requested_base = 0;
        std::uint64_t requested_size = 0;
        if (!read_guest_memory(uc, frame.rdx, &requested_base, sizeof requested_base) ||
            !read_guest_memory(uc, frame.r9, &requested_size, sizeof requested_size)) {
            outcome.status = kStatusAccessViolation;
            break;
        }
        requested_size = (requested_size + kAllocationPageMask) & ~kAllocationPageMask;
        if (requested_size == 0) {
            outcome.status = kStatusInvalidParameter;
            break;
        }
        std::uint32_t allocation_protect = 0;
        static_cast<void>(read_guest_memory(uc, frame.rsp + kStackArgsOffset + 0x8,
                                            &allocation_protect, sizeof allocation_protect));
        outcome.map_base = requested_base;
        outcome.map_size = requested_size;
        outcome.alloc_protection = allocation_protect;
        break;
    }
    case BuiltinHandler::kQueryZero: {
        // NtQuery* (info buffer = r8, length = r9, return-length = stack
        // arg 5): zero the verdict fields. The debug-port and debug-flags
        // checks inside the real dispatcher route the whole exception to
        // the phantom-debugger path when the buffer holds stale stack
        // garbage; zeroed means no debugger, no port, no job.
        // ReturnLength reports the bytes actually written (the real kernel
        // always fills it in) - strict callers in the loader's KnownDll load
        // path treat a zero ReturnLength as a failed query and abort the
        // load with FAST_FAIL_FATAL_APP_EXIT (packed corpus, 2026-09-30).
        const auto length =
            frame.r9 < kQueryZeroBytes ? static_cast<std::size_t>(frame.r9) : kQueryZeroBytes;
        if (length != 0) {
            std::array<std::uint8_t, kQueryZeroBytes> zeros{};
            uc_mem_write(uc, frame.r8, zeros.data(), length);
        }
        std::uint64_t return_length_pointer = 0;
        if (read_guest_memory(uc, frame.rsp + kStackArgsOffset, &return_length_pointer,
                              sizeof return_length_pointer) &&
            return_length_pointer != 0) {
            const std::uint64_t written = length;
            uc_mem_write(uc, return_length_pointer, &written, sizeof written);
        }
        break;
    }
    case BuiltinHandler::kProtectVirtualMemory: {
        // NtProtectVirtualMemory(ProcessHandle, *BaseAddress, *Size,
        // NewProtect, *OldProtect): BaseAddress and NumberOfBytesToProtect
        // are pointers to the caller's values (rdx/r8), NewProtect travels
        // by value in r9, the old-protect pointer is on the stack. The
        // engine applies the protection to the ledger (the unicorn region
        // stays read-only so the first write still faults into the dirty
        // tracker) and answers the out-parameters.
        std::uint64_t base = 0;
        std::uint64_t size = 0;
        std::uint64_t old_protect_pointer = 0;
        if (!read_guest_memory(uc, frame.rdx, &base, sizeof base) ||
            !read_guest_memory(uc, frame.r8, &size, sizeof size) || size == 0 ||
            !read_guest_memory(uc, frame.rsp + kStackArgsOffset, &old_protect_pointer,
                               sizeof old_protect_pointer)) {
            outcome.status = kStatusAccessViolation;
            break;
        }
        const std::uint32_t new_protect = static_cast<std::uint32_t>(frame.r9);
        outcome.protect_base = base;
        outcome.protect_size = size;
        outcome.protect_protection = new_protect;
        if (old_protect_pointer != 0) {
            uc_mem_write(uc, old_protect_pointer, &new_protect, sizeof new_protect);
        }
        break;
    }
    case BuiltinHandler::kCreateThreadEx: {
        // synthetic ABI (both modes via the shared frame): rcx/arg0 =
        // ThreadHandle* out, rdx/arg1 = StartRoutine, r8/arg2 = Argument.
        // The handler only parses; the engine builds the thread (same split
        // as kAllocateMemory) and writes the synthetic handle to *out.
        outcome.thread_create = true;
        outcome.thread_handle_ptr = frame.rcx;
        outcome.thread_start = frame.rdx;
        outcome.thread_argument = frame.r8;
        break;
    }
    case BuiltinHandler::kTerminateThread:
        // (Handle, ExitCode): ends the calling thread only
        outcome.terminate_thread = true;
        outcome.exit_code = static_cast<std::uint32_t>(frame.rdx);
        break;
    case BuiltinHandler::kWaitSingle:
    case BuiltinHandler::kWaitMultiple:
        // deterministic simplification: the engine
        // yields the thread once and satisfies the wait on resume
        outcome.blocking = true;
        break;
    case BuiltinHandler::kRaiseException:
        // (Record, Context, FirstChance): the engine re-dispatches or
        // terminates; the syscall's own return never reaches the guest
        outcome.raise = true;
        break;
    case BuiltinHandler::kQueryVirtualMemory:
        // (ProcessHandle, BaseAddress, InformationClass, Buffer, Length,
        // ReturnLength): the engine answers MemoryBasicInformation from its
        // region map; other information classes are rejected
        outcome.query_virtual = true;
        break;
    case BuiltinHandler::kContinue:
        // (Context, RaiseAlert): the engine applies the CONTEXT and resumes
        // at its Eip; the syscall's own return never reaches the guest
        outcome.continue_ctx = true;
        break;
    case BuiltinHandler::kOpenSection:
        // NtOpenSection(OutHandle=rcx, AccessMask=rdx, ObjectAttributes=r8):
        // the engine resolves the object name against its section table
        // (KnownDLL membership) and writes the out-handle.
        outcome.open_section = true;
        outcome.section_handle_out = frame.rcx;
        outcome.section_objattr = frame.r8;
        break;
    case BuiltinHandler::kCreateSection:
        // NtCreateSection(OutHandle=rcx, Access=rdx, ObjectAttributes=r8,
        // *MaximumSize=r9, Protect=[rsp+0x28], AllocAttr=[rsp+0x30],
        // File=[rsp+0x38]): pagefile-backed create with an optional name -
        // always succeeds into the engine's handle table. The File stack
        // argument makes it an image-section create: the engine binds the
        // captured host file bytes (the real loader's non-KnownDll DLL
        // loads always arrive this way - the native \KnownDlls open of a
        // non-resident DLL fails with OBJECT_NAME_NOT_FOUND and the loader
        // falls back to the file path).
        outcome.create_section = true;
        outcome.section_handle_out = frame.rcx;
        outcome.section_objattr = frame.r8;
        static_cast<void>(read_guest_memory(uc, frame.r9, &outcome.section_maxsize,
                                            sizeof outcome.section_maxsize));
        static_cast<void>(read_guest_memory(uc, frame.rsp + kStackArgsOffset + 0x10,
                                            &outcome.section_file_handle,
                                            sizeof outcome.section_file_handle));
        break;
    case BuiltinHandler::kCreateFile:
        // NtCreateFile(*FileHandle=rcx, Access=rdx, OBJECT_ATTRIBUTES=r8,
        // IoStatusBlock=r9, ...): the engine resolves ObjectName against the
        // host filesystem and writes the out-handle (or OBJECT_NAME_NOT_FOUND
        // when the host file is absent - the loader's DLL probes then keep
        // the real failure path).
        outcome.create_file = true;
        outcome.file_handle_out = frame.rcx;
        outcome.file_io_status = frame.r9;
        outcome.file_objattr = frame.r8;
        break;
    case BuiltinHandler::kReadFile:
        // NtReadFile(FileHandle=rcx, Event=rdx, Apc=r8, ApcCtx=r9,
        // IoStatusBlock=[rsp+0x28], Buffer=[rsp+0x30], Length=[rsp+0x38],
        // ...): the engine serves host file bytes into the buffer and fills
        // the IO_STATUS_BLOCK (Information = bytes transferred).
        outcome.read_file = true;
        outcome.read_handle = frame.rcx;
        outcome.read_io_status = frame.rsp + 0x28;
        static_cast<void>(read_guest_memory(uc, frame.rsp + 0x30, &outcome.read_buffer,
                                            sizeof outcome.read_buffer));
        static_cast<void>(read_guest_memory(uc, frame.rsp + 0x38, &outcome.read_length,
                                            sizeof outcome.read_length));
        break;
    case BuiltinHandler::kQueryInformationFile:
        // NtQueryInformationFile(FileHandle=rcx, IoStatusBlock=rdx,
        // FileInformation=r8, Length=r9, Class=[rsp+0x28]): the engine
        // answers FileStandardInformation (size) from its file table.
        outcome.query_file = true;
        outcome.query_file_handle = frame.rcx;
        outcome.query_file_iosb = frame.rdx;
        outcome.query_file_out = frame.r8;
        outcome.query_file_len = frame.r9;
        static_cast<void>(read_guest_memory(uc, frame.rsp + 0x28, &outcome.query_file_class,
                                            sizeof outcome.query_file_class));
        break;
    case BuiltinHandler::kQueryAttributesFile:
        // NtQueryAttributesFile(OBJECT_ATTRIBUTES=rcx,
        // FILE_NETWORK_OPEN_INFORMATION=rdx): the engine resolves the name
        // against the host filesystem and fills the information block.
        outcome.query_attributes = true;
        outcome.attributes_objattr = frame.rcx;
        outcome.attributes_out = frame.rdx;
        break;
    case BuiltinHandler::kClose:
        // NtClose(Handle): always succeeds; the engine drops the entry.
        outcome.status = kStatusSuccess;
        break;
    case BuiltinHandler::kOpenEvent: {
        // NtOpenEvent(*Handle=rcx, ...): deterministic constant handle in a
        // dedicated range - nothing in the engine dereferences event
        // handles, so a table is unnecessary state. Fail-soft: an
        // unwritable out-pointer keeps the default reject.
        constexpr std::uint64_t kEventHandle = 0x5ECB0001;
        if (uc_mem_write(uc, frame.rcx, &kEventHandle, sizeof kEventHandle) == UC_ERR_OK) {
            outcome.status = kStatusSuccess;
        } else {
            outcome.status = kStatusAccessViolation;
        }
        break;
    }
    case BuiltinHandler::kQueryPerformanceCounter:
        // NtQueryPerformanceCounter(PLARGE_INTEGER Counter=rcx,
        // PLARGE_INTEGER Frequency=rdx optional): parse only - the engine
        // answers the counter from the virtual clock and the frequency from
        // the clock policy (a nonzero container-pinned value), keeping the
        // whole QPC face a pure function of the block count.
        outcome.query_performance = true;
        outcome.qpc_counter_ptr = frame.rcx;
        outcome.qpc_frequency_ptr = frame.rdx;
        break;
    case BuiltinHandler::kMapViewOfSection:
        // NtMapViewOfSection(Handle=rcx, Process=rdx, *BaseAddress=r8,
        // *ZeroBits=r9, CommitSize=[rsp+0x28], *SectionOffset=[rsp+0x30],
        // *ViewSize=[rsp+0x38], ...): the engine maps the bound view -
        // honoring a requested base and answering both out-parameters.
        // *ViewSize is a POINTER stored in the seventh argument slot: the
        // loader passes &LdrEntry->ViewSize there, and a size answered
        // anywhere else leaves that LDR size field at zero - the post-map
        // RtlImageNtHeaderEx(base, 0) deep validation then fails the load
        // with STATUS_INVALID_IMAGE_FORMAT.
        outcome.map_view = true;
        outcome.map_view_handle = frame.rcx;
        outcome.map_view_base_ptr = frame.r8;
        {
            std::array<std::uint64_t, kStackArgCount> stack_args{};
            if (read_guest_memory(uc, frame.rsp + kStackArgsOffset, stack_args.data(),
                                  sizeof stack_args)) {
                outcome.map_view_size_ptr = stack_args[2]; // argument 7: *ViewSize
            }
            // unreadable stack = no size answer; the engine keeps the base
            // answer and the load fails cleanly on its own validation
        }
        break;
    case BuiltinHandler::kNone:
        outcome.status = kStatusAccessDenied;
        outcome.rejected = true;
        break;
    }
    return outcome;
}

} // namespace sheller::syscalls
