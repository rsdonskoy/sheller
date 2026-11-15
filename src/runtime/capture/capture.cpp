// Win32 capture path: the re-photography pipeline, in three
// phases. spawn_sample creates the sample suspended under the real loader,
// patches its entry into an in-place spin (EB FE) and zeroes its TLS callback
// array - the sample itself executes zero instructions of its own in the real
// process. wait_for_entry_spin resumes it and polls until the loader has
// finished and the main thread spins at the entry. capture_state photographs
// registers, TEB and all committed regions into a v1 snapshot writer.
// Windows-only by nature; unicorn-free by construction (the sheller_capture
// target has no unicorn include path).

#include "capture_detail.h"
#include "dll_admission.h"
#include "pe_headers.h"
#include "wrapper.h"
#include <memory>
#include <optional>
#include <random>
#include <thread>

#include <sheller/capture.h>
#include <sheller/clock_policy.h>
#include <sheller/snapshot.h>

#include <windows.h>

#include <array>
#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace sheller::capture {
namespace {

// x64 PEB offset of ImageBaseAddress: undocumented but stable for ages; the
// read-back is validated against the MZ signature before use.
constexpr std::size_t kPebImageBaseOffset = 0x10;
std::uint32_t read_u32_le(const std::uint8_t* bytes)
{
    std::uint32_t value = 0;
    std::memcpy(&value, bytes, sizeof value);
    return value;
}

// The PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY payload packs 2-bit policy
// fields (00 defer, 01 always-on, 10 always-off, 11 reserved). The SDK
// headers omit these documented values, so they are spelled here per the
// PROCESS_CREATION_MITIGATION_POLICY layout: bottom-up ASLR occupies bits
// 16-17, high-entropy ASLR bits 20-21.
constexpr std::uint64_t kPolicyFieldAlwaysOff = 2;
constexpr std::uint64_t kBottomUpAslrFieldShift = 16;
constexpr std::uint64_t kHighEntropyAslrFieldShift = 20;
constexpr std::uint64_t kNoAslrMitigationPolicy =
    (kPolicyFieldAlwaysOff << kBottomUpAslrFieldShift) |
    (kPolicyFieldAlwaysOff << kHighEntropyAslrFieldShift);

// Win32 handles differ in their invalid value, so each kind gets its own
// traits and one RAII template covers them all.
struct NullHandleTraits {
    using value_type = HANDLE;
    static constexpr value_type invalid() noexcept
    {
        return nullptr;
    }
    static void close(const value_type handle) noexcept
    {
        if (handle != invalid()) {
            CloseHandle(handle);
        }
    }
};

struct InvalidHandleTraits {
    using value_type = HANDLE;
    static constexpr value_type invalid() noexcept
    {
        return INVALID_HANDLE_VALUE;
    }
    static void close(const value_type handle) noexcept
    {
        if (handle != invalid()) {
            CloseHandle(handle);
        }
    }
};

template <typename Traits>
concept HandleTraits =
    std::is_same_v<Traits, NullHandleTraits> || std::is_same_v<Traits, InvalidHandleTraits>;

template <HandleTraits Traits> class UniqueHandle {
  public:
    explicit UniqueHandle(const typename Traits::value_type handle) : handle_(handle)
    {
    }
    UniqueHandle(UniqueHandle&& other) noexcept
        : handle_(std::exchange(other.handle_, Traits::invalid()))
    {
    }
    UniqueHandle& operator=(UniqueHandle&& other) noexcept
    {
        if (this != &other) {
            Traits::close(handle_);
            handle_ = std::exchange(other.handle_, Traits::invalid());
        }
        return *this;
    }
    ~UniqueHandle()
    {
        Traits::close(handle_);
    }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    [[nodiscard]] typename Traits::value_type get() const
    {
        return handle_;
    }

  private:
    typename Traits::value_type handle_;
};

// CreateFileW yields INVALID_HANDLE_VALUE on failure; CreateFileMappingW,
// CreateProcessW yield null.
using UniqueFileHandle = UniqueHandle<InvalidHandleTraits>;
using UniqueObjectHandle = UniqueHandle<NullHandleTraits>;

// Owns the handles of the spawned sample; the sample spins forever once
// resumed, so it is terminated on every destruction - successful snapshot or
// failed capture.
struct SpawnedSample {
    SpawnedSample() = default;
    SpawnedSample(SpawnedSample&&) = default;
    SpawnedSample& operator=(SpawnedSample&&) = default;
    SpawnedSample(const SpawnedSample&) = delete;
    SpawnedSample& operator=(const SpawnedSample&) = delete;
    ~SpawnedSample()
    {
        if (proc_handle.get() != nullptr) {
            TerminateProcess(proc_handle.get(), 0);
        }
    }

    UniqueObjectHandle proc_handle{nullptr};
    UniqueObjectHandle thread_handle{nullptr};
    bool is_wow64{}; // IsWow64Process on the spawned handle: 32-bit semantics
    std::uint64_t peb_address{};
    std::uint64_t image_base{};
    std::uint64_t preferred_base{};
    std::uint64_t entry_va{};
    std::array<std::uint8_t, snapshot::kOriginalEntryBytes> original_entry{};
};

// RAII wrapper for the extended startup-info attribute list. The backing
// buffer is a plain byte vector sized by InitializeProcThreadAttributeList;
// UpdateProcThreadAttribute stores pointers to attached values without
// copying, so attached values live as members until the list is deleted.
class ProcThreadAttributeList {
  public:
    explicit ProcThreadAttributeList(const std::size_t attribute_count)
    {
        SIZE_T buffer_size = 0;
        ::InitializeProcThreadAttributeList(nullptr, static_cast<DWORD>(attribute_count), 0,
                                            &buffer_size);
        buffer_.resize(buffer_size);
        list_ = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(buffer_.data());
        if (!::InitializeProcThreadAttributeList(list_, static_cast<DWORD>(attribute_count), 0,
                                                 &buffer_size)) {
            list_ = nullptr;
        }
    }
    ~ProcThreadAttributeList()
    {
        if (list_ != nullptr) {
            DeleteProcThreadAttributeList(list_);
        }
    }
    ProcThreadAttributeList(const ProcThreadAttributeList&) = delete;
    ProcThreadAttributeList& operator=(const ProcThreadAttributeList&) = delete;

    [[nodiscard]] bool valid() const
    {
        return list_ != nullptr;
    }
    [[nodiscard]] LPPROC_THREAD_ATTRIBUTE_LIST get() const
    {
        return list_;
    }
    bool set_mitigation_policy(const std::uint64_t policy)
    {
        mitigation_policy_ = policy;
        return ::UpdateProcThreadAttribute(list_, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                                           &mitigation_policy_, sizeof mitigation_policy_, nullptr,
                                           nullptr) != 0;
    }

  private:
    std::vector<std::byte> buffer_;
    LPPROC_THREAD_ATTRIBUTE_LIST list_{};
    std::uint64_t mitigation_policy_{};
};

// Mirrors of PROCESS_BASIC_INFORMATION / THREAD_BASIC_INFORMATION; resolved
// dynamically so no ntdll import library is needed.
struct ProcessBasicInfo {
    LONG exit_status;
    void* peb_base_address;
    ULONG_PTR affinity_mask;
    LONG base_priority;
    ULONG_PTR unique_process_id;
    ULONG_PTR inherited_from_unique_process_id;
};
static_assert(sizeof(ProcessBasicInfo) == 48);

struct ThreadBasicInfo {
    LONG exit_status;
    void* teb_base_address;
    void* client_id_process;
    void* client_id_thread;
    ULONG_PTR affinity_mask;
    LONG priority;
};
static_assert(sizeof(ThreadBasicInfo) == 48);

using QueryInfoFn = LONG(NTAPI*)(HANDLE, ULONG, void*, ULONG, ULONG*);

template <typename Fn> Fn resolve_ntdll_api(const char* const name)
{
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll == nullptr
               ? nullptr
               : reinterpret_cast<Fn>(reinterpret_cast<void*>(GetProcAddress(ntdll, name)));
}

// The error channel carries the Win32 error code of the failed transfer.
std::expected<void, DWORD> read_process_memory(const HANDLE process, const std::uint64_t address,
                                               void* const buffer, const std::size_t size)
{
    auto* cursor = static_cast<std::uint8_t*>(buffer);
    std::size_t done = 0;
    while (done < size) {
        SIZE_T read = 0;
        if (ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address + done), cursor + done,
                              size - done, &read) == 0 ||
            read == 0) {
            return std::unexpected(GetLastError());
        }
        done += read;
    }
    return {};
}

std::expected<void, DWORD> write_process_memory(const HANDLE process, const std::uint64_t address,
                                                const void* const buffer, const std::size_t size)
{
    const auto* cursor = static_cast<const std::uint8_t*>(buffer);
    std::size_t done = 0;
    while (done < size) {
        SIZE_T written = 0;
        if (WriteProcessMemory(process, reinterpret_cast<LPVOID>(address + done),
                               const_cast<std::uint8_t*>(cursor + done), size - done,
                               &written) == 0 ||
            written == 0) {
            return std::unexpected(GetLastError());
        }
        done += written;
    }
    return {};
}

// Image pages reject raw WriteProcessMemory on some setups even when a
// sibling page took the entry patch, so the two patches take the trainer
// route: flip the page writable, write, restore, flush the instruction cache.
std::expected<void, DWORD> patch_image_memory(const HANDLE process, const std::uint64_t address,
                                              const void* const buffer, const std::size_t size)
{
    DWORD old_protection = 0;
    if (VirtualProtectEx(process, reinterpret_cast<LPVOID>(address), size, PAGE_READWRITE,
                         &old_protection) == 0) {
        return std::unexpected(GetLastError());
    }
    const auto written = write_process_memory(process, address, buffer, size);
    DWORD restored = 0;
    VirtualProtectEx(process, reinterpret_cast<LPVOID>(address), size, old_protection, &restored);
    if (written.has_value()) {
        FlushInstructionCache(process, reinterpret_cast<LPCVOID>(address), size);
    }
    return written;
}

// Guard pages and no-access pages carry facts (protection, type) but no
// readable payload; the engine maps them as UC_PROT_NONE, same semantics.
bool protection_readable(const DWORD protect)
{
    if ((protect & PAGE_GUARD) != 0) {
        return false;
    }
    switch (protect & 0xFF) {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

Result fail(const Status status, std::string detail)
{
    return {status, std::move(detail)};
}

std::expected<PeImageInfo, std::string> read_sample_headers(const std::filesystem::path& path)
{
    std::error_code ec;
    const auto file_size = std::filesystem::file_size(path, ec);
    if (ec) {
        return std::unexpected(std::format("cannot stat sample: {}", ec.message()));
    }
    UniqueFileHandle file{CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
    if (file.get() == INVALID_HANDLE_VALUE) {
        return std::unexpected(std::format("cannot open sample (Win32 error {})", GetLastError()));
    }
    UniqueObjectHandle mapping{
        CreateFileMappingW(file.get(), nullptr, PAGE_READONLY, 0, 0, nullptr)};
    if (mapping.get() == nullptr) {
        return std::unexpected(std::format("cannot map sample (Win32 error {})", GetLastError()));
    }
    const auto* view =
        static_cast<const std::uint8_t*>(MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0, 0));
    if (view == nullptr) {
        return std::unexpected(
            std::format("cannot map sample view (Win32 error {})", GetLastError()));
    }
    PeImageInfo info;
    const auto error = parse_pe_headers(view, static_cast<std::size_t>(file_size), info);
    UnmapViewOfFile(view);
    if (error != PeError::kNone) {
        return std::unexpected(std::string(pe_error_message(error)));
    }
    return info;
}

// Phase 1: spawn the sample suspended under the real loader, patch its entry
// into the in-place spin and zero its TLS callback array. On success the
// sample has executed zero instructions of its own.
std::expected<SpawnedSample, Result> spawn_sample(const Options& options,
                                                  const PeImageInfo& headers,
                                                  const std::filesystem::path& controlled_cwd = {})
{
    ProcThreadAttributeList attribute_list{1};
    auto creation_flags = DWORD{CREATE_SUSPENDED};
    STARTUPINFOEXW startup_info{};
    startup_info.StartupInfo.cb = sizeof startup_info;
    if (options.disable_aslr) {
        // Clear both ASLR policy bits so the loader honors preferred bases and
        // repeated captures see an identical layout.
        if (!attribute_list.valid()) {
            return std::unexpected(
                fail(Status::kSpawnFailed, "cannot initialize the process attribute list"));
        }
        if (!attribute_list.set_mitigation_policy(kNoAslrMitigationPolicy)) {
            return std::unexpected(
                fail(Status::kSpawnFailed, "cannot set the ASLR mitigation policy"));
        }
        startup_info.lpAttributeList = attribute_list.get();
        creation_flags |= EXTENDED_STARTUPINFO_PRESENT;
    }

    auto command = L"\"" + options.sample_path.wstring() + L"\"";
    if (!options.sample_args.empty()) {
        command += L" ";
        command += std::wstring(options.sample_args.begin(), options.sample_args.end());
    }
    // Controlled working directory (DLL-input route): the runner is spawned
    // with its own empty temp directory as CWD, so nothing in the analyst's
    // directory influences the loader's search path.
    const std::wstring controlled_cwd_w =
        controlled_cwd.empty() ? std::wstring{} : controlled_cwd.wstring();
    const wchar_t* const cwd = controlled_cwd_w.empty() ? nullptr : controlled_cwd_w.c_str();
    PROCESS_INFORMATION process_info{};
    const auto created = CreateProcessW(
        options.sample_path.c_str(), command.data(), nullptr, nullptr, FALSE, creation_flags,
        nullptr, const_cast<LPWSTR>(cwd), &startup_info.StartupInfo, &process_info);
    if (created == 0) {
        return std::unexpected(
            fail(Status::kSpawnFailed,
                 std::format("CreateProcessW failed (Win32 error {})", GetLastError())));
    }

    SpawnedSample sample;
    sample.proc_handle = UniqueObjectHandle{process_info.hProcess};
    sample.thread_handle = UniqueObjectHandle{process_info.hThread};

    const auto query_process = resolve_ntdll_api<QueryInfoFn>("NtQueryInformationProcess");
    ProcessBasicInfo process_basic{};
    if (query_process == nullptr ||
        query_process(sample.proc_handle.get(), 0 /*ProcessBasicInformation*/, &process_basic,
                      sizeof process_basic, nullptr) != 0) {
        return std::unexpected(
            fail(Status::kQueryFailed, "cannot query process basic information (PEB)"));
    }
    BOOL is_wow64_process = FALSE;
    IsWow64Process(sample.proc_handle.get(), &is_wow64_process);
    sample.is_wow64 = is_wow64_process != FALSE;
    // x64 PEB: ImageBaseAddress at +0x10 (8 bytes). WOW64: the loader fills
    // the 32-bit PEB (ProcessWow64Information) whose ImageBaseAddress sits
    // at +0x08 as a 4-byte value; the 64-bit PEB of the host loader is not
    // the sample address space this snapshot is about.
    constexpr std::size_t kPebImageBaseOffset32 = 0x08;
    if (sample.is_wow64) {
        PVOID peb32 = nullptr;
        if (query_process == nullptr ||
            query_process(sample.proc_handle.get(), 26 /*ProcessWow64Information*/, &peb32,
                          sizeof peb32, nullptr) != 0 ||
            peb32 == nullptr) {
            return std::unexpected(
                fail(Status::kQueryFailed, "cannot query the wow64 PEB location"));
        }
        sample.peb_address = reinterpret_cast<std::uint64_t>(peb32);
        std::uint32_t image_base32 = 0;
        if (const auto read = read_process_memory(sample.proc_handle.get(),
                                                  sample.peb_address + kPebImageBaseOffset32,
                                                  &image_base32, sizeof image_base32);
            !read) {
            return std::unexpected(
                fail(Status::kQueryFailed,
                     std::format("cannot read the wow64 PEB image base (Win32 error {})",
                                 read.error())));
        }
        sample.image_base = image_base32;
    } else {
        sample.peb_address = reinterpret_cast<std::uint64_t>(process_basic.peb_base_address);
        if (const auto read = read_process_memory(sample.proc_handle.get(),
                                                  sample.peb_address + kPebImageBaseOffset,
                                                  &sample.image_base, sizeof sample.image_base);
            !read) {
            return std::unexpected(
                fail(Status::kQueryFailed,
                     std::format("cannot read the PEB image base (Win32 error {})", read.error())));
        }
    }
    std::array<std::uint8_t, 2> mz{};
    if (const auto read =
            read_process_memory(sample.proc_handle.get(), sample.image_base, mz.data(), mz.size());
        !read) {
        return std::unexpected(
            fail(Status::kQueryFailed,
                 std::format("cannot read the image header (Win32 error {})", read.error())));
    }
    if (mz[0] != 'M' || mz[1] != 'Z') {
        return std::unexpected(
            fail(Status::kQueryFailed, "PEB image base sanity check failed (MZ missing)"));
    }
    sample.entry_va = sample.image_base + headers.entry_rva;
    sample.preferred_base = headers.preferred_base;

    std::array<std::uint8_t, snapshot::kOriginalEntryBytes> original_entry{};
    if (const auto read = read_process_memory(sample.proc_handle.get(), sample.entry_va,
                                              original_entry.data(), original_entry.size());
        !read) {
        return std::unexpected(fail(
            Status::kPatchFailed,
            std::format("cannot read the original entry bytes (Win32 error {})", read.error())));
    }
    sample.original_entry = original_entry;
    constexpr std::uint8_t kEntrySpin[2] = {0xEB, 0xFE}; // jmp $
    if (const auto written = patch_image_memory(sample.proc_handle.get(), sample.entry_va,
                                                kEntrySpin, sizeof kEntrySpin);
        !written) {
        return std::unexpected(
            fail(Status::kPatchFailed,
                 std::format("cannot patch the entry point (Win32 error {})", written.error())));
    }
    FlushInstructionCache(sample.proc_handle.get(), reinterpret_cast<LPCVOID>(sample.entry_va),
                          sizeof kEntrySpin);

    if (headers.has_tls) {
        // Zero the first callback pointer: the loader skips an array whose
        // first element is null, so no sample instruction runs in the real
        // process while TLS data structures are still built.
        // Directory shapes follow the magic: 40-byte x64 (callbacks pointer
        // at +0x18, 8-byte entries) vs 24-byte x86 (+0x0C, 4-byte entries).
        constexpr std::size_t kTlsDir32Size = 24;
        constexpr std::size_t kTlsCallbacksOffset32 = 0x0C;
        alignas(TlsDirectory64) std::array<std::uint8_t, sizeof(TlsDirectory64)> tls_bytes{};
        const auto tls_dir_size = sample.is_wow64 ? kTlsDir32Size : sizeof(TlsDirectory64);
        if (const auto read = read_process_memory(sample.proc_handle.get(),
                                                  sample.image_base + headers.tls_directory_rva,
                                                  tls_bytes.data(), tls_dir_size);
            !read) {
            return std::unexpected(
                fail(Status::kPatchFailed,
                     std::format("cannot read the TLS directory (Win32 error {})", read.error())));
        }
        const std::uint64_t callbacks_va =
            sample.is_wow64
                ? read_u32_le(tls_bytes.data() + kTlsCallbacksOffset32)
                : reinterpret_cast<const TlsDirectory64*>(tls_bytes.data())->address_of_callbacks;
        // The kernel applies relocations while mapping the image, so the
        // directory already holds actual-base pointers at the snapshot point.
        const std::uint64_t null_callback64 = 0;
        const std::uint32_t null_callback32 = 0;
        const auto* null_bytes = sample.is_wow64 ? reinterpret_cast<const void*>(&null_callback32)
                                                 : reinterpret_cast<const void*>(&null_callback64);
        const auto null_size = sample.is_wow64 ? sizeof null_callback32 : sizeof null_callback64;
        if (callbacks_va != 0) {
            if (const auto written = patch_image_memory(sample.proc_handle.get(), callbacks_va,
                                                        null_bytes, null_size);
                !written) {
                return std::unexpected(fail(
                    Status::kPatchFailed,
                    std::format("cannot zero the TLS callback array at 0x{:X} (Win32 error {})",
                                callbacks_va, written.error())));
            }
        }
    }
    return sample;
}

// Phase 2: resume the main thread and poll until it spins at the patched
// entry; on success the thread stays suspended at the snapshot point.
std::expected<void, Result> wait_for_entry_spin(SpawnedSample& sample,
                                                const std::chrono::milliseconds entry_timeout)
{
    if (ResumeThread(sample.thread_handle.get()) == static_cast<DWORD>(-1)) {
        return std::unexpected(fail(Status::kSpawnFailed, "cannot resume the sample thread"));
    }
    CONTEXT wait_context{};
    const auto deadline = std::chrono::steady_clock::now() + entry_timeout;
    std::uint64_t last_rip = 0;
    for (;;) {
        if (std::chrono::steady_clock::now() >= deadline) {
            break;
        }
        Sleep(10);
        if (SuspendThread(sample.thread_handle.get()) == static_cast<DWORD>(-1)) {
            continue;
        }
        std::uint64_t rip = 0;
        if (sample.is_wow64) {
            WOW64_CONTEXT wow64_wait{};
            wow64_wait.ContextFlags = WOW64_CONTEXT_CONTROL;
            if (Wow64GetThreadContext(sample.thread_handle.get(), &wow64_wait) == 0) {
                ResumeThread(sample.thread_handle.get());
                continue;
            }
            rip = wow64_wait.Eip;
        } else {
            wait_context.ContextFlags = CONTEXT_CONTROL;
            if (GetThreadContext(sample.thread_handle.get(), &wait_context) == 0) {
                ResumeThread(sample.thread_handle.get());
                continue;
            }
            rip = wait_context.Rip;
        }
        last_rip = rip;
        if (rip == sample.entry_va) {
            return {};
        }
        ResumeThread(sample.thread_handle.get());
    }
    return std::unexpected(
        fail(Status::kEntryTimeout,
             std::format("the sample never reached the entry spin (image 0x{:X}, preferred 0x{:X}, "
                         "last RIP 0x{:X})",
                         sample.image_base, sample.preferred_base, last_rip)));
}

// Phase 3: photograph registers, TEB and all committed regions into the
// writer; returns the summary line for the CLI. The pending module (the
// DLL-input route) rides into the trailing block area by the caller; the
// header is v3 either way (the clock block is unconditional).
std::expected<std::string, Result> capture_state(SpawnedSample& sample, snapshot::Writer& writer,
                                                 const snapshot::PendingModule* pending = nullptr)
{
    static_cast<void>(pending);
    // Register photograph follows the sampled world: WOW64 threads give
    // their 32-bit context only through the Wow64 API pair (the 64-bit
    // CONTEXT of the same thread describes the host-mode half).
    CONTEXT full_context{};
    WOW64_CONTEXT wow64_context{};
    if (sample.is_wow64) {
        wow64_context.ContextFlags = WOW64_CONTEXT_ALL;
        if (Wow64GetThreadContext(sample.thread_handle.get(), &wow64_context) == 0) {
            return std::unexpected(
                fail(Status::kCaptureFailed, "cannot get the wow64 thread context"));
        }
    } else {
        full_context.ContextFlags = CONTEXT_ALL;
        if (GetThreadContext(sample.thread_handle.get(), &full_context) == 0) {
            return std::unexpected(fail(Status::kCaptureFailed, "cannot get the thread context"));
        }
    }
    std::uint64_t teb_address = 0;
    if (sample.is_wow64) {
        // The 32-bit TEB is not the TEB64 ThreadBasicInformation reports;
        // its linear address is the FS descriptor base of the wow64 thread.
        WOW64_LDT_ENTRY fs_entry{};
        if (Wow64GetThreadSelectorEntry(sample.thread_handle.get(), wow64_context.SegFs,
                                        &fs_entry) == 0) {
            return std::unexpected(
                fail(Status::kQueryFailed, "cannot read the wow64 FS descriptor"));
        }
        teb_address = static_cast<std::uint64_t>(fs_entry.BaseLow) |
                      (static_cast<std::uint64_t>(fs_entry.HighWord.Bits.BaseMid) << 16) |
                      (static_cast<std::uint64_t>(fs_entry.HighWord.Bits.BaseHi) << 24);
    } else {
        const auto query_thread = resolve_ntdll_api<QueryInfoFn>("NtQueryInformationThread");
        ThreadBasicInfo thread_basic{};
        if (query_thread == nullptr ||
            query_thread(sample.thread_handle.get(), 0 /*ThreadBasicInformation*/, &thread_basic,
                         sizeof thread_basic, nullptr) != 0) {
            return std::unexpected(
                fail(Status::kQueryFailed, "cannot query thread basic information (TEB)"));
        }
        teb_address = reinterpret_cast<std::uint64_t>(thread_basic.teb_base_address);
    }

    snapshot::Registers registers{};
    if (sample.is_wow64) {
        // the contract keeps R8..R15 zero for 32-bit snapshots
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRax)] = wow64_context.Eax;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRcx)] = wow64_context.Ecx;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRdx)] = wow64_context.Edx;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRbx)] = wow64_context.Ebx;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRsp)] = wow64_context.Esp;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRbp)] = wow64_context.Ebp;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRsi)] = wow64_context.Esi;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRdi)] = wow64_context.Edi;
        registers.rip = wow64_context.Eip;
        registers.rflags = wow64_context.EFlags;
    } else {
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRax)] = full_context.Rax;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRcx)] = full_context.Rcx;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRdx)] = full_context.Rdx;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRbx)] = full_context.Rbx;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRsp)] = full_context.Rsp;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRbp)] = full_context.Rbp;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRsi)] = full_context.Rsi;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRdi)] = full_context.Rdi;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kR8)] = full_context.R8;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kR9)] = full_context.R9;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kR10)] = full_context.R10;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kR11)] = full_context.R11;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kR12)] = full_context.R12;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kR13)] = full_context.R13;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kR14)] = full_context.R14;
        registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kR15)] = full_context.R15;
        registers.rip = full_context.Rip;
        registers.rflags = full_context.EFlags;
    }

    const snapshot::Metadata metadata{
        .bitness = sample.is_wow64 ? snapshot::kBitness32 : snapshot::kBitness64,
        .peb_address = sample.peb_address,
        .teb_address = teb_address,
        .image_base = sample.image_base,
        .entry_address = sample.entry_va,
        .original_entry_bytes = sample.original_entry,
    };

    const auto write_fail = [](const snapshot::Error error) {
        return fail(Status::kWriteFailed, std::string(snapshot::error_message(error)));
    };
    const auto snapshot_bitness = sample.is_wow64 ? snapshot::kBitness32 : snapshot::kBitness64;
    // The engine production write path pins the default clock policy and
    // writes v3 unconditionally - EXE and DLL-input containers alike (the
    // clock block rides after the optional pending block). The clock is an
    // engine constant, never a host measurement.
    if (const auto written = writer.write_header(
            snapshot::Header{.version = snapshot::kVersionV3, .bitness = snapshot_bitness});
        !written) {
        return std::unexpected(write_fail(written.error()));
    }
    if (const auto written = writer.write_registers(registers); !written) {
        return std::unexpected(write_fail(written.error()));
    }
    if (const auto written = writer.write_metadata(metadata); !written) {
        return std::unexpected(write_fail(written.error()));
    }

    auto region_count = std::uint32_t{0};
    auto region_bytes = std::uint64_t{0};
    auto address = std::uint64_t{0};
    for (;;) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(sample.proc_handle.get(), reinterpret_cast<LPCVOID>(address), &mbi,
                           sizeof mbi) == 0) {
            break;
        }
        const auto region_base = reinterpret_cast<std::uint64_t>(mbi.BaseAddress);
        const auto region_size = static_cast<std::uint64_t>(mbi.RegionSize);
        if ((mbi.State & MEM_COMMIT) != 0 && region_size > 0) {
            snapshot::RegionHeader region_header{
                .base_address = region_base,
                .size = region_size,
                .protection = mbi.Protect,
                .type = mbi.Type,
                .content = snapshot::kContentAbsent,
            };
            std::vector<std::uint8_t> bytes;
            if (protection_readable(mbi.Protect)) {
                bytes.resize(static_cast<std::size_t>(region_size));
                if (const auto read = read_process_memory(sample.proc_handle.get(), region_base,
                                                          bytes.data(), bytes.size());
                    !read) {
                    return std::unexpected(
                        fail(Status::kCaptureFailed,
                             std::format("ReadProcessMemory failed for readable region at 0x{:X} "
                                         "(Win32 error {})",
                                         region_base, read.error())));
                }
                region_header.content = snapshot::kContentPresent;
            }
            if (const auto written =
                    writer.write_region(region_header, bytes.empty() ? nullptr : bytes.data());
                !written) {
                return std::unexpected(write_fail(written.error()));
            }
            ++region_count;
            region_bytes += bytes.size();
        }
        const auto next = region_base + region_size;
        if (next <= address) {
            break; // address space wrapped around
        }
        address = next;
    }
    return std::format("{} regions, {} bytes", region_count, region_bytes);
}

} // namespace

bool capture_available()
{
    return true;
}

// RAII guard for the wrapped-blob temp file: every exit path (including a
// failed capture) removes it; the random name never reaches any output.
class TempFileGuard {
  public:
    TempFileGuard(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes)
    {
        std::error_code ec;
        path_ = path;
        std::ofstream out(path_, std::ios::binary | std::ios::trunc);
        if (!out) {
            path_.clear();
            return;
        }
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        out.close();
        if (!out) {
            std::filesystem::remove(path_, ec);
            path_.clear();
        }
    }
    ~TempFileGuard()
    {
        if (!path_.empty()) {
            // the spawned process may still hold the image mapped for a
            // moment: retry while the kernel releases the last handle
            std::error_code ec;
            for (int attempt = 0; attempt < 100; ++attempt) {
                std::filesystem::remove(path_, ec);
                if (!std::filesystem::exists(path_, ec)) {
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
    }
    TempFileGuard(const TempFileGuard&) = delete;
    TempFileGuard& operator=(const TempFileGuard&) = delete;
    bool ok() const
    {
        return !path_.empty();
    }
    const std::filesystem::path& path() const
    {
        return path_;
    }

  private:
    std::filesystem::path path_;
};

// Input normalization: a bare shellcode blob -
// auto-detected by the missing MZ, or forced by the flag - is wrapped into
// a minimal PE and the capture proceeds against that temp file. A DLL
// input takes its own route: the system-dependency admission produces a
// load-stub runner (the sample's dependencies preload through the runner's
// own import table), the runner is what gets spawned, and the sample bytes
// ride beside the snapshot as the pending module. The guard lives in the
// caller's run scope: the spawned process maps the temp image until the
// capture is done, so deletion must wait for it.
struct EffectiveCapture {
    Options options{};
    std::unique_ptr<TempFileGuard> wrapper;
    WrapError wrap_error{WrapError::kNone}; // blob and temp-directory failures
    // DLL-input route (empty for EXE/blob inputs):
    std::optional<snapshot::PendingModule> pending{}; // sample bytes + arrival name
    std::optional<Result> admission_failure{};        // named pre-spawn rejection
};

// DLL-input route. Returns true when the route took over (either the
// pending module is armed or a named admission failure is set); false
// means "not a DLL input, continue with EXE passthrough".
bool normalize_dll_input(const Options& options, const std::vector<std::uint8_t>& bytes,
                         EffectiveCapture& effective)
{
    PeImageInfo info;
    if (parse_pe_headers(bytes.data(), bytes.size(), info) != PeError::kNone || !info.is_dll) {
        return false;
    }
    if (info.bitness != 64) {
        effective.admission_failure =
            fail(Status::kNotX64Pe, "DLL input is only supported for x64 images");
        return true;
    }
    const std::string arrival_name = options.sample_path.filename().string();
    const auto plan = admit_dll_sample(bytes, arrival_name);
    if (!plan) {
        effective.admission_failure =
            fail(Status::kNotX64Pe, std::format("DLL input rejected: {}", plan.error()));
        return true;
    }
    const auto runner = build_runner(*plan);
    if (!runner) {
        effective.admission_failure =
            fail(Status::kCaptureFailed, std::string(runner_error_message(runner.error())));
        return true;
    }
    thread_local std::mt19937_64 generator{std::random_device{}()};
    char name[32] = {};
    std::snprintf(name, sizeof name, "sheller_run_%llx.exe",
                  static_cast<unsigned long long>(generator()));
    std::error_code temp_ec;
    const auto temp_dir = std::filesystem::temp_directory_path(temp_ec);
    if (temp_ec) {
        effective.wrap_error = WrapError::kTempDirUnavailable;
        return true;
    }
    effective.wrapper = std::make_unique<TempFileGuard>(temp_dir / name, *runner);
    if (!effective.wrapper->ok()) {
        effective.wrapper.reset();
        effective.wrap_error = WrapError::kTempDirUnavailable;
        return true;
    }
    effective.options = options;
    effective.options.sample_path = effective.wrapper->path();
    effective.pending = snapshot::PendingModule{
        .name = arrival_name, .bitness = snapshot::kBitness64, .bytes = bytes};
    return true;
}

EffectiveCapture normalize_input(const Options& options)
{
    EffectiveCapture effective;
    std::error_code exists_ec;
    if (!std::filesystem::exists(options.sample_path, exists_ec)) {
        effective.options = options;
        return effective; // start_capture reports sample-not-found
    }
    if (!options.shellcode) {
        std::ifstream in(options.sample_path, std::ios::binary);
        std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(in),
                                        std::istreambuf_iterator<char>()};
        if (looks_like_pe(bytes)) {
            if (normalize_dll_input(options, bytes, effective)) {
                return effective; // DLL route handled (pending armed or named failure)
            }
            effective.options = options; // standard PE input: pass through
            return effective;
        }
    }
    std::ifstream in(options.sample_path, std::ios::binary);
    std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(in),
                                    std::istreambuf_iterator<char>()};
    const auto wrapped = wrap_blob(WrapArch::kX64, bytes);
    if (!wrapped) {
        effective.wrap_error = wrapped.error();
        return effective;
    }
    // Per thread, not per process: this name is the collision point when two hosts
    // drive the same blob at once, and a shared generator would itself be mutable
    // process-global state on that path. The seed source is a temporary - it is
    // seeding, not state worth keeping alive.
    thread_local std::mt19937_64 generator{std::random_device{}()};
    char name[32] = {};
    std::snprintf(name, sizeof name, "sheller_wrap_%llx.exe",
                  static_cast<unsigned long long>(generator()));
    // The ec overload, not the throwing one: this runs on the capture path, where
    // a host with no resolvable temp directory is supposed to get a Status back,
    // not an exception it was never told to catch.
    std::error_code temp_ec;
    const auto temp_dir = std::filesystem::temp_directory_path(temp_ec);
    if (temp_ec) {
        effective.wrap_error = WrapError::kTempDirUnavailable;
        return effective;
    }
    effective.wrapper = std::make_unique<TempFileGuard>(temp_dir / name, *wrapped);
    if (!effective.wrapper->ok()) {
        effective.wrapper.reset();
        return effective;
    }
    effective.options = options;
    effective.options.sample_path = effective.wrapper->path();
    return effective;
}

std::expected<SpawnedSample, Result> start_capture(const Options& options,
                                                   const std::filesystem::path& controlled_cwd = {})
{
    std::error_code ec;
    if (!std::filesystem::exists(options.sample_path, ec) || ec) {
        return std::unexpected(
            fail(Status::kSampleNotFound,
                 std::format("sample not found: {}", options.sample_path.string())));
    }
    const auto headers = read_sample_headers(options.sample_path);
    if (!headers) {
        return std::unexpected(fail(Status::kNotX64Pe, headers.error()));
    }
    auto sample = spawn_sample(options, *headers, controlled_cwd);
    if (!sample) {
        return sample;
    }
    if (const auto spun = wait_for_entry_spin(*sample, options.entry_timeout); !spun) {
        return std::unexpected(spun.error());
    }
    return sample;
}

namespace detail {

// The snapshot-production entry, under its internal name: the public
// sheller::capture::run is defined by the shared interface library and
// forwards here (capture_stub.cpp carries the matching name for every other
// host, so the link face stays identical on both platforms).
Result run_impl(const Options& options)
{
    auto effective = normalize_input(options);
    if (effective.wrap_error != WrapError::kNone) {
        return fail(wrap_status(effective.wrap_error),
                    std::string(wrap_error_message(effective.wrap_error)));
    }
    if (effective.admission_failure) {
        return *effective.admission_failure; // named pre-spawn rejection
    }
    auto sample =
        start_capture(effective.options, effective.pending ? effective.wrapper->path().parent_path()
                                                           : std::filesystem::path{});
    if (!sample) {
        return sample.error();
    }

    std::ofstream out(options.output_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return fail(Status::kWriteFailed,
                    std::format("cannot open output: {}", options.output_path.string()));
    }
    snapshot::Writer writer{out};
    const auto captured =
        capture_state(*sample, writer, effective.pending ? &*effective.pending : nullptr);
    if (!captured) {
        return captured.error();
    }
    if (const auto finalized = writer.finalize_region_count(); !finalized) {
        return fail(Status::kWriteFailed, std::string(snapshot::error_message(finalized.error())));
    }
    if (effective.pending) {
        if (const auto written = writer.write_pending(*effective.pending); !written) {
            return fail(Status::kWriteFailed,
                        std::string(snapshot::error_message(written.error())));
        }
    }
    if (const auto written = writer.write_clock(snapshot::default_clock_policy()); !written) {
        return fail(Status::kWriteFailed, std::string(snapshot::error_message(written.error())));
    }
    out.flush();
    if (!out) {
        return fail(Status::kWriteFailed, "cannot flush the snapshot file");
    }
    return {Status::kOk, std::format("{}, -> {}", *captured, options.output_path.string())};
}

} // namespace detail

Result run_to_buffer(const Options& options, std::vector<std::uint8_t>& snapshot)
{
    auto effective = normalize_input(options);
    if (effective.wrap_error != WrapError::kNone) {
        return fail(wrap_status(effective.wrap_error),
                    std::string(wrap_error_message(effective.wrap_error)));
    }
    if (effective.admission_failure) {
        return *effective.admission_failure; // named pre-spawn rejection
    }
    auto sample =
        start_capture(effective.options, effective.pending ? effective.wrapper->path().parent_path()
                                                           : std::filesystem::path{});
    if (!sample) {
        return sample.error();
    }

    std::ostringstream out(std::ios::binary);
    snapshot::Writer writer{out};
    const auto captured =
        capture_state(*sample, writer, effective.pending ? &*effective.pending : nullptr);
    if (!captured) {
        return captured.error();
    }
    if (const auto finalized = writer.finalize_region_count(); !finalized) {
        return fail(Status::kWriteFailed, std::string(snapshot::error_message(finalized.error())));
    }
    if (effective.pending) {
        if (const auto written = writer.write_pending(*effective.pending); !written) {
            return fail(Status::kWriteFailed,
                        std::string(snapshot::error_message(written.error())));
        }
    }
    if (const auto written = writer.write_clock(snapshot::default_clock_policy()); !written) {
        return fail(Status::kWriteFailed, std::string(snapshot::error_message(written.error())));
    }
    const std::string bytes = out.str();
    snapshot.assign(bytes.begin(), bytes.end());
    return {Status::kOk, std::format("{}", *captured)};
}

} // namespace sheller::capture
