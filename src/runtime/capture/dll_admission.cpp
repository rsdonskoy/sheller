// DLL-input admission, Windows side. See dll_admission.h for the contract.

#include "dll_admission.h"

#include "admission.h"
#include "pe_headers.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <deque>
#include <format>
#include <fstream>
#include <iterator>
#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <utility>

namespace sheller::capture {
namespace {

std::wstring to_wide(const std::string& text)
{
    std::wstring out(text.size() + 1, L'\0');
    const int written =
        MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, out.data(), static_cast<int>(out.size()));
    out.resize(written > 0 ? static_cast<std::size_t>(written - 1) : 0);
    return out;
}

// System-source proof: the module's loaded path must sit directly inside
// the system directory - no nested paths, no ".." hops, no file that merely
// shares a name with a system DLL. Case-insensitive throughout: the system
// directory's own spelling varies between API results.
bool under_system_directory(const std::wstring& path)
{
    wchar_t system_dir[MAX_PATH] = {};
    const auto length = GetSystemDirectoryW(system_dir, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return false;
    }
    auto lower = [](std::wstring text) {
        for (wchar_t& c : text) {
            c = static_cast<wchar_t>(towlower(c));
        }
        return text;
    };
    const std::wstring prefix = lower({system_dir, length});
    if (path.size() <= prefix.size() + 1) {
        return false;
    }
    const std::wstring lowered = lower(path);
    if (lowered.compare(0, prefix.size(), prefix) != 0 || path[prefix.size()] != L'\\') {
        return false;
    }
    const std::wstring rest = lowered.substr(prefix.size() + 1);
    return rest.find(L'\\') == std::wstring::npos && rest.find(L"..") == std::wstring::npos;
}

std::uint32_t rd32(const std::uint8_t* p)
{
    std::uint32_t v = 0;
    std::memcpy(&v, p, sizeof v);
    return v;
}

constexpr std::size_t kUnmapped = static_cast<std::size_t>(-1);

std::size_t rva_off(const std::span<const std::uint8_t> bytes, const std::int32_t lfanew,
                    const std::uint32_t rva)
{
    const std::uint16_t sections =
        *reinterpret_cast<const std::uint16_t*>(bytes.data() + lfanew + 6);
    const std::uint16_t opt_size =
        *reinterpret_cast<const std::uint16_t*>(bytes.data() + lfanew + 20);
    const std::uint32_t headers_size = rd32(bytes.data() + lfanew + 24 + 60);
    if (rva < headers_size) {
        return rva;
    }
    const std::size_t table = lfanew + 24 + opt_size;
    for (std::uint16_t i = 0; i < sections; ++i) {
        const std::size_t s = table + i * 40;
        if (s + 40 > bytes.size()) {
            return kUnmapped;
        }
        const std::uint32_t va = rd32(bytes.data() + s + 12);
        std::uint32_t span = rd32(bytes.data() + s + 8);
        const std::uint32_t raw = rd32(bytes.data() + s + 16);
        const std::uint32_t ptr = rd32(bytes.data() + s + 20);
        if (span == 0 || span > raw) {
            span = raw;
        }
        if (rva >= va && rva < va + span) {
            const std::size_t offset = ptr + (rva - va);
            return offset < bytes.size() ? offset : kUnmapped;
        }
    }
    return kUnmapped;
}

struct ExportTable {
    const std::uint8_t* data = nullptr;
    std::size_t size = 0;
    std::int32_t lfanew = 0;
    bool pe32plus = true;
    std::uint32_t dir_rva = 0;
    std::uint32_t dir_size = 0;
    std::uint32_t ordinal_base = 0;
    std::uint32_t function_count = 0;
    std::uint32_t name_count = 0;
    std::uint32_t functions_rva = 0;
    std::uint32_t names_rva = 0;
    std::uint32_t ordinals_rva = 0;
    bool valid = false;
};

ExportTable parse_exports(const std::span<const std::uint8_t> bytes)
{
    ExportTable table;
    if (bytes.size() < 0x40) {
        return table;
    }
    table.data = bytes.data();
    table.size = bytes.size();
    table.lfanew = static_cast<std::int32_t>(rd32(bytes.data() + 0x3C));
    if (table.lfanew < 0 || static_cast<std::size_t>(table.lfanew) + 24 > bytes.size()) {
        return table;
    }
    const std::uint16_t machine =
        *reinterpret_cast<const std::uint16_t*>(bytes.data() + table.lfanew + 4);
    table.pe32plus = machine == kMachineAmd64;
    if (!table.pe32plus && machine != kMachineI386) {
        return table;
    }
    const std::size_t dir_base = table.lfanew + 24 + (table.pe32plus ? 112 : 96);
    if (dir_base + 8 > bytes.size()) {
        return table;
    }
    table.dir_rva = rd32(bytes.data() + dir_base);
    table.dir_size = rd32(bytes.data() + dir_base + 4);
    if (table.dir_rva == 0) {
        return table;
    }
    const std::size_t dir = rva_off(bytes, table.lfanew, table.dir_rva);
    if (dir == kUnmapped || dir + 40 > bytes.size()) {
        return table;
    }
    table.ordinal_base = rd32(bytes.data() + dir + 16);
    table.function_count = rd32(bytes.data() + dir + 20);
    // IMAGE_EXPORT_DIRECTORY: NumberOfNames @+24, AddressOfFunctions @+28,
    // AddressOfNames @+32, AddressOfNameOrdinals @+36.
    table.name_count = rd32(bytes.data() + dir + 24);
    table.functions_rva = rd32(bytes.data() + dir + 28);
    table.names_rva = rd32(bytes.data() + dir + 32);
    table.ordinals_rva = rd32(bytes.data() + dir + 36);
    table.valid = table.function_count > 0 && table.functions_rva != 0;
    return table;
}

// Resolution outcome for one referenced symbol.
struct ExportHit {
    bool exported = false;
    bool forwarder = false;   // "DLL.Function" string
    std::string forwarded_to; // target DLL name when forwarder
};

ExportHit find_export(const ExportTable& table, const std::string& name,
                      const std::uint16_t ordinal, const bool by_ordinal)
{
    ExportHit hit;
    if (!table.valid) {
        return hit;
    }
    std::uint32_t function_rva = 0;
    if (by_ordinal) {
        if (ordinal < table.ordinal_base ||
            static_cast<std::uint32_t>(ordinal - table.ordinal_base) >= table.function_count) {
            return hit;
        }
        const std::size_t arr = rva_off({table.data, table.size}, table.lfanew,
                                        table.functions_rva + 4u * (ordinal - table.ordinal_base));
        if (arr == kUnmapped) {
            return hit;
        }
        function_rva = rd32(table.data + arr);
    } else {
        bool matched = false;
        for (std::uint32_t i = 0; i < table.name_count && i < 65536; ++i) {
            const std::size_t name_slot =
                rva_off({table.data, table.size}, table.lfanew, table.names_rva + 4u * i);
            if (name_slot == kUnmapped) {
                break;
            }
            const std::size_t candidate =
                rva_off({table.data, table.size}, table.lfanew, rd32(table.data + name_slot));
            if (candidate == kUnmapped) {
                continue;
            }
            const char* candidate_name = reinterpret_cast<const char*>(table.data + candidate);
            if (std::string_view{candidate_name} != name) {
                continue;
            }
            const std::size_t ord_slot =
                rva_off({table.data, table.size}, table.lfanew, table.ordinals_rva + 2u * i);
            if (ord_slot == kUnmapped) {
                return hit;
            }
            const auto ord_index = *reinterpret_cast<const std::uint16_t*>(table.data + ord_slot);
            const std::size_t arr = rva_off({table.data, table.size}, table.lfanew,
                                            table.functions_rva + 4u * ord_index);
            if (arr == kUnmapped) {
                return hit;
            }
            function_rva = rd32(table.data + arr);
            matched = true;
            break;
        }
        if (!matched) {
            return hit;
        }
    }
    if (function_rva == 0) {
        return hit;
    }
    if (function_rva >= table.dir_rva && function_rva < table.dir_rva + table.dir_size) {
        const std::size_t fwd = rva_off({table.data, table.size}, table.lfanew, function_rva);
        if (fwd == kUnmapped) {
            return hit;
        }
        const char* text = reinterpret_cast<const char*>(table.data + fwd);
        std::string forwarding{text};
        const auto dot = forwarding.find('.');
        if (dot == std::string::npos) {
            return hit; // malformed forwarder: treat as not exported
        }
        hit.exported = true;
        hit.forwarder = true;
        hit.forwarded_to = forwarding.substr(0, dot);
        return hit;
    }
    hit.exported = true;
    return hit;
}

std::string admission_error(const std::string& module, const char* reason)
{
    return std::format("dependency {}: {}", module, reason);
}

// One verified system module, owned by the source for the admission pass.
// The export table's pointers index `bytes_`, which lives as long as the view;
// the view is constructed in place in the source's deque and never moved.
class SystemModuleView final : public ModuleView {
  public:
    SystemModuleView(std::string spelled, std::vector<std::uint8_t> bytes)
        : spelled_(std::move(spelled)), bytes_(std::move(bytes))
    {
        name = spelled_;
        std::vector<PeImportThunk> parsed;
        if (parse_imports(bytes_.data(), bytes_.size(), parsed) == PeError::kNone) {
            closure_imports_ = std::move(parsed);
        }
        exports_ = parse_exports({bytes_.data(), bytes_.size()});
    }

    SystemModuleView(const SystemModuleView&) = delete;
    SystemModuleView& operator=(const SystemModuleView&) = delete;
    SystemModuleView(SystemModuleView&&) = delete;
    SystemModuleView& operator=(SystemModuleView&&) = delete;

    std::expected<Hit, std::string> resolves(const std::string_view symbol,
                                             const std::uint16_t ordinal) override
    {
        const ExportHit found = find_export(exports_, std::string{symbol}, ordinal, symbol.empty());
        Hit hit;
        hit.exported = found.exported;
        hit.forwarder = found.forwarder;
        hit.forward_to = found.forwarded_to;
        return hit;
    }

    std::span<const PeImportThunk> imports() const override
    {
        return closure_imports_;
    }

  private:
    std::string spelled_;
    std::vector<std::uint8_t> bytes_;
    ExportTable exports_;
    std::vector<PeImportThunk> closure_imports_;
};

// The Windows route's module source: the operating system is the trusted world.
// The data-file probe is the primary path (search set is exactly the system
// directory and no code runs); API-set virtual names fail it and fall through
// to a real system32-only load whose module path is checked back. The handle is
// released inside acquire - the skeleton never holds a library reference. The
// verified bytes (and their parsed export/import tables) are retained per view
// for the admission pass: the skeleton may look at a module again while its
// closure is walked, and the sample's own dependency count is bounded by
// parse_imports (64 descriptors).
class SystemModuleSource final : public ModuleSource {
  public:
    ModuleView* acquire(const std::string_view spelled, const std::string_view,
                        std::string& error) override
    {
        const std::string module{spelled};
        HMODULE map = LoadLibraryExW(to_wide(module).c_str(), nullptr,
                                     LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_AS_DATAFILE);
        const bool via_datafile = map != nullptr;
        if (map == nullptr) {
            map = LoadLibraryExW(to_wide(module).c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        }
        if (map == nullptr) {
            error = admission_error(module, "not a verifiable system module");
            return nullptr;
        }
        // RAII in every direction: an early refusal below cannot leak the
        // reference, and the success path releases explicitly before the reads.
        struct ModuleHandle {
            HMODULE value;
            ~ModuleHandle()
            {
                if (value != nullptr) {
                    FreeLibrary(value);
                }
            }
        } handle{map};
        wchar_t module_path[MAX_PATH * 2] = {};
        bool path_ok = true;
        if (!via_datafile) {
            path_ok = GetModuleFileNameW(map, module_path, MAX_PATH * 2) != 0 &&
                      under_system_directory(module_path);
        }
        if (!path_ok) {
            error =
                admission_error(module, "resolves outside the system directory (private module)");
            return nullptr;
        }
        FreeLibrary(map);
        handle.value = nullptr;

        std::vector<std::uint8_t> module_bytes;
        if (via_datafile) {
            // Re-derive the verified file path for the byte reads below.
            wchar_t system_dir[MAX_PATH] = {};
            const auto length = GetSystemDirectoryW(system_dir, MAX_PATH);
            if (length == 0 || length >= MAX_PATH) {
                error = admission_error(module, "system directory unreadable");
                return nullptr;
            }
            std::wstring wide{system_dir, length};
            wide += L'\\';
            wide += to_wide(module);
            const int needed =
                WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
            std::string utf8(static_cast<std::size_t>(needed > 0 ? needed - 1 : 0), '\0');
            if (!utf8.empty()) {
                WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, utf8.data(),
                                    static_cast<int>(utf8.size() + 1), nullptr, nullptr);
            }
            std::ifstream in(utf8, std::ios::binary);
            module_bytes = std::vector<std::uint8_t>{std::istreambuf_iterator<char>(in),
                                                     std::istreambuf_iterator<char>()};
        } else {
            std::ifstream in(module_path, std::ios::binary);
            module_bytes = std::vector<std::uint8_t>{std::istreambuf_iterator<char>(in),
                                                     std::istreambuf_iterator<char>()};
        }
        if (module_bytes.empty()) {
            error = admission_error(module, "system module unreadable");
            return nullptr;
        }
        views_.emplace_back(module, std::move(module_bytes));
        return &views_.back();
    }

    bool walk_full_closure() const override
    {
        return true;
    }

    std::string dependency_error(const std::string_view spelled,
                                 const AdmissionProblem problem) const override
    {
        const std::string module{spelled};
        switch (problem) {
        case AdmissionProblem::kCollisionWithSample:
            return admission_error(module, "dependency name collides with the sample");
        case AdmissionProblem::kPathShapedName:
            return admission_error(module, "path-shaped import name");
        case AdmissionProblem::kNoImportableExport:
            return admission_error(module, "no importable export for the referenced symbol");
        }
        return admission_error(module, "unverifiable dependency");
    }

  private:
    std::deque<SystemModuleView> views_;
};

} // namespace

std::expected<RunnerPlan, std::string>
admit_dll_sample(const std::vector<std::uint8_t>& sample_bytes, const std::string& arrival_name)
{
    SystemModuleSource source;
    return admit_sample(sample_bytes, arrival_name, source);
}

} // namespace sheller::capture
