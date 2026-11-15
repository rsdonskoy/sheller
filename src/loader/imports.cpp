#include "imports.h"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <optional>

namespace sheller::loader {
namespace {

constexpr std::uint32_t kDataDirectoryOffset64 = 112; // PE32+ optional+0x70
constexpr std::uint32_t kDataDirectoryOffset32 = 96;  // PE32  optional+0x60
constexpr std::size_t kMaxDescriptors = 256;          // import descriptors per image
constexpr std::size_t kMaxThunksPerDll = 8192;        // bounded walk
constexpr std::size_t kMaxForwardHops = 4;
constexpr std::size_t kMaxExportName = 255;

std::uint16_t read16(std::span<const std::uint8_t> bytes, std::size_t offset)
{
    if (offset + 2 > bytes.size()) {
        return 0;
    }
    return static_cast<std::uint16_t>(bytes[offset] |
                                      (static_cast<std::uint16_t>(bytes[offset + 1]) << 8));
}

std::uint32_t read32(std::span<const std::uint8_t> bytes, std::size_t offset)
{
    if (offset + 4 > bytes.size()) {
        return 0;
    }
    std::uint32_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof value);
    return value;
}

std::uint64_t read64(std::span<const std::uint8_t> bytes, std::size_t offset)
{
    if (offset + 8 > bytes.size()) {
        return 0;
    }
    std::uint64_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof value);
    return value;
}

void write32(std::span<std::uint8_t> bytes, std::size_t offset, std::uint32_t value)
{
    if (offset + 4 <= bytes.size()) {
        std::memcpy(bytes.data() + offset, &value, sizeof value);
    }
}

void write64(std::span<std::uint8_t> bytes, std::size_t offset, std::uint64_t value)
{
    if (offset + 8 <= bytes.size()) {
        std::memcpy(bytes.data() + offset, &value, sizeof value);
    }
}

// Thunk width and directory placement follow the optional header magic of
// the image being walked.
struct ImportLayout {
    std::size_t import_dir_offset{}; // file offset of DataDirectory[1].VA
    std::size_t thunk_size{};        // 8 (PE32+) or 4 (PE32)
    std::uint64_t ordinal_flag{};    // high bit of a thunk entry
};

ImportLayout detect_layout(std::span<const std::uint8_t> image)
{
    const auto pe = read32(image, 0x3C);
    // DataDirectory[1].VA is pe-relative: sig(4) + COFF(20) + the optional
    // header's pre-directory prefix, then one 8-byte directory slot. A fixed
    // offset only fits hand-built images with a minimal DOS header.
    const auto import_dir = [&](const std::uint32_t prefix) -> std::size_t {
        return static_cast<std::size_t>(pe) + 24 + prefix + 8;
    };
    ImportLayout pe32plus{import_dir(kDataDirectoryOffset64), 8, 1ULL << 63};
    if (pe == 0 || pe + 4 + 20 + 2 > image.size() || read32(image, pe) != 0x00004550) {
        return pe32plus;
    }
    if (read16(image, pe + 4 + 20) == 0x010B) {
        return ImportLayout{import_dir(kDataDirectoryOffset32), 4, 1ULL << 31};
    }
    return pe32plus;
}

// NUL-terminated ASCII string at an RVA, bounded.
std::string read_c_string(std::span<const std::uint8_t> bytes, std::size_t offset)
{
    if (offset >= bytes.size()) {
        return {};
    }
    const auto end = std::min(bytes.size(), offset + kMaxExportName + 1);
    std::string out;
    for (auto i = offset; i < end; ++i) {
        if (bytes[i] == 0) {
            break;
        }
        out.push_back(static_cast<char>(bytes[i]));
    }
    return out;
}

std::string read_import_string(std::span<const std::uint8_t> bytes, const std::size_t offset)
{
    if (offset >= bytes.size()) {
        return {};
    }
    const auto end = std::min(bytes.size(), offset + kMaxExportName + 1);
    if (std::find(bytes.begin() + offset, bytes.begin() + end, 0) == bytes.begin() + end) {
        return {};
    }
    return read_c_string(bytes, offset);
}

std::string fold(std::string_view name)
{
    std::string out;
    for (const char c : name) {
        out.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c));
    }
    return out;
}

// The export directory's span: DataDirectory[0] {VA, Size}. The size MUST
// come from the directory entry - the struct's own +4 field is
// TimeDateStamp (zero in freshly generated synthetic modules, which would
// fail a size guard and empty the index).
std::pair<std::uint32_t, std::uint32_t> export_dir_bounds(std::span<const std::uint8_t> image)
{
    const auto pe = read32(image, 0x3C);
    if (pe == 0 || pe + 4 + 20 + 128 > image.size() || read32(image, pe) != 0x00004550) {
        return {};
    }
    // DataDirectory placement follows the optional header magic (the export
    // directory itself is identically laid out for both magics)
    const auto dirs =
        read16(image, pe + 4 + 20) == 0x010B ? kDataDirectoryOffset32 : kDataDirectoryOffset64;
    return {read32(image, pe + 4 + 20 + dirs), read32(image, pe + 4 + 20 + dirs + 4)};
}

} // namespace

std::string_view api_set_host(const std::string_view folded_name)
{
    if (folded_name.rfind("api-ms-win-crt-", 0) == 0) {
        return "ucrtbase.dll";
    }
    if (folded_name.rfind("api-ms-win-", 0) == 0) {
        return "kernelbase.dll";
    }
    return {};
}

std::expected<void, LoadError> index_exports(LoadedModule& module)
{
    module.exports.clear();
    const auto d = std::span<const std::uint8_t>(module.image);
    const auto [export_rva, export_size] = export_dir_bounds(d);
    if (export_rva == 0 || export_size == 0 || export_rva >= d.size()) {
        return {}; // no exports: legal (data-only image)
    }
    const auto number_of_names = read32(d, export_rva + 0x18); // NumberOfNames
    const auto names_va = read32(d, export_rva + 0x20);        // AddressOfNames
    const auto ordinals_va = read32(d, export_rva + 0x24);     // AddressOfNameOrdinals
    const auto functions_va = read32(d, export_rva + 0x1C);    // AddressOfFunctions
    const auto bounded = std::min<std::uint32_t>(number_of_names, 8192);
    module.exports.reserve(bounded);
    for (std::uint32_t i = 0; i < bounded; ++i) {
        const auto name_rva = read32(d, names_va + 4 * i);
        if (name_rva == 0 || name_rva >= d.size()) {
            continue;
        }
        const auto ordinal = read16(d, ordinals_va + 2 * i);
        const auto function_rva = read32(d, functions_va + 4ULL * ordinal);
        if (function_rva == 0) {
            continue;
        }
        auto name = read_c_string(d, name_rva);
        if (name.empty()) {
            continue;
        }
        // forwarder entries keep the forwarder string as their "function"
        // address: resolve_export walks them at lookup time
        module.exports.emplace_back(std::move(name), module.base + function_rva);
    }
    std::ranges::sort(module.exports, std::ranges::less{}, [](const auto& e) { return e.first; });
    return {};
}

ResolvedExport resolve_export(const std::vector<LoadedModule>& modules,
                              const std::string_view module_name,
                              const std::string_view function_name)
{
    return resolve_export(modules, module_name, function_name, ApiSetContext{});
}

ResolvedExport resolve_export(const std::vector<LoadedModule>& modules,
                              const std::string_view module_name,
                              const std::string_view function_name, const ApiSetContext& ctx)
{
    return resolve_export(modules, module_name, function_name, ctx, {});
}

namespace {

// The shared forwarder-chain walker. The lookup key rides as (function_name,
// ordinal) with exactly one side meaningful per hop: an import-by-ordinal
// enters with a typed ordinal, an import-by-name with the name string. The
// '#' spelling is meaningful ONLY inside a forwarder string, where the PE
// format itself defines "dll.#N" as ordinal N of the target - a requested
// name (or a forwarder target) that is literally "#5" resolves by that exact
// name, never as ordinal 5. missing_module names the actual missing endpoint
// after API Set reduction and every hop.
ResolvedExport resolve_chain(const std::vector<LoadedModule>& modules,
                             const std::string_view module_name,
                             const std::string_view function_name,
                             const std::optional<std::uint32_t> ordinal, const ApiSetContext& ctx,
                             const std::string_view importer_name)
{
    std::string missing_module;
    // locate: name -> (module, api-set query went unanswered). Both modes
    // reduce the name before any module lookup; in map mode an api-set name
    // the map does not cover is flagged, never silently reduced.
    const auto locate = [&](const std::string_view name) -> std::pair<const LoadedModule*, bool> {
        auto folded = fold(name);
        if (ctx.mode == ApiSetContext::Mode::kDirectoryMap) {
            if (folded.rfind("api-ms-", 0) == 0 || folded.rfind("ext-ms-", 0) == 0) {
                // contracts live in the map without the extension
                constexpr std::string_view kSuffix = ".dll";
                if (folded.size() > kSuffix.size() &&
                    folded.compare(folded.size() - kSuffix.size(), kSuffix.size(), kSuffix) == 0) {
                    folded.resize(folded.size() - kSuffix.size());
                }
                const auto host = ctx.directory_map != nullptr
                                      ? ctx.directory_map->host_for(folded, importer_name)
                                      : std::nullopt;
                if (!host.has_value()) {
                    missing_module = folded;
                    return {nullptr, true};
                }
                folded = fold(*host);
            }
        } else if (const auto host = api_set_host(folded); !host.empty()) {
            folded = std::string(host);
        }
        for (const auto& module : modules) {
            const auto module_folded = fold(std::string_view(module.name.data()));
            if (module_folded == folded || module_folded == folded + ".dll") {
                return {&module, false};
            }
        }
        missing_module = folded;
        if (!missing_module.ends_with(".dll")) {
            missing_module += ".dll";
        }
        return {nullptr, false};
    };
    const auto located = locate(module_name);
    const LoadedModule* current = located.first;
    if (current == nullptr) {
        return ResolvedExport{.unmapped_api_set = located.second, .missing_module = missing_module};
    }
    std::string function{function_name};
    std::optional<std::uint32_t> hop_ordinal{ordinal};
    for (std::size_t hop = 0; hop <= kMaxForwardHops; ++hop) {
        std::uint64_t function_va = 0;
        if (hop_ordinal.has_value()) {
            // EAT index arithmetic against the current image (a derived
            // boundary image preserves the source's Base and EAT positions,
            // so the consumer's ordinal lands on the derived slot directly)
            const auto d = std::span<const std::uint8_t>(current->image);
            const auto [rva, size] = export_dir_bounds(d);
            if (rva == 0 || static_cast<std::uint64_t>(rva) + 40 > d.size()) {
                return {};
            }
            const auto base = read32(d, rva + 0x10);
            const auto count = read32(d, rva + 0x14);
            if (*hop_ordinal < base || static_cast<std::uint64_t>(*hop_ordinal) - base >= count) {
                return {};
            }
            const auto slot =
                static_cast<std::uint64_t>(read32(d, rva + 0x1C)) + 4ULL * (*hop_ordinal - base);
            if (slot + 4 > d.size()) {
                return {};
            }
            const auto target = read32(d, static_cast<std::size_t>(slot));
            if (target == 0 || target >= d.size()) {
                return {};
            }
            function_va = current->base + target;
        } else {
            const auto it =
                std::ranges::lower_bound(current->exports, function, std::ranges::less{},
                                         [](const auto& e) { return e.first; });
            if (it == current->exports.end() || it->first != function) {
                return {};
            }
            function_va = it->second;
        }
        // forwarder detection: the function RVA points inside the export
        // directory, where the forwarder string ("dll.func") lives
        const auto d = std::span<const std::uint8_t>(current->image);
        const auto [export_rva, export_size] = export_dir_bounds(d);
        const auto function_rva = static_cast<std::uint32_t>(function_va - current->base);
        const bool forwarded = export_size != 0 && function_rva >= export_rva &&
                               function_rva < export_rva + export_size;
        if (!forwarded) {
            return ResolvedExport{.ok = true,
                                  .forwarded = hop != 0,
                                  .va = function_va,
                                  .module = current,
                                  .final_name = function};
        }
        const auto forwarder = read_c_string(d, export_rva + (function_rva - export_rva));
        const auto dot = forwarder.find('.');
        if (dot == std::string::npos) {
            return {};
        }
        const auto next_module = std::string_view(forwarder).substr(0, dot);
        const auto target_name = std::string_view(forwarder).substr(dot + 1);
        function.clear();
        hop_ordinal.reset();
        if (target_name.starts_with('#')) {
            std::uint32_t parsed_ordinal = 0;
            const auto parsed = std::from_chars(
                target_name.data() + 1, target_name.data() + target_name.size(), parsed_ordinal);
            if (parsed.ec != std::errc{} || parsed.ptr != target_name.data() + target_name.size()) {
                return {};
            }
            hop_ordinal = parsed_ordinal;
        } else {
            function = std::string(target_name);
        }
        const auto [next, next_unmapped] = locate(next_module);
        if (next == nullptr) {
            // host module not resident or unmapped: the import fails, exactly
            // like the real loader when a forwarder's DLL cannot be loaded
            return ResolvedExport{.unmapped_api_set = next_unmapped,
                                  .missing_module = missing_module};
        }
        current = next;
    }
    return {};
}

} // namespace

ResolvedExport resolve_ordinal_export(const std::vector<LoadedModule>& modules,
                                      const std::string_view module_name,
                                      const std::uint32_t ordinal)
{
    return resolve_ordinal_export(modules, module_name, ordinal, ApiSetContext{}, {});
}

ResolvedExport resolve_ordinal_export(const std::vector<LoadedModule>& modules,
                                      const std::string_view module_name,
                                      const std::uint32_t ordinal, const ApiSetContext& ctx,
                                      const std::string_view importer_name)
{
    return resolve_chain(modules, module_name, {}, ordinal, ctx, importer_name);
}

ResolvedExport resolve_export(const std::vector<LoadedModule>& modules,
                              const std::string_view module_name,
                              const std::string_view function_name, const ApiSetContext& ctx,
                              const std::string_view importer_name)
{
    return resolve_chain(modules, module_name, function_name, std::nullopt, ctx, importer_name);
}

std::expected<std::vector<ImportFixup>, LoadError>
resolve_imports(std::span<std::uint8_t> image, const std::vector<LoadedModule>& modules,
                std::vector<UnresolvedImport>* unresolved)
{
    return resolve_imports(image, modules, unresolved, ApiSetContext{}, {});
}

std::expected<std::vector<ImportFixup>, LoadError>
resolve_imports(std::span<std::uint8_t> image, const std::vector<LoadedModule>& modules,
                std::vector<UnresolvedImport>* unresolved, const ApiSetContext& ctx,
                const std::string_view importer_name, const bool write)
{
    std::vector<ImportFixup> fixups;
    const bool strict = ctx.mode == ApiSetContext::Mode::kDirectoryMap;
    const auto layout = detect_layout(image);
    const auto import_rva = read32(image, layout.import_dir_offset); // DataDirectory[1].VA
    if (import_rva == 0) {
        return fixups; // no imports: clean no-op
    }
    const auto import_size = read32(image, layout.import_dir_offset + 4);
    if (strict && (import_size < 20 || import_rva >= image.size() ||
                   import_size > image.size() - import_rva)) {
        return std::unexpected(LoadError::kBadImport);
    }
    const auto import_end =
        strict ? static_cast<std::size_t>(import_rva) + import_size : image.size();

    auto offset = static_cast<std::size_t>(import_rva);
    bool descriptors_terminated = false;
    for (std::size_t d = 0; d < kMaxDescriptors; ++d, offset += 20) {
        if (offset + 20 > import_end) {
            if (strict) {
                return std::unexpected(LoadError::kBadImport);
            }
            break;
        }
        const auto original_thunk = read32(image, offset);
        const auto name_rva = read32(image, offset + 12);
        const auto first_thunk = read32(image, offset + 16);
        if (original_thunk == 0 && name_rva == 0 && first_thunk == 0 &&
            (!strict || (read32(image, offset + 4) == 0 && read32(image, offset + 8) == 0))) {
            descriptors_terminated = true;
            break; // terminating descriptor
        }
        if (name_rva == 0 || first_thunk == 0 || name_rva >= image.size()) {
            if (strict) {
                return std::unexpected(LoadError::kBadImport);
            }
            continue;
        }
        const auto dll_name =
            strict ? read_import_string(image, name_rva) : read_c_string(image, name_rva);
        if (strict && dll_name.empty()) {
            return std::unexpected(LoadError::kBadImport);
        }
        const auto thunk_array = original_thunk != 0 ? original_thunk : first_thunk;
        bool thunks_terminated = false;
        for (std::size_t t = 0; t < kMaxThunksPerDll; ++t) {
            const auto thunk_rva = first_thunk + t * layout.thunk_size;
            const auto lookup_rva = thunk_array + t * layout.thunk_size;
            if (lookup_rva + layout.thunk_size > image.size() ||
                thunk_rva + layout.thunk_size > image.size()) {
                if (strict) {
                    return std::unexpected(LoadError::kBadImport);
                }
                break;
            }
            const auto thunk =
                layout.thunk_size == 8 ? read64(image, lookup_rva) : read32(image, lookup_rva);
            if (thunk == 0) {
                thunks_terminated = true;
                break; // terminator
            }
            // import-by-name: low dword = hint/name RVA; import-by-ordinal:
            // the flag bit set, low 16 bits the ordinal. Both resolve —
            // real corpora (kernelbase) import ntdll slots by ordinal.
            ResolvedExport resolved;
            if ((thunk & layout.ordinal_flag) != 0) {
                if (strict && (thunk & ~(layout.ordinal_flag | 0xFFFFULL)) != 0) {
                    return std::unexpected(LoadError::kBadImport);
                }
                const auto ordinal = static_cast<std::uint32_t>(thunk & 0xFFFF);
                resolved = resolve_ordinal_export(modules, dll_name, ordinal, ctx, importer_name);
                if (!resolved.ok) {
                    if (unresolved != nullptr) {
                        unresolved->push_back({fold(dll_name),
                                               "<ordinal " + std::to_string(ordinal) + ">",
                                               resolved.missing_module, resolved.unmapped_api_set});
                    }
                    continue;
                }
            } else {
                if (strict && (thunk > 0xFFFFFFFFULL || thunk + 3 > image.size())) {
                    return std::unexpected(LoadError::kBadImport);
                }
                const auto name_offset = static_cast<std::size_t>(thunk & 0xFFFFFFFF) + 2;
                const auto function_name = strict ? read_import_string(image, name_offset)
                                                  : read_c_string(image, name_offset);
                if (strict && function_name.empty()) {
                    return std::unexpected(LoadError::kBadImport);
                }
                resolved = resolve_export(modules, dll_name, function_name, ctx, importer_name);
                if (!resolved.ok) {
                    if (unresolved != nullptr) {
                        unresolved->push_back({fold(dll_name), std::string(function_name),
                                               resolved.missing_module, resolved.unmapped_api_set});
                    }
                    continue;
                }
            }
            if (write && layout.thunk_size == 8) {
                write64(image, thunk_rva, resolved.va);
            } else if (write) {
                write32(image, thunk_rva, static_cast<std::uint32_t>(resolved.va));
            }
            fixups.push_back({thunk_rva, resolved.va});
        }
        if (strict && !thunks_terminated) {
            return std::unexpected(LoadError::kBadImport);
        }
    }
    if (strict && !descriptors_terminated) {
        return std::unexpected(LoadError::kBadImport);
    }
    return fixups;
}

std::expected<std::vector<ImportFixup>, LoadError>
bind_delayed_imports(std::span<std::uint8_t> image, const std::vector<LoadedModule>& modules,
                     std::vector<UnresolvedImport>* unresolved, const ApiSetContext& ctx,
                     const std::string_view importer_name, const bool write)
{
    // the tolerance never fills `unresolved` - misses ride the file's own
    // static failure thunks; the parameter stays for caller symmetry
    static_cast<void>(unresolved);
    std::vector<ImportFixup> fixups;
    const auto layout = detect_layout(image);
    if (read32(image, layout.import_dir_offset - 12) <= 13) {
        return fixups; // NumberOfRvaAndSizes does not declare directory(13)
    }
    // DataDirectory[13]: IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT. The directory
    // slot sits one fixed prefix past the optional header, mirroring the
    // import directory's own placement.
    const std::size_t delay_dir_offset = layout.import_dir_offset + 12 * 8;
    if (delay_dir_offset + 8 > image.size()) {
        return fixups; // no room for the directory slot: no delay imports
    }
    const auto delay_rva = read32(image, delay_dir_offset);
    const auto delay_size = read32(image, delay_dir_offset + 4);
    if (delay_rva == 0) {
        return fixups; // no delay imports: clean no-op
    }
    // a directory that does not name in-image bytes is malformed, not absent
    if (static_cast<std::uint64_t>(delay_rva) + 32 > image.size() || delay_size < 32 ||
        delay_size > image.size() - delay_rva) {
        return std::unexpected(LoadError::kBadDelayImport);
    }

    // The descriptor walk is bounded like every other untrusted-table walk.
    // Write-value set (the capture corpus's .didat slot records): the IAT
    // slots take the final resolved VAs and nothing else is written - the
    // capture world's descriptor timestamp fields, module-handle slots,
    // bound-IAT copies and unload tables all read zero/untouched with the
    // IAT slots bound, so writing them would create diffs, not close them.
    //
    // Resolution misses are TOLERATED: the slot keeps its construction-input
    // bytes, because MSVC statically initializes the failed-delay IAT
    // entries to the module's own helper thunks and the real loader leaves
    // them there (the capture corpus's slots match the file bytes +
    // relocation delta slot-for-slot, 142/142 + 18/18 - an unresolved
    // delayed dependency, the map not covering the contract, and a host
    // missing the export all read as the file bytes in the captured world).
    // Writing anything else - and rejecting outright - would create diffs,
    // not close them. `unresolved` is therefore never filled here; only a
    // malformed descriptor (VA form, out of range) is the named rejection.
    auto offset = static_cast<std::size_t>(delay_rva);
    const auto dir_end = static_cast<std::size_t>(delay_rva) + delay_size;
    bool descriptors_terminated = false;
    for (std::size_t d = 0; d < kMaxDescriptors && offset + 32 <= dir_end; ++d, offset += 32) {
        if (offset + 32 > image.size()) {
            return std::unexpected(LoadError::kBadDelayImport);
        }
        const auto gr_attrs = read32(image, offset);
        const auto name_field = read32(image, offset + 4);
        const auto phmod_field = read32(image, offset + 8);
        const auto piat_field = read32(image, offset + 12);
        const auto pint_field = read32(image, offset + 16);
        if (gr_attrs == 0 && name_field == 0 && phmod_field == 0 && piat_field == 0 &&
            pint_field == 0 && read32(image, offset + 20) == 0 && read32(image, offset + 24) == 0 &&
            read32(image, offset + 28) == 0) {
            descriptors_terminated = true;
            break; // terminating descriptor
        }
        // RVA addressing only: a VA-form descriptor names absolute addresses
        // in the image's preferred base - the construction never guesses one.
        if (gr_attrs != 1) {
            return std::unexpected(LoadError::kBadDelayImport);
        }
        if (name_field == 0 || name_field >= image.size() || piat_field == 0 ||
            piat_field >= image.size()) {
            return std::unexpected(LoadError::kBadDelayImport);
        }
        const auto dll_name = read_import_string(image, name_field);
        if (dll_name.empty()) {
            return std::unexpected(LoadError::kBadDelayImport);
        }
        // INT (import names) drives the lookup; IAT takes the resolved VAs.
        // Either table missing is the malformed-descriptor rejection.
        if (pint_field == 0 || pint_field >= image.size()) {
            return std::unexpected(LoadError::kBadDelayImport);
        }
        if (phmod_field != 0 &&
            static_cast<std::uint64_t>(phmod_field) + layout.thunk_size > image.size()) {
            return std::unexpected(LoadError::kBadDelayImport);
        }
        bool thunks_terminated = false;
        for (std::size_t t = 0; t < kMaxThunksPerDll; ++t) {
            const auto iat_rva = piat_field + t * layout.thunk_size;
            const auto lookup_rva = pint_field + t * layout.thunk_size;
            if (lookup_rva + layout.thunk_size > image.size() ||
                iat_rva + layout.thunk_size > image.size()) {
                return std::unexpected(LoadError::kBadDelayImport);
            }
            for (const auto field : {read32(image, offset + 20), read32(image, offset + 24)}) {
                if (field != 0 && static_cast<std::uint64_t>(field) + (t + 1) * layout.thunk_size >
                                      image.size()) {
                    return std::unexpected(LoadError::kBadDelayImport);
                }
            }
            const auto thunk =
                layout.thunk_size == 8 ? read64(image, lookup_rva) : read32(image, lookup_rva);
            if (thunk == 0) {
                thunks_terminated = true;
                break; // terminator
            }
            ResolvedExport resolved;
            if ((thunk & layout.ordinal_flag) != 0) {
                if ((thunk & ~(layout.ordinal_flag | 0xFFFFULL)) != 0) {
                    return std::unexpected(LoadError::kBadDelayImport);
                }
                const auto ordinal = static_cast<std::uint32_t>(thunk & 0xFFFF);
                resolved = resolve_ordinal_export(modules, dll_name, ordinal, ctx, importer_name);
            } else {
                if (thunk > 0xFFFFFFFFULL) {
                    return std::unexpected(LoadError::kBadDelayImport);
                }
                const auto name_thunk = static_cast<std::size_t>(thunk & 0xFFFFFFFF);
                // the hint/name RVA must name in-image bytes: an out-of-range
                // thunk is a malformed descriptor, not a tolerated miss
                if (name_thunk + 3 > image.size()) {
                    return std::unexpected(LoadError::kBadDelayImport);
                }
                const auto function_name = read_import_string(image, name_thunk + 2);
                if (function_name.empty()) {
                    return std::unexpected(LoadError::kBadDelayImport);
                }
                resolved = resolve_export(modules, dll_name, function_name, ctx, importer_name);
            }
            if (!resolved.ok) {
                // tolerated miss: the slot keeps its construction-input bytes
                // (the static failure thunk the file itself synthesizes)
                continue;
            }
            if (write) {
                if (layout.thunk_size == 8) {
                    write64(image, iat_rva, resolved.va);
                } else {
                    write32(image, iat_rva, static_cast<std::uint32_t>(resolved.va));
                }
            }
            fixups.push_back({iat_rva, resolved.va});
        }
        if (!thunks_terminated) {
            return std::unexpected(LoadError::kBadDelayImport);
        }
    }
    if (!descriptors_terminated) {
        return std::unexpected(LoadError::kBadDelayImport);
    }
    return fixups;
}

} // namespace sheller::loader
