#include "loader_route.h"

#include "../loader/boundary_derive.h"
#include "../loader/env.h"
#include "../loader/imports.h"
#include "../loader/loader.h"
#include "boundary_manifest.h"
#include "boundary_metadata.h"
#include "intercept.h"

#include <algorithm>
#include <cstring>
#include <format>
#include <fstream>
#include <set>

#include <sheller/log.h>
#include <xxhash.h>

namespace sheller::engine {
namespace {

// The system-module set stage's product: the resident modules, their
// guest-side map bytes (fixed base -> image), the intercepted
// (VA, handler id) pairs the import resolution registered, and - directory
// mode only - the module source table, the manifested boundary rules and
// the loaded API Set map.
struct LoadedSystemModules {
    std::vector<loader::LoadedModule> modules;
    std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>> maps;
    std::vector<std::pair<std::uint64_t, std::uint32_t>> intercepts;
    // folded module name -> source class (the module source table)
    std::vector<std::pair<std::string, SystemModuleSource>> sources;
    // index-parallel to modules: the whole-file hash of the bytes each
    // module came from (0 where unbound: the synthetic/host routes)
    std::vector<std::uint64_t> image_hashes;
    // folded boundary module name -> applicability-checked manifest rules
    std::map<std::string, std::vector<loader::BoundaryRule>> boundary_rules;
    // folded boundary module name -> its derivation dispositions (the
    // metadata's boundary records)
    std::map<std::string, std::vector<loader::DerivedBoundaryExport>> boundary_dispositions;
    // the directory's API Set map, anchored to its raw ntdll
    loader::ApiSetMapView api_set_map;
    // the raw apiset-map.bin bytes + anchor (the metadata embeds them)
    std::vector<std::uint8_t> apiset_file_bytes;
    std::uint64_t apiset_anchor{};
};

// The resident core modules, in load order. The fixed bases come from
// kBases64/kBases86 by index.
struct SystemModuleSpec {
    const char* file_name;
    const char* folded_name;
};
inline constexpr SystemModuleSpec kSystemModules[] = {
    {"ntdll.dll", "ntdll.dll"},
    {"kernel32.dll", "kernel32.dll"},
    {"kernelbase.dll", "kernelbase.dll"},
    // Tier 2 behavior surface: advapi32 hosts the registry-family
    // interceptions. No frozen advapi32 manifest exists yet - a missing file
    // is skipped (fail-soft).
    {"advapi32.dll", "advapi32.dll"},
    // Tier 2: user32 hosts the packed-DLL corpus's
    // second import module. Manifest frozen (user32.x64.json); a missing
    // file is skipped (fail-soft) - the DLL construction path validates the
    // modules it needs explicitly.
    {"user32.dll", "user32.dll"},
};

std::string module_stem(std::string_view folded_name)
{
    constexpr std::string_view kDllSuffix = ".dll";
    std::string stem{folded_name};
    if (stem.size() > kDllSuffix.size() &&
        stem.compare(stem.size() - kDllSuffix.size(), kDllSuffix.size(), kDllSuffix) == 0) {
        stem.resize(stem.size() - kDllSuffix.size());
    }
    return stem;
}

std::filesystem::path synthetic_module_path(const std::filesystem::path& dir,
                                            std::string_view folded_name, GuestMode mode)
{
    return dir / (module_stem(folded_name) + (mode == GuestMode::kX86 ? ".x86.dll" : ".x64.dll"));
}

// Extras continue the core trio's series: x64 upward from the third base in
// 0x100000000 steps, x86 downward from it in 0x1000000 steps.
std::uint64_t extra_module_base(const GuestMode mode, const std::size_t index)
{
    return mode == GuestMode::kX86
               ? kBases86[2] - 0x1000000ULL * static_cast<std::uint64_t>(index + 1)
               : kBases64[2] + 0x100000000ULL * static_cast<std::uint64_t>(index + 1);
}

// The synthetic module files present in the directory, split into the core
// specs (in their fixed order) and the sorted extras. Mirrors the
// construction's discovery exactly.
struct SyntheticDirectoryPlan {
    std::vector<std::size_t> core_indices;
    std::vector<std::filesystem::path> extras;
};

SyntheticDirectoryPlan plan_synthetic_directory(const GuestMode mode,
                                                const std::filesystem::path& dir)
{
    SyntheticDirectoryPlan plan;
    std::error_code ec;
    for (std::size_t i = 0; i < std::size(kSystemModules); ++i) {
        const auto module_path = synthetic_module_path(dir, kSystemModules[i].folded_name, mode);
        if (std::filesystem::exists(module_path, ec) && !ec) {
            plan.core_indices.push_back(i);
        }
    }
    const std::string suffix = mode == GuestMode::kX86 ? ".x86.dll" : ".x64.dll";
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        auto name = entry.path().filename().string();
        if (name.size() <= suffix.size() ||
            name.compare(name.size() - suffix.size(), suffix.size(), suffix) != 0) {
            continue;
        }
        name.resize(name.size() - suffix.size());
        name += ".dll";
        const bool core =
            std::any_of(std::begin(kSystemModules), std::end(kSystemModules),
                        [&name](const SystemModuleSpec& spec) { return name == spec.folded_name; });
        if (!core) {
            plan.extras.push_back(entry.path());
        }
    }
    std::sort(plan.extras.begin(), plan.extras.end());
    return plan;
}

// Interception bookkeeping shared by both source routes: a resolved import
// whose final name is in the intercept set hooks that function entry
// (VA + stable handler id). One entry per VA: the sample's and the
// residents' fixups can name the same final function, and a duplicated
// address would double-scan and double-count on the dispatch path.
void register_import_intercepts(const std::vector<loader::ImportFixup>& fixups,
                                const std::vector<loader::LoadedModule>& modules,
                                std::vector<std::pair<std::uint64_t, std::uint32_t>>& intercepts)
{
    for (const auto& fixup : fixups) {
        const auto already =
            std::any_of(intercepts.begin(), intercepts.end(),
                        [&](const auto& entry) { return entry.first == fixup.resolved; });
        if (already) {
            continue;
        }
        for (const auto& system : modules) {
            for (const auto& [name, va] : system.exports) {
                if (va == fixup.resolved) {
                    if (const auto id = intercept_id_for(name)) {
                        intercepts.emplace_back(fixup.resolved, *id);
                    }
                }
            }
        }
    }
}

// Reads one file's bytes; a read failure is a named IO rejection carrying
// the path.
std::expected<std::vector<std::uint8_t>, RebuildFailure>
read_file_bytes(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::unexpected(
            failure(RebuildError::kIoFailure, std::format("cannot read '{}'", path.string())));
    }
    return std::vector<std::uint8_t>{std::istreambuf_iterator<char>(in),
                                     std::istreambuf_iterator<char>()};
}

// Loads one real-byte module: parse, build, relocate, index - every result
// checked, any failure a named construction rejection (no ignored-return or
// base-only comparison path). The module joins the set with its source mark.
std::expected<void, RebuildFailure>
load_real_module(const std::vector<std::uint8_t>& bytes, const std::string_view folded_name,
                 const std::uint64_t fixed_base, const SystemModuleSource source,
                 LoadedSystemModules& loaded, const bool pi_exempt = false)
{
    const auto reject = [&](const std::string& why) {
        return std::unexpected(
            failure(RebuildError::kBadSnapshot, std::format("{}: {}", folded_name, why)));
    };
    auto info = loader::parse_pe(bytes);
    if (!info.has_value()) {
        return reject(std::string(loader::load_error_message(info.error())));
    }
    // directory mode is an x64 world: an i386 module file names itself here
    if (info->bitness != loader::kBitness64) {
        return reject("i386 module in an x64 directory world");
    }
    auto module_image = loader::build_image(bytes, *info);
    if (!module_image.has_value()) {
        return reject(std::string(loader::load_error_message(module_image.error())));
    }
    const auto delta = fixed_base - info->image_base;
    if (delta != 0 && info->reloc_directory_rva != 0 && info->reloc_directory_size != 0) {
        // fixups exist and the base moved: the table must be fully
        // applicable (every fixup target inside the image - the
        // "needs relocation without effective info" shape rejects here) and
        // the application must succeed.
        if (const auto valid = loader::validate_relocations(*module_image, *info);
            !valid.has_value()) {
            return reject("relocation table names targets outside the image");
        }
        if (const auto relocated = loader::apply_relocations(*module_image, *info, delta);
            !relocated.has_value()) {
            return reject(std::string(loader::load_error_message(relocated.error())));
        }
    } else if (delta != 0 && !pi_exempt) {
        // a real directory input moved off its preferred base with no
        // relocation table: absolute fields cannot be fixed up, so this is a
        // named rejection - only images known position-independent by
        // construction (the generator's synthetic fallback modules) load
        // without a table
        return reject(
            std::format("mapped at 0x{:x} but carries no relocation directory", fixed_base));
    }
    if (folded_name.size() >= 64) {
        return reject(
            std::format("module name {} bytes exceeds the 63-byte name limit", folded_name.size()));
    }
    loader::LoadedModule module;
    module.base = fixed_base;
    module.image = std::move(*module_image);
    module.name.fill(0);
    std::memcpy(module.name.data(), folded_name.data(), folded_name.size());
    if (!loader::index_exports(module).has_value()) {
        return reject("export index failed");
    }
    loaded.sources.emplace_back(std::string(folded_name), source);
    loaded.image_hashes.push_back(XXH64(bytes.data(), bytes.size(), 0));
    loaded.modules.push_back(std::move(module));
    return {};
}

// Directory mode (change real-dll-module-dir): the strict source tiers. The
// boundary pair derives from the directory files under the committed
// manifest (ntdll required, win32u optional), every other directory DLL
// maps as real bytes, the API Set map is required and anchored to the raw
// ntdll, and the sample's module closure must resolve from the directory -
// a missing member is a named rejection, or an explicitly-marked synthetic
// fallback when the option is on. The host system directories are never
// read.
std::expected<LoadedSystemModules, RebuildFailure> load_directory_system_modules(
    const GuestMode mode, const std::filesystem::path& dir, const bool fallback_enabled,
    const std::filesystem::path& synthetic_module_dir, std::vector<std::uint8_t>& image)
{
    // Phase 1 derives the x64 boundary pair only (design Non-Goals).
    if (mode != GuestMode::kX64) {
        return std::unexpected(failure(RebuildError::kBadSnapshot,
                                       "system-modules directory mode is x64-only in this phase"));
    }
    std::error_code probe_ec;
    if (!std::filesystem::is_directory(dir, probe_ec) || probe_ec) {
        return std::unexpected(
            failure(RebuildError::kIoFailure,
                    std::format("system-modules directory '{}' is not readable", dir.string())));
    }
    LoadedSystemModules loaded;
    const auto dir_file = [&dir](const std::string_view name) {
        return dir / std::filesystem::path(std::string_view(name));
    };

    // The API Set map is required and anchored to the directory's own raw
    // ntdll (design D5) - the boundary derivation binds to the same hash.
    const auto map_bytes = read_file_bytes(dir_file("apiset-map.bin"));
    if (!map_bytes.has_value()) {
        return std::unexpected(
            failure(RebuildError::kIoFailure,
                    std::format("system-modules directory '{}' lacks apiset-map.bin (the API Set "
                                "map travels with the directory)",
                                dir.string())));
    }
    const auto ntdll_path = dir_file("ntdll.dll");
    auto ntdll_bytes = read_file_bytes(ntdll_path);
    if (!ntdll_bytes.has_value()) {
        return std::unexpected(
            failure(RebuildError::kIoFailure, std::format("system-modules directory mode requires "
                                                          "ntdll.dll: {}",
                                                          ntdll_bytes.error().detail)));
    }
    const auto ntdll_hash = XXH64(ntdll_bytes->data(), ntdll_bytes->size(), 0);
    auto map_view = loader::ApiSetMapView::load(*map_bytes, loader::kApiSetMapArchX64, ntdll_hash);
    if (!map_view.has_value()) {
        return std::unexpected(
            failure(RebuildError::kBadSnapshot,
                    std::format("apiset-map.bin rejected: {} ({})",
                                loader::apiset_map_error_message(map_view.error().code),
                                map_view.error().detail)));
    }
    loaded.apiset_file_bytes = *map_bytes;
    loaded.apiset_anchor = ntdll_hash;
    loaded.api_set_map = std::move(*map_view);

    // The boundary pair: ntdll derives at its reserved base, win32u derives
    // only when the directory carries it (a referenced-but-absent win32u is
    // the binding stage's named rejection, not a load failure).
    const auto& bases = kBases64;
    const auto derive_boundary = [&](const std::string_view module_name, const std::uint64_t base,
                                     const bool required) -> std::expected<void, RebuildFailure> {
        auto bytes = read_file_bytes(dir_file(module_name));
        if (!bytes.has_value()) {
            if (required) {
                return std::unexpected(
                    failure(RebuildError::kIoFailure,
                            std::format("system-modules directory mode requires {}: {}",
                                        module_name, bytes.error().detail)));
            }
            return {}; // optional boundary member: absent, not resident
        }
        const auto hash = XXH64(bytes->data(), bytes->size(), 0);
        auto rules = BoundaryManifest::committed().rules_for(module_name, "x64", hash);
        if (!rules.has_value()) {
            return std::unexpected(
                failure(RebuildError::kBadSnapshot,
                        std::format("{}: boundary manifest rejected: {}", module_name,
                                    boundary_manifest_error_message(rules.error()))));
        }
        auto derived = loader::derive_boundary_image(*bytes, module_name, *rules);
        if (!derived.has_value()) {
            return std::unexpected(failure(RebuildError::kBadSnapshot,
                                           std::format("{}: boundary derivation rejected: {}",
                                                       module_name, derived.error().detail)));
        }
        loader::LoadedModule module;
        module.base = base;
        // the derived bytes are a PE file; the guest map takes the folded
        // SizeOfImage image every other module path builds (page-aligned)
        auto derived_info = loader::parse_pe(derived->image);
        if (!derived_info.has_value()) {
            return std::unexpected(
                failure(RebuildError::kBadSnapshot,
                        std::format("{}: derived image does not parse: {}", module_name,
                                    loader::load_error_message(derived_info.error()))));
        }
        auto guest_image = loader::build_image(derived->image, *derived_info);
        if (!guest_image.has_value()) {
            return std::unexpected(
                failure(RebuildError::kBadSnapshot,
                        std::format("{}: derived image build failed: {}", module_name,
                                    loader::load_error_message(guest_image.error()))));
        }
        module.image = std::move(*guest_image);
        // the derived ntdll carries the independent mode marker in its
        // reserved DOS e_res2 slot (design D6) - part of the generated
        // image contract, written before any map bytes exist
        if (module_name == "ntdll.dll") {
            if (const auto marked =
                    boundary_metadata::write_marker(module.image, boundary_metadata::kMetadataBase);
                !marked.has_value()) {
                return std::unexpected(failure(
                    RebuildError::kBadSnapshot,
                    std::format("{}: mode marker rejected: {}", module_name,
                                boundary_metadata::metadata_error_message(marked.error().code))));
            }
        }
        if (module_name.size() >= sizeof(module.name)) {
            return std::unexpected(
                failure(RebuildError::kBadSnapshot,
                        std::format("{}: module name exceeds the {}-byte name limit", module_name,
                                    sizeof(module.name) - 1)));
        }
        module.name.fill(0);
        std::memcpy(module.name.data(), module_name.data(), module_name.size());
        if (!loader::index_exports(module).has_value()) {
            return std::unexpected(
                failure(RebuildError::kBadSnapshot,
                        std::format("{}: derived export index failed", module_name)));
        }
        loaded.sources.emplace_back(std::string(module_name),
                                    SystemModuleSource::kDirectoryDerived);
        loaded.image_hashes.push_back(hash);
        loaded.boundary_rules.emplace(std::string(module_name), std::move(*rules));
        loaded.boundary_dispositions.emplace(std::string(module_name), std::move(derived->exports));
        loaded.modules.push_back(std::move(module));
        return {};
    };
    if (const auto loaded_ntdll = derive_boundary("ntdll.dll", bases[0], true);
        !loaded_ntdll.has_value()) {
        return std::unexpected(loaded_ntdll.error());
    }

    // The other directory DLLs: the four core names map at their reserved
    // slots (real bytes), everything else takes the extras ladder in sorted
    // name order - win32u derives there, the rest map as real bytes.
    const constexpr auto is_core_name = [](const std::string_view folded) {
        return folded == "kernel32.dll" || folded == "kernelbase.dll" || folded == "advapi32.dll" ||
               folded == "user32.dll";
    };
    std::vector<std::filesystem::path> extras;
    for (const auto& entry : std::filesystem::directory_iterator(dir, probe_ec)) {
        auto name = entry.path().filename().string();
        if (name.size() <= 4 || name.compare(name.size() - 4, 4, ".dll") != 0) {
            continue;
        }
        for (auto& c : name) {
            if (c >= 'A' && c <= 'Z') {
                c = static_cast<char>(c - 'A' + 'a');
            }
        }
        if (name == "ntdll.dll" || name == "apiset-map.bin") {
            continue;
        }
        extras.push_back(entry.path());
    }
    std::sort(extras.begin(), extras.end());
    std::size_t extra_index = 0;
    for (const auto& path : extras) {
        std::string folded = path.filename().string();
        for (auto& c : folded) {
            if (c >= 'A' && c <= 'Z') {
                c = static_cast<char>(c - 'A' + 'a');
            }
        }
        if (is_core_name(folded)) {
            std::size_t slot = 1;
            for (std::size_t i = 1; i < std::size(kSystemModules); ++i) {
                if (folded == kSystemModules[i].folded_name) {
                    slot = i;
                    break;
                }
            }
            auto bytes = read_file_bytes(path);
            if (!bytes.has_value()) {
                return std::unexpected(bytes.error());
            }
            if (const auto ok = load_real_module(*bytes, folded, bases[slot],
                                                 SystemModuleSource::kDirectoryRealBytes, loaded);
                !ok.has_value()) {
                return std::unexpected(ok.error());
            }
            continue;
        }
        const auto base = extra_module_base(mode, extra_index++);
        if (folded == "win32u.dll") {
            if (const auto ok = derive_boundary(folded, base, true); !ok.has_value()) {
                return std::unexpected(ok.error());
            }
            continue;
        }
        auto bytes = read_file_bytes(path);
        if (!bytes.has_value()) {
            return std::unexpected(bytes.error());
        }
        if (const auto ok = load_real_module(*bytes, folded, base,
                                             SystemModuleSource::kDirectoryRealBytes, loaded);
            !ok.has_value()) {
            return std::unexpected(ok.error());
        }
    }

    // Strict closure over the FULL dependency graph: resolve the sample and
    // every resident real module; modules missing from the directory join
    // from the frozen synthetic fallback (when enabled) until the resident
    // set stops growing. An api-set name the map does not cover is the named
    // unmapped rejection; a missing member without fallback coverage is the
    // named rejection - never a silent partial world. Function-level misses
    // keep the existing recorded-tolerated semantics.
    loader::ApiSetContext api_set_ctx;
    api_set_ctx.mode = loader::ApiSetContext::Mode::kDirectoryMap;
    api_set_ctx.directory_map = &loaded.api_set_map;
    const auto resident = [&loaded](const std::string_view folded) {
        return std::any_of(loaded.modules.begin(), loaded.modules.end(),
                           [folded](const loader::LoadedModule& module) {
                               return std::string_view(module.name.data()) == folded;
                           });
    };
    std::set<std::string> missing;
    // missing module -> the resident module whose import pulled it in (for
    // the rejection wording); empty for sample-direct references
    std::map<std::string, std::string> missing_dependents;
    for (;;) {
        // resolve the sample and each resident real module against the
        // current set; collect the module-level names still missing
        std::vector<loader::UnresolvedImport> loop_unresolved;
        std::vector<std::string> loop_dependents;
        static_cast<void>(
            loader::resolve_imports(image, loaded.modules, &loop_unresolved, api_set_ctx, {}));
        loop_dependents.assign(loop_unresolved.size(),
                               std::string{}); // sample-direct: no depending module
        for (std::size_t i = 0; i < loaded.modules.size(); ++i) {
            if (loaded.sources[i].second != SystemModuleSource::kDirectoryRealBytes &&
                loaded.sources[i].second != SystemModuleSource::kFallbackSynthetic) {
                continue; // derived boundary images carry no import table
            }
            std::vector<loader::UnresolvedImport> module_unresolved;
            static_cast<void>(loader::resolve_imports(
                loaded.modules[i].image, loaded.modules, &module_unresolved, api_set_ctx,
                std::string_view(loaded.modules[i].name.data())));
            const std::string depending_module(std::string_view(loaded.modules[i].name.data()));
            for (const auto& miss : module_unresolved) {
                loop_unresolved.emplace_back(miss);
                loop_dependents.emplace_back(depending_module);
            }
        }
        missing.clear();
        std::size_t entry_index = 0;
        // the importer's report spelling: a resident module names itself; the
        // sample's own imports name the sample image (never an empty slot)
        const auto importer_spelled = [](const std::string& depending_module) {
            return depending_module.empty() ? std::string{"the sample image"} : depending_module;
        };
        for (const auto& entry : loop_unresolved) {
            const auto& depending_module = loop_dependents[entry_index++];
            if (entry.unmapped_api_set) {
                return std::unexpected(
                    failure(RebuildError::kBadSnapshot,
                            std::format("api set not mapped by apiset-map.bin: {} (imported by {})",
                                        entry.missing_module, importer_spelled(depending_module))));
            }
            // The resolver carries the actual missing endpoint after API Set
            // reduction and every forwarder hop, using the original importer.
            if (entry.missing_module.empty()) {
                continue;
            } // symbol, not module, missing
            const auto folded = fold_name(entry.missing_module);
            if (folded.size() >= 64 || folded.find_first_of("/\\:") != std::string::npos ||
                folded.find("..") != std::string::npos) {
                return std::unexpected(
                    failure(RebuildError::kBadSnapshot, "path-shaped dependency: " + folded));
            }
            if (!resident(folded)) {
                missing.insert(folded);
                // remember the depending module for the rejection's wording
                missing_dependents.emplace(folded, depending_module);
            }
        }
        if (missing.empty()) {
            break;
        }
        // the fallback residents join from the frozen synthetic directory;
        // without the option this is the named rejection
        for (const auto& name : missing) {
            std::error_code missing_ec;
            const auto synth_path = synthetic_module_dir.empty()
                                        ? std::filesystem::path{}
                                        : synthetic_module_path(synthetic_module_dir, name, mode);
            const bool fallback_available = fallback_enabled && !synth_path.empty() &&
                                            std::filesystem::exists(synth_path, missing_ec) &&
                                            !missing_ec;
            if (!fallback_available) {
                auto detail = std::format("system module missing from directory '{}': {}{}",
                                          dir.string(), name,
                                          fallback_enabled ? " and no synthetic fallback covers it"
                                                           : " (the fallback option is off)");
                const auto dependent = missing_dependents.find(name);
                if (dependent != missing_dependents.end()) {
                    detail += std::format(" (imported by {})", importer_spelled(dependent->second));
                }
                return std::unexpected(failure(RebuildError::kBadSnapshot, detail));
            }
            auto bytes = read_file_bytes(synth_path);
            if (!bytes.has_value()) {
                return std::unexpected(bytes.error());
            }
            if (const auto ok =
                    load_real_module(*bytes, name, extra_module_base(mode, extra_index++),
                                     SystemModuleSource::kFallbackSynthetic, loaded,
                                     /*pi_exempt=*/true);
                !ok.has_value()) {
                return std::unexpected(ok.error());
            }
        }
    }
    // Resident IAT binding: every real-byte module's own import table
    // resolves against the complete resident set (forwarder chains and the
    // API Set map included), writing the resolved VAs into its host image -
    // before any map bytes are generated, so the host image, the guest copy
    // and the container region all carry the same final IAT. A dependency
    // that fails to resolve is the named rejection: no half-bound world.
    // No resident module runs DllMain, TLS callbacks or any entry
    // initialization - binding is the only writeback.
    for (std::size_t i = 0; i < loaded.modules.size(); ++i) {
        const auto source = loaded.sources[i].second;
        if (source != SystemModuleSource::kDirectoryRealBytes &&
            source != SystemModuleSource::kFallbackSynthetic) {
            continue; // derived boundary images carry no import table
        }
        auto& module = loaded.modules[i];
        const std::string_view module_name(module.name.data());
        std::vector<loader::UnresolvedImport> resident_unresolved;
        const auto bound = loader::resolve_imports(module.image, loaded.modules,
                                                   &resident_unresolved, api_set_ctx, module_name);
        if (!bound.has_value()) {
            return std::unexpected(
                failure(RebuildError::kBadSnapshot,
                        std::format("{}: resident IAT binding failed", module_name)));
        }
        if (!resident_unresolved.empty()) {
            return std::unexpected(
                failure(RebuildError::kBadSnapshot,
                        std::format("{}: unresolved dependency '{}!{}'", module_name,
                                    resident_unresolved.front().dll_name,
                                    resident_unresolved.front().function_name)));
        }
        // Real bodies call each other's imports: a resident module's own
        // resolved imports join the interception set, so an intercepted
        // final name hooks wherever it is called from, not only from the
        // sample (the loop is idempotent - binding re-runs below re-bind to
        // the same VAs, and the registration deduplicates by VA).
        register_import_intercepts(*bound, loaded.modules, loaded.intercepts);
    }
    // the sample resolves once more over the complete set (idempotent -
    // already-bound slots re-bind to the same VAs)
    std::vector<loader::ImportFixup> fixups;
    {
        std::vector<loader::UnresolvedImport> sample_unresolved;
        auto resolved =
            loader::resolve_imports(image, loaded.modules, &sample_unresolved, api_set_ctx, {});
        if (resolved.has_value()) {
            fixups = std::move(*resolved);
        }
    }
    register_import_intercepts(fixups, loaded.modules, loaded.intercepts);
    // Bind-then-map: the map bytes are the bound final images, never a
    // pre-binding copy.
    for (const auto& module : loaded.modules) {
        loaded.maps.emplace_back(module.base, module.image);
    }
    return loaded;
}

// The world-building stage's product: the export index, the attribution
// records, and the TEB/PEB/Ldr environment the finish section assembles the
// PreparedGuest from.
struct LoaderWorld {
    std::vector<LoaderExportEntry> exports;
    std::vector<mem_region::ModuleImage> images;
    std::vector<mem_region::RegionRecord> regions;
    std::uint64_t teb_va;
    std::uint64_t peb_va;
    std::vector<std::uint64_t> module_entry_vas;
};

std::expected<LoadedSnapshot, RebuildFailure> load_snapshot_stream(std::istream& in)
{
    snapshot::Reader reader{in};
    LoadedSnapshot loaded;
    auto header = reader.read_header();
    if (!header) {
        return std::unexpected(
            header.error() == snapshot::Error::kBitnessMismatch
                ? failure(RebuildError::kBitnessUnsupported)
                : failure(RebuildError::kBadSnapshot,
                          std::string{"header: "} +
                              std::string{snapshot::error_message(header.error())}));
    }
    loaded.header = *header;
    auto registers = reader.read_registers();
    if (!registers) {
        return std::unexpected(failure(
            RebuildError::kBadSnapshot,
            std::string{"registers: "} + std::string{snapshot::error_message(registers.error())}));
    }
    loaded.registers = *registers;
    auto metadata = reader.read_metadata();
    if (!metadata) {
        return std::unexpected(failure(RebuildError::kBadSnapshot,
                                       std::string{"metadata: "} +
                                           std::string{snapshot::error_message(metadata.error())}));
    }
    loaded.metadata = *metadata;
    for (std::uint32_t i = 0; i < loaded.header.region_count; ++i) {
        auto region = reader.read_region();
        if (!region) {
            return std::unexpected(
                failure(RebuildError::kBadSnapshot,
                        std::format("region {}: {}", i, snapshot::error_message(region.error()))));
        }
        loaded.regions.push_back(std::move(*region));
    }
    // the bilateral directory-mode check runs before anything maps: a
    // damaged or one-sided container is the named rejection, a legacy
    // container keeps its route
    auto replay_metadata = inspect_replay_metadata(loaded.regions);
    if (!replay_metadata.has_value()) {
        return std::unexpected(replay_metadata.error());
    }
    loaded.replay_metadata = std::move(*replay_metadata);
    // v2 carries exactly one pending-module block (the DLL-input route's
    // sample bytes); a v2 file that ends before it, or a malformed block, is
    // not a loadable container. A second physical block (or any trailing
    // byte) after the first is likewise rejected - the format defines one
    // block per container, and a silent tail would let hand-built doubles
    // through. v1 files stop at the region table - unchanged behavior.
    if (loaded.header.version == snapshot::kVersionV2) {
        auto pending = reader.read_pending();
        if (!pending) {
            return std::unexpected(failure(RebuildError::kBadSnapshot));
        }
        loaded.pending = std::move(*pending);
        char trailing = 0;
        in.read(&trailing, 1);
        if (in.gcount() != 0) {
            return std::unexpected(failure(RebuildError::kBadSnapshot));
        }
    }
    if (loaded.registers.rip != loaded.metadata.entry_address) {
        return std::unexpected(failure(RebuildError::kInconsistent));
    }
    return loaded;
}

// Per-region rebuild order: validate alignment, map with the interpreted
// permissions, then write the content bytes the capture actually read.
std::expected<void, RebuildFailure> map_regions(UnicornEngine& unicorn,
                                                const std::vector<snapshot::Region>& regions)
{
    for (const auto& region : regions) {
        if (region.header.size == 0) {
            continue; // degenerate entry, nothing to rebuild
        }
        if (region.header.base_address % kMapAlignment != 0 ||
            region.header.size % kMapAlignment != 0) {
            return std::unexpected(failure(RebuildError::kUnalignedRegion));
        }
        auto perms = protection_to_perms(region.header.protection);
        // Fault-based dirty tracking: writable regions lose
        // their write permission at map time; the write-prot hook re-grants
        // it page by page on the guest's first write.
        if (snapshot_protection_writable(region.header.protection)) {
            perms &= ~static_cast<std::uint32_t>(UC_PROT_WRITE);
        }
        if (uc_mem_map(unicorn.get(), region.header.base_address,
                       static_cast<std::size_t>(region.header.size),
                       static_cast<std::uint32_t>(perms)) != UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
        if (region.header.content == snapshot::kContentPresent && !region.content.empty() &&
            uc_mem_write(unicorn.get(), region.header.base_address, region.content.data(),
                         region.content.size()) != UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
    }
    return {};
}

std::expected<void, RebuildFailure> write_registers_gdt(UnicornEngine& unicorn,
                                                        const snapshot::Registers& registers,
                                                        const snapshot::Metadata& metadata,
                                                        std::uint64_t gdt_base);

std::expected<void, RebuildFailure> write_registers(UnicornEngine& unicorn,
                                                    const snapshot::Registers& registers,
                                                    const snapshot::Metadata& metadata,
                                                    const GuestMode mode,
                                                    const std::uint64_t gdt_base = kX86GdtBase)
{
    for (std::size_t i = 0; i < gpr_count_for(mode); ++i) {
        if (uc_reg_write(unicorn.get(), gpr_register_for(mode, i), &registers.gpr[i]) !=
            UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
    }
    if (uc_reg_write(unicorn.get(), UC_X86_REG_EFLAGS, &registers.rflags) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    if (mode == GuestMode::kX86) {
        return write_registers_gdt(unicorn, registers, metadata, gdt_base);
    }
    if (uc_reg_write(unicorn.get(), UC_X86_REG_RIP, &registers.rip) != UC_ERR_OK ||
        uc_reg_write(unicorn.get(), UC_X86_REG_GS_BASE, &metadata.teb_address) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    return {};
}

// x86 segment setup for a snapshot-route rebuild: same contract as
// write_registers but the GDT page sits at a caller-chosen free slot of
// the captured address space.
std::expected<void, RebuildFailure> write_registers_gdt(UnicornEngine& unicorn,
                                                        const snapshot::Registers& registers,
                                                        const snapshot::Metadata& metadata,
                                                        const std::uint64_t gdt_base)
{
    {
        // unicorn2 UC_MODE_32 no-ops FS_BASE, and the default SS/DS
        // descriptors are 16-bit (a push truncates ESP to SP): the segment
        // bases must come from a GDT over the pinned GDT page - entry 1
        // = TEB for FS, entry 2 = flat 4GB data for SS/DS.
        std::array<std::uint8_t, 24> gdt{};
        const auto teb = metadata.teb_address;
        auto write_data_desc = [&](const std::size_t at, const std::uint64_t base) {
            gdt[at + 0] = 0xFF; // limit low word 0xFFFF
            gdt[at + 1] = 0xFF;
            gdt[at + 2] = static_cast<std::uint8_t>(base & 0xFF);
            gdt[at + 3] = static_cast<std::uint8_t>((base >> 8) & 0xFF);
            gdt[at + 4] = static_cast<std::uint8_t>((base >> 16) & 0xFF);
            gdt[at + 5] = 0x92; // data segment, writable, present
            gdt[at + 6] = 0xCF; // 4K granularity, 32-bit (B), limit high 0xF
            gdt[at + 7] = static_cast<std::uint8_t>((base >> 24) & 0xFF);
        };
        write_data_desc(8, teb); // selector 0x08: FS -> TEB
        write_data_desc(16, 0);  // selector 0x10: SS/DS -> flat 4GB
        if (uc_mem_write(unicorn.get(), gdt_base, gdt.data(), gdt.size()) != UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
        uc_x86_mmr gdtr{};
        gdtr.base = gdt_base;
        gdtr.limit = 0xFFF;
        uc_reg_write(unicorn.get(), UC_X86_REG_GDTR, &gdtr);
        const std::uint16_t fs_selector = 0x08;
        uc_reg_write(unicorn.get(), UC_X86_REG_FS, &fs_selector);
        const std::uint16_t data_selector = 0x10;
        uc_reg_write(unicorn.get(), UC_X86_REG_SS, &data_selector);
        uc_reg_write(unicorn.get(), UC_X86_REG_DS, &data_selector);
        uc_reg_write(unicorn.get(), UC_X86_REG_ES, &data_selector);
        const auto eip = static_cast<std::uint32_t>(registers.rip);
        uc_reg_write(unicorn.get(), UC_X86_REG_EIP, &eip);
        return {};
    }
}

} // namespace

std::expected<PreparedGuest, RebuildFailure> prepare_guest_stream(std::istream& in)
{
    const auto loaded = load_snapshot_stream(in);
    if (!loaded) {
        return std::unexpected(loaded.error());
    }

    const auto mode =
        loaded->metadata.bitness == snapshot::kBitness32 ? GuestMode::kX86 : GuestMode::kX64;
    uc_engine* handle = nullptr;
    if (uc_open(UC_ARCH_X86, mode == GuestMode::kX86 ? UC_MODE_32 : UC_MODE_64, &handle) !=
        UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    UnicornEngine unicorn{handle};

    if (const auto mapped = map_regions(unicorn, loaded->regions); !mapped) {
        return std::unexpected(mapped.error());
    }
    if (mode == GuestMode::kX86) {
        // the 32-bit segment contract needs a GDT page; park it high in
        // the captured space at the first free 4KB page below 0xFFFE0000
        // (deterministic scan, skipping captured regions)
        std::uint64_t gdt_page = 0xFFFE0000ULL;
        while (gdt_page > 0x1000) {
            std::uint8_t probe = 0;
            if (uc_mem_read(handle, gdt_page, &probe, sizeof probe) != UC_ERR_OK) {
                break; // unmapped: free
            }
            gdt_page -= 0x100000;
        }
        const auto gdt_map_err = uc_mem_map(handle, gdt_page, 0x1000, UC_PROT_ALL);
        if (gdt_map_err != UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
        if (const auto written =
                write_registers(unicorn, loaded->registers, loaded->metadata, mode, gdt_page);
            !written) {
            return std::unexpected(written.error());
        }
    } else if (const auto written =
                   write_registers(unicorn, loaded->registers, loaded->metadata, mode);
               !written) {
        return std::unexpected(written.error());
    }
    // Attribute the whole address space once, at rebuild time: module
    // images from the Ldr walk, region records from the snapshot. Regions
    // double as synthesis candidates: contiguous MEM_IMAGE chains that no
    // Ldr module spans become unknown-image module records, appended after
    // the Ldr set (the sample-ordinal / arming alignment depends on that
    // order) so hand-mapped payloads get section-level attribution.
    auto images = mem_region::enumerate_guest_images(handle, mode == GuestMode::kX86,
                                                     loaded->metadata.teb_address);
    std::vector<mem_region::RegionRecord> region_records;
    region_records.reserve(loaded->regions.size());
    std::vector<mem_region::UnknownImageCandidate> candidates;
    candidates.reserve(loaded->regions.size());
    for (const auto& region : loaded->regions) {
        region_records.push_back(
            mem_region::RegionRecord{region.header.base_address, region.header.size,
                                     region.header.protection, region.header.type});
        candidates.push_back({region.header.base_address, region.header.size, region.header.type,
                              std::span<const std::uint8_t>{region.content}});
    }
    const auto unknown_images =
        mem_region::synthesize_unknown_images(images, {candidates.data(), candidates.size()});
    images.insert(images.end(), unknown_images.begin(), unknown_images.end());
    mem_region::MemRegionMap map(images, region_records);
    PreparedGuest guest{std::move(unicorn),          mode,
                        std::move(loaded->metadata), std::move(map),
                        std::move(images),           std::move(region_records)};
    if (loaded->replay_metadata.has_value()) {
        guest.directory_metadata = std::move(*loaded->replay_metadata);
    }
    // v2 containers carry the DLL-input route's pending module: hand it to
    // the guest and rebuild the loader tables from the photographed world
    // - the synthetic load consumes both at run time.
    // the directory-mode attach runs first and needs no pending block: the
    // EXE/shellcode/DLL container types all restore their full run tables
    // before execution; a pending block on top composes (the resident-world
    // attach passes through when the tables already exist)
    if (guest.directory_metadata.has_value()) {
        if (const auto restored = attach_directory_world(guest); !restored.has_value()) {
            return std::unexpected(
                failure(RebuildError::kBadSnapshot,
                        std::string{"directory-world attach rejected: "} +
                            std::string{syscall_run_error_message(restored.error())}));
        }
    }
    if (loaded->pending.has_value()) {
        guest.pending = std::move(loaded->pending);
        if (const auto attached = attach_resident_world(guest); !attached.has_value()) {
            return std::unexpected(
                failure(RebuildError::kBadSnapshot,
                        std::string{"resident-world attach rejected: "} +
                            std::string{syscall_run_error_message(attached.error())}));
        }
    }
    return guest;
}

// Loader-route API interception:
// intercepted kernel32/Rtl entries are replaced wholesale by these built-in
// implementations - args from the x64 call registers, result in rax, return
// address popped off the stack. The uc_emu_stop + api_resume hands the leg
// back to the run loop, which re-enters at the return address.

// Loader route: build the address space
// from a PE file instead of a snapshot. Layout: bottom 64KB reserved with
// NULL-page semantics, the image at its declared base (fully RWX - section
// protections ride the metadata, never page permissions, or a shell's
// self-modification trips over them), KUSER at the fixed page, and a
// deterministic stack. The loader module does the byte work; this function
// maps it and produces the same PreparedGuest the snapshot path runs.
// Loads the resident system modules for the loader route: the core
// ntdll/kernel32/kernelbase/advapi32 set (synthetic dir first, host
// System32/SysWOW64 fallback) plus the synthetic extras, then resolves
// the sample's imports against them and registers the intercepted
// entries. Returns the module set with its guest-side map bytes and
// the intercepted (VA, handler id) pairs.
std::expected<LoadedSystemModules, RebuildFailure>
load_system_modules(const GuestMode mode, const std::filesystem::path& synthetic_module_dir,
                    std::vector<std::uint8_t>& image,
                    const std::filesystem::path& system_modules_dir,
                    const bool system_modules_fallback)
{
    // Directory mode: the strict source tiers, no host system directories,
    // no silent synthetic mixing.
    if (!system_modules_dir.empty()) {
        return load_directory_system_modules(mode, system_modules_dir, system_modules_fallback,
                                             synthetic_module_dir, image);
    }
    LoadedSystemModules loaded;
    // one resident module: map its bytes at the fixed base, relocate by the
    // base delta, and index the exports (resolve_imports below and the
    // interception layer's GetProcAddress/LoadLibrary both read module.exports)
    auto& system_modules = loaded.modules;
    auto& system_maps = loaded.maps;
    auto& intercepts = loaded.intercepts;
    auto& system_sources = loaded.sources;
    // system modules: real host system images
    // at fixed high addresses, RWX, relocated by their own delta. Their
    // bytes are retained host-side for import resolution and the
    // GetProcAddress index. Absent files fail the run loudly.
    // Windows-host-only: reads System32 (x64) or SysWOW64 (x86); on other
    // hosts the loader route runs import-free samples only (imports stay
    // unresolved by design).
    // system modules come from either the synthetic module dir (
    // portable - deterministic stub bodies + frozen export tables) or, on
    // Windows hosts, the real host DLLs. Without either, imports resolve to
    // nothing by design.
    const auto& bases = mode == GuestMode::kX64 ? kBases64 : kBases86;
    // one resident module: map its bytes at the fixed base, relocate by the
    // base delta, and index the exports (resolve_imports below and the
    // interception layer's GetProcAddress/LoadLibrary both read module.exports)
    const auto load_system_module =
        [&](const std::filesystem::path& dll_path, std::string_view folded_name,
            std::uint64_t fixed_base) -> std::expected<void, RebuildFailure> {
        std::ifstream dll_in(dll_path, std::ios::binary);
        if (!dll_in) {
            return std::unexpected(failure(RebuildError::kIoFailure));
        }
        std::vector<std::uint8_t> dll_bytes{std::istreambuf_iterator<char>(dll_in),
                                            std::istreambuf_iterator<char>()};
        auto module_info = loader::parse_pe(dll_bytes);
        if (!module_info) {
            return std::unexpected(failure(RebuildError::kBadSnapshot));
        }
        auto module_image = loader::build_image(dll_bytes, *module_info);
        if (!module_image) {
            return std::unexpected(failure(RebuildError::kBadSnapshot));
        }
        const auto delta = fixed_base - module_info->image_base;
        if (delta != 0) {
            static_cast<void>(loader::apply_relocations(*module_image, *module_info, delta));
        }
        loader::LoadedModule loaded;
        loaded.base = fixed_base;
        loaded.image = std::move(*module_image);
        std::memcpy(loaded.name.data(), folded_name.data(), folded_name.size());
        static_cast<void>(loader::index_exports(loaded));
        system_sources.emplace_back(std::string(folded_name), synthetic_module_dir.empty()
                                                                  ? SystemModuleSource::kHostSystem
                                                                  : SystemModuleSource::kSynthetic);
        system_modules.push_back(std::move(loaded));
        system_maps.emplace_back(fixed_base, system_modules.back().image);
        return {};
    };
    for (std::size_t i = 0; i < std::size(kSystemModules); ++i) {
        const auto& spec = kSystemModules[i];
        // synthetic system modules take precedence: deterministic
        // stub bodies + frozen export tables replace the host's real DLLs
        std::filesystem::path dll_path;
        if (!synthetic_module_dir.empty()) {
            dll_path = synthetic_module_path(synthetic_module_dir, spec.folded_name, mode);
        } else {
#ifdef _WIN32
            char system_root[MAX_PATH] = {};
            const auto len = mode == GuestMode::kX86
                                 ? GetSystemWow64DirectoryA(system_root, sizeof system_root)
                                 : GetSystemDirectoryA(system_root, sizeof system_root);
            if (len == 0) {
                return std::unexpected(failure(RebuildError::kIoFailure));
            }
            dll_path = std::filesystem::path(system_root) / spec.file_name;
#else
            continue; // non-Windows host without synth dir: no system modules
#endif
        }
        // Tier 2 fail-soft: the synthetic route has no frozen advapi32
        // manifest yet - a missing module file there is a skip, not a run
        // failure (the route simply runs without that module and its
        // interception surface). The real-DLL route keeps its loud failure.
        // The error_code overload, not the throwing one: an engine frame
        // reports a probe failure through this same skip channel instead of
        // letting a filesystem error escape as an exception (see the no-throw
        // discipline in the root CMakeLists). A probe that fails for a reason
        // other than "absent" is indistinguishable here and takes the same
        // branch - the module stays unloaded either way.
        std::error_code probe_ec;
        const bool present = std::filesystem::exists(dll_path, probe_ec);
        if (!synthetic_module_dir.empty() && (!present || probe_ec)) {
            continue;
        }
        auto loaded_module = load_system_module(dll_path, spec.folded_name, bases[i]);
        if (!loaded_module) {
            return std::unexpected(loaded_module.error());
        }
    }

    // additional synthetic modules (the CRT / vcruntime sets): the packed
    // corpus's unpack stubs LoadLibraryA them at runtime, and their exports
    // answer both import resolution and the interception layer. Resident
    // beside the core trio at extended fixed bases, sorted-name order for
    // determinism.
    if (!synthetic_module_dir.empty()) {
        std::error_code dir_ec;
        if (!std::filesystem::is_directory(synthetic_module_dir, dir_ec) || dir_ec) {
            return std::unexpected(failure(RebuildError::kIoFailure));
        }
        const std::string suffix = mode == GuestMode::kX86 ? ".x86.dll" : ".x64.dll";
        auto plan = plan_synthetic_directory(mode, synthetic_module_dir);
        for (std::size_t i = 0; i < plan.extras.size(); ++i) {
            auto stem = plan.extras[i].filename().string();
            stem.resize(stem.size() - suffix.size());
            const auto folded = stem + ".dll";
            auto loaded_module =
                load_system_module(plan.extras[i], folded, extra_module_base(mode, i));
            if (!loaded_module) {
                return std::unexpected(loaded_module.error());
            }
        }
    }

    // Base distinctness gate: a duplicated base would double-map in
    // unicorn and die as a setup failure far from the cause. The fixed-slot
    // planner makes collisions structurally impossible (the reserved pair
    // sits off the ladder); this guard turns a future planner regression
    // into a named construction failure at the source.
    for (std::size_t i = 0; i < system_modules.size(); ++i) {
        for (std::size_t j = i + 1; j < system_modules.size(); ++j) {
            if (system_modules[i].base == system_modules[j].base) {
                return std::unexpected(failure(
                    RebuildError::kBadSnapshot,
                    std::format("synthetic module base collision: {} and {} both plan at 0x{:x}",
                                std::string_view(system_modules[i].name.data()),
                                std::string_view(system_modules[j].name.data()),
                                system_modules[i].base)));
            }
        }
    }

    // resolve the sample's imports against the system modules (sample bytes
    // are host-side here, so IAT fixups land before the mapping)
    std::vector<loader::UnresolvedImport> unresolved_imports;
    const auto fixups = loader::resolve_imports(image, system_modules, &unresolved_imports);
    // intercepted-API bookkeeping: a resolved import whose final name is in
    // the intercept set hooks that function entry (VA + stable handler id)
    if (fixups.has_value()) {
        register_import_intercepts(*fixups, system_modules, intercepts);
    }
    return loaded;
}

// Opens the unicorn instance and builds the loader route's address space:
// the NULL guard, the sample image (write-protected for the fault-based
// dirty tracking), KUSER, the deterministic stack/heap/env regions, the
// x86 GDT page, then the resident module bytes and the sample itself,
// and the KUSER semantic fields.
std::expected<UnicornEngine, RebuildFailure>
map_loader_address_space(const GuestMode mode, const std::uint64_t base,
                         const std::uint64_t image_size, const std::vector<std::uint8_t>& image,
                         const LoadedSystemModules& loaded)
{
    const auto& layout = layout_for(mode);
    const auto& system_maps = loaded.maps;

    uc_engine* handle = nullptr;
    const auto uc_mode_selected = mode == GuestMode::kX86 ? UC_MODE_32 : UC_MODE_64;
    if (uc_open(UC_ARCH_X86, uc_mode_selected, &handle) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    UnicornEngine unicorn{handle};

    const auto image_span = static_cast<std::size_t>(image_size);
    // Fault-based dirty tracking: the
    // guest-writable loader regions map without write permission - the
    // write-prot hook re-grants it page by page on the guest's first write,
    // so the dump ledger sees exactly the pages the sample touched.
    constexpr auto kNoWrite = static_cast<std::uint32_t>(UC_PROT_READ | UC_PROT_EXEC);
    if (uc_mem_map(unicorn.get(), 0, kLoaderNullBytes, UC_PROT_NONE) != UC_ERR_OK ||
        uc_mem_map(unicorn.get(), base, image_span, kNoWrite) != UC_ERR_OK ||
        uc_mem_map(unicorn.get(), kLoaderKUser, 0x1000, UC_PROT_READ) != UC_ERR_OK ||
        uc_mem_map(unicorn.get(), layout.stack_base, layout.stack_size, kNoWrite) != UC_ERR_OK ||
        uc_mem_map(unicorn.get(), layout.heap_base, layout.heap_size, kNoWrite) != UC_ERR_OK ||
        uc_mem_map(unicorn.get(), layout.env_base, layout.env_block_size, kNoWrite) != UC_ERR_OK ||
        (mode == GuestMode::kX86 &&
         uc_mem_map(unicorn.get(), kX86GdtBase, kX86GdtSize, UC_PROT_ALL) != UC_ERR_OK)) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    // system module images land at their fixed bases:
    // relocated host-side above, written guest-side RWX
    for (const auto& [map_base, map_bytes] : system_maps) {
        if (uc_mem_map(unicorn.get(), map_base, map_bytes.size(), UC_PROT_ALL) != UC_ERR_OK ||
            uc_mem_write(unicorn.get(), map_base, map_bytes.data(), map_bytes.size()) !=
                UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
    }
    if (uc_mem_write(unicorn.get(), base, image.data(), image.size()) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    return unicorn;
}

// Seeds the fidelity-mode ntdll runtime globals: the process-init gate
// and the inverted function table over the resident module set plus the
// sample, version-pinned to the Windows 11 ntdll. Engine dispatch never
// consumes these - the seeding only wires up in fidelity mode.
std::expected<void, RebuildFailure>
seed_ntdll_ifnt(UnicornEngine& unicorn, const GuestMode mode, const bool fidelity_seams,
                const LoadedSystemModules& loaded, const std::vector<std::uint8_t>& image,
                const std::uint64_t base, const std::uint64_t image_size)
{
    const auto& system_modules = loaded.modules;

    // ntdll runtime globals: the disk image carries
    // pre-init process state that LdrpInitialize would fill. x64 SEH
    // dispatch needs two of those globals. The process-init gate at
    // +0x1d23c8: RtlLookupFunctionEntry only consults the inverted
    // function table when it reads 3 there, and its fallback otherwise
    // (NtQueryVirtualMemory probing) cannot produce a working unwind. The
    // inverted function table itself: DWORD count at +0x1e7430, DWORD
    // max-count at +0x1e7438, then 24-byte entries at +0x1e7440
    // ({exception directory, image base, size of image, directory size}).
    // Entry 0 is ntdll's own descriptor (excluded from the reader's binary
    // search, which instead matches it against the dedicated descriptor
    // globals); entries 1.. are searched by image base and must be sorted.
    // RVAs verified against the Windows 11 ntdll this host ships; a much
    // smaller ntdll skips the seeding and stays on the fallback path.
    // The seeding is a Windows-fidelity seam (exception dispatch via
    // real ntdll); the engine-side dispatcher never consumes it, so it only
    // wires up in fidelity mode.
    if (fidelity_seams && mode == GuestMode::kX64 && image.size() > 0x1000) {
        constexpr std::uint64_t kInitGateRva = 0x1d23c8;
        constexpr std::uint64_t kIfntCountRva = 0x1e7430;
        constexpr std::uint64_t kIfntEntriesRva = 0x1e7440;
        const auto exception_directory =
            [](const std::vector<std::uint8_t>& img) -> std::pair<std::uint32_t, std::uint32_t> {
            if (img.size() < 0x200) {
                return {};
            }
            std::uint32_t e_lfanew = 0;
            std::memcpy(&e_lfanew, img.data() + 0x3c, sizeof e_lfanew);
            if (e_lfanew + 0xa8 > img.size() ||
                std::memcmp(img.data() + e_lfanew, "PE\0\0", 4) != 0) {
                return {};
            }
            std::uint16_t magic = 0;
            std::memcpy(&magic, img.data() + e_lfanew + 0x18, sizeof magic);
            const auto dir_rva =
                magic == 0x20b ? e_lfanew + 0x18 + 0x70 + 0x18 : e_lfanew + 0x18 + 0x60 + 0x18;
            std::pair<std::uint32_t, std::uint32_t> out{};
            std::memcpy(&out.first, img.data() + dir_rva, sizeof out.first);
            std::memcpy(&out.second, img.data() + dir_rva + 4, sizeof out.second);
            return out;
        };
        const auto ntdll = std::find_if(system_modules.begin(), system_modules.end(),
                                        [](const loader::LoadedModule& m) {
                                            return std::string_view(m.name.data()) == "ntdll.dll";
                                        });
        if (ntdll != system_modules.end() && ntdll->image.size() > kIfntEntriesRva + 0x100) {
            struct IfntEntry {
                std::uint64_t directory;
                std::uint64_t image_base;
                std::uint32_t size_of_image;
                std::uint32_t directory_size;
            };
            std::vector<IfntEntry> entries;
            for (const auto& system : system_modules) {
                const auto dir = exception_directory(system.image);
                entries.push_back({system.base + dir.first, system.base,
                                   static_cast<std::uint32_t>(system.image.size()), dir.second});
            }
            const auto sample_dir = exception_directory(image);
            entries.push_back({base + sample_dir.first, base,
                               static_cast<std::uint32_t>(image_size), sample_dir.second});
            // entry 0 must be ntdll's own descriptor: the reader excludes it
            // from the search and matches ControlPc against it via the
            // descriptor globals; the rest are binary-searched by image base
            const auto ntdll_idx = std::find_if(entries.begin(), entries.end(),
                                                [ntdll_base = ntdll->base](const IfntEntry& e) {
                                                    return e.image_base == ntdll_base;
                                                }) -
                                   entries.begin();
            std::swap(entries[0], entries[ntdll_idx]);
            std::sort(
                entries.begin() + 1, entries.end(),
                [](const IfntEntry& a, const IfntEntry& b) { return a.image_base < b.image_base; });
            const std::uint32_t gate = 3;
            const std::uint32_t count = static_cast<std::uint32_t>(entries.size());
            const std::uint32_t max_count = 0xa;
            std::vector<std::uint8_t> table(0x10 + entries.size() * sizeof(IfntEntry), 0);
            std::memcpy(table.data(), &count, sizeof count);
            std::memcpy(table.data() + 8, &max_count, sizeof max_count);
            std::memcpy(table.data() + 0x10, entries.data(), entries.size() * sizeof(IfntEntry));
            if (uc_mem_write(unicorn.get(), ntdll->base + kInitGateRva, &gate, sizeof gate) !=
                    UC_ERR_OK ||
                uc_mem_write(unicorn.get(), ntdll->base + kIfntCountRva, table.data(),
                             table.size()) != UC_ERR_OK) {
                return std::unexpected(failure(RebuildError::kUnicornFailure));
            }
        }
    }
    return {};
}

// Builds the loader route's world bookkeeping: the export index feeding
// GetProcAddress/LoadLibrary, the module images and region records for
// behavior attribution (ascending-base order for the binary-searching
// readers), and the deterministic TEB/PEB/Ldr environment block.
std::expected<LoaderWorld, RebuildFailure>
build_loader_world(UnicornEngine& unicorn, const GuestMode mode, const LoadedSystemModules& loaded,
                   const std::vector<std::uint8_t>& image, const std::uint64_t base,
                   const std::uint64_t image_size)
{
    LoaderWorld world;
    auto& loader_exports = world.exports;
    auto& images = world.images;
    auto& regions = world.regions;
    const auto& layout = layout_for(mode);
    const auto& system_modules = loaded.modules;

    // KUSER_SHARED_DATA semantic fields: fixed deterministic values
    {
        std::vector<std::uint8_t> kuser(0x1000, 0);
        loader::fill_kuser_shared_data(kuser);
        uc_mem_write(unicorn.get(), kLoaderKUser, kuser.data(), kuser.size());
    }

    // loader tables: the exports indexed at load time feed the
    // interception layer's GetProcAddress/LoadLibrary lookups. Forwarder
    // entries resolve through the resident set to their final callable VA —
    // a host calling GetProcAddress must never receive a string RVA as
    // code. Synthetic modules carry no forwarders; real directory modules
    // (real export tables) do.
    loader::ApiSetContext export_ctx;
    if (!loaded.apiset_file_bytes.empty()) {
        export_ctx.mode = loader::ApiSetContext::Mode::kDirectoryMap;
        export_ctx.directory_map = &loaded.api_set_map;
    }
    for (const auto& system : system_modules) {
        for (const auto& [name, va] : system.exports) {
            static_cast<void>(va);
            const auto resolved =
                loader::resolve_export(system_modules, std::string_view(system.name.data()), name,
                                       export_ctx, std::string_view(system.name.data()));
            if (resolved.ok) {
                loader_exports.push_back({system.base, resolved.va, name});
            }
        }
    }

    // regions + attribution: the image, system modules, KUSER, stack, heap
    // and the environment block; the loader sample joins as its own module so
    // behavior attribution and monitored windows work unchanged

    for (const auto& system : system_modules) {
        mem_region::ModuleImage system_image;
        system_image.module.base = system.base;
        system_image.module.size = system.image.size();
        std::memcpy(system_image.module.name.data(), system.name.data(), system.name.size());
        system_image.header_bytes.assign(system.image.begin(), system.image.begin() + 0x1000);
        images.push_back(std::move(system_image));
    }
    mem_region::ModuleImage loader_image;
    loader_image.module.base = base;
    loader_image.module.size = image_size;
    const std::string module_name = "loader_image";
    std::copy(module_name.begin(), module_name.end(), loader_image.module.name.begin());
    loader_image.header_bytes.assign(image.begin(), image.begin() + 0x1000);
    images.push_back(loader_image);

    regions.push_back(mem_region::RegionRecord{base, image_size, 0x40, kMemImage});
    for (const auto& system : system_modules) {
        regions.push_back(
            mem_region::RegionRecord{system.base, system.image.size(), 0x40, kMemImage});
    }
    regions.push_back(mem_region::RegionRecord{kLoaderKUser, 0x1000, 0x02, kMemPrivate});
    regions.push_back(
        mem_region::RegionRecord{layout.stack_base, layout.stack_size, 0x04, kMemPrivate});
    regions.push_back(
        mem_region::RegionRecord{layout.heap_base, layout.heap_size, 0x04, kMemPrivate});
    regions.push_back(
        mem_region::RegionRecord{layout.env_base, layout.env_block_size, 0x04, kMemPrivate});
    // Region records are consumed by binary-searching readers (the write
    // ledger's find_region): canonical order is ascending by base. The
    // capture path produces sorted records; the loader build does not.
    std::sort(regions.begin(), regions.end(),
              [](const mem_region::RegionRecord& a, const mem_region::RegionRecord& b) {
                  return a.base < b.base;
              });

    // environment block: TEB/PEB/Ldr constructed from the module set;
    // x86 mode gets the 32-bit layout twin (wires build_environment_x86;
    // for now both modes use the x64 shape, which only x64 samples consume)
    std::vector<loader::EnvModule> env_modules;
    for (const auto& image_rec : images) {
        env_modules.push_back({image_rec.module.base,
                               static_cast<std::uint32_t>(image_rec.module.size),
                               std::string(image_rec.module.name.data())});
    }
    // the TEB stack pair must describe the mapped stack exactly: the entry
    // rsp sits kLoaderStackTop-0x1000, and RtlDispatchException validates
    // the dispatch Rsp against [TEB.StackLimit, TEB.StackBase) - a declared
    // top below the real top makes every early fault look like a bad stack
    const auto stack_top = layout.stack_base + layout.stack_size;
    const auto env =
        mode == GuestMode::kX86
            ? loader::build_environment_x86(layout.env_base, base, stack_top, layout.stack_base,
                                            layout.heap_base, env_modules)
            : loader::build_environment(layout.env_base, base, stack_top, layout.stack_base,
                                        layout.heap_base, env_modules);
    if (uc_mem_write(unicorn.get(), layout.env_base, env.env.data(), env.env.size()) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    world.teb_va = env.teb_va;
    world.peb_va = env.peb_va;
    world.module_entry_vas = std::move(env.module_entry_vas);
    return world;
}

// x86 only: welds the three-byte int-2E transition stub over the
// Wow64Transition slot (real ntdll32 RVA, or the synthetic ntdll's own
// slot) and the TEB's fs:[0xC0] pointer, so every SysWOW64 service call
// lands in the engine's native int-2E answer.
std::expected<void, RebuildFailure>
seed_wow64_transition(UnicornEngine& unicorn, const GuestMode mode,
                      const LoadedSystemModules& loaded,
                      const std::filesystem::path& synthetic_module_dir, const std::uint64_t teb_va)
{
    const auto& system_modules = loaded.modules;

    // x86 wow64 transition: every SysWOW64 ntdll service stub
    // reaches the kernel through `call *fs:[0xC0]` / `jmp [Wow64Transition]`,
    // and ntdll's own dispatcher wraps its information queries in the same
    // shape. The real transition target is the wow64cpu layer, but its ABI - eax = number, edx =
    // argument block, call
    // - is exactly the int 0x2E convention the engine answers natively. A
    // three-byte stub turns every transition into an emulated service call;
    // both dispatch identifiers point at it. The Wow64Transition RVA matches
    // the Windows 11 ntdll this host ships (guarded like the x64 seeding).
    if (mode == GuestMode::kX86) {
        constexpr std::uint64_t kWow64StubBase = kLoaderWow64StubBase;
        // The Wow64Transition slot serves syscall transitions (not exception
        // dispatch): the real ntdll32's slot RVA is version-pinned, while the
        // synthetic ntdll welds its own slot at a known RVA.
        constexpr std::uint64_t kRealWow64TransitionRva = 0x13B014;
        constexpr std::uint64_t kSynthWow64TransitionRva = 0x41000;
        const std::uint64_t kWow64TransitionRva =
            synthetic_module_dir.empty() ? kRealWow64TransitionRva : kSynthWow64TransitionRva;
        constexpr std::uint64_t kWow64TransitionTeb = 0xC0;
        static const std::array<std::uint8_t, 3> kWow64Stub{0xCD, 0x2E, 0xC3}; // int 2Eh; ret
        if (uc_mem_map(unicorn.get(), kWow64StubBase, 0x1000, UC_PROT_ALL) != UC_ERR_OK ||
            uc_mem_write(unicorn.get(), kWow64StubBase, kWow64Stub.data(), kWow64Stub.size()) !=
                UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
        const auto ntdll = std::find_if(system_modules.begin(), system_modules.end(),
                                        [](const loader::LoadedModule& m) {
                                            return std::string_view(m.name.data()) == "ntdll.dll";
                                        });
        if (ntdll != system_modules.end() && ntdll->image.size() > kWow64TransitionRva + 4) {
            const auto stub = static_cast<std::uint32_t>(kWow64StubBase);
            if (uc_mem_write(unicorn.get(), ntdll->base + kWow64TransitionRva, &stub,
                             sizeof stub) != UC_ERR_OK ||
                uc_mem_write(unicorn.get(), teb_va + kWow64TransitionTeb, &stub, sizeof stub) !=
                    UC_ERR_OK) {
                return std::unexpected(failure(RebuildError::kUnicornFailure));
            }
        }
    }
    return {};
}

std::expected<PreparedGuest, RebuildFailure>
prepare_pe_file(const std::filesystem::path& path, bool fidelity_seams,
                const std::filesystem::path& synthetic_module_dir,
                const std::filesystem::path& system_modules_dir, const bool system_modules_fallback)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::unexpected(failure(RebuildError::kIoFailure));
    }
    std::vector<std::uint8_t> file{std::istreambuf_iterator<char>(in),
                                   std::istreambuf_iterator<char>()};
    const auto info = loader::parse_pe(file);
    if (!info) {
        return std::unexpected(failure(RebuildError::kBadSnapshot));
    }
    const auto mode = info->bitness == loader::kBitness32 ? GuestMode::kX86 : GuestMode::kX64;
    const auto& layout = layout_for(mode);
    auto image = loader::build_image(file, *info);
    if (!image) {
        return std::unexpected(failure(RebuildError::kBadSnapshot));
    }
    // The image is remapped when its declared base cannot survive a 32-bit
    // slot (see kLoaderSampleBase); the delta repairs every relocated pointer
    // and PEB.ImageBase / metadata follow the mapped base below.
    const auto mapped_base = ((!synthetic_module_dir.empty() || !system_modules_dir.empty()) &&
                              info->image_base > 0xFFFFFFFFULL)
                                 ? kLoaderSampleBase
                                 : info->image_base;
    const auto base_delta = mapped_base - info->image_base;
    static_cast<void>(loader::apply_relocations(*image, *info, base_delta));
    auto callbacks = loader::tls_callbacks(*image, *info, base_delta);
    if (!callbacks.has_value()) {
        callbacks = std::vector<std::uint64_t>{};
    }

    auto system_loaded = load_system_modules(mode, synthetic_module_dir, *image, system_modules_dir,
                                             system_modules_fallback);
    if (!system_loaded.has_value()) {
        return std::unexpected(system_loaded.error());
    }
    // the directory mode's whole-interval overlap gate: modules, sample and
    // fixed regions must be pairwise disjoint, not merely distinct-based
    if (!system_modules_dir.empty()) {
        if (const auto overlap = find_directory_range_overlap(system_loaded->modules, mode,
                                                              mapped_base, info->image_size);
            overlap.has_value()) {
            return std::unexpected(
                failure(RebuildError::kBadSnapshot,
                        std::format("directory-mode mapping ranges overlap: {} and {}",
                                    overlap->first, overlap->second)));
        }
    }
    auto& intercepts = system_loaded->intercepts;
    // directory-mode whitelist/trap locals: the metadata block fills them,
    // the guest handoff below consumes them
    std::vector<LoaderExportEntry> guest_stub_whitelist;
    std::vector<std::uint64_t> guest_boundary_trap_vas;
    std::map<std::uint64_t, std::tuple<std::string, std::string, std::uint32_t>>
        guest_boundary_trap_names;
    auto unicorn_result =
        map_loader_address_space(mode, mapped_base, info->image_size, *image, *system_loaded);
    if (!unicorn_result.has_value()) {
        return std::unexpected(unicorn_result.error());
    }
    UnicornEngine& unicorn = *unicorn_result;
    const auto base = mapped_base;
    if (const auto seeded = seed_ntdll_ifnt(unicorn, mode, fidelity_seams, *system_loaded, *image,
                                            mapped_base, info->image_size);
        !seeded.has_value()) {
        return std::unexpected(seeded.error());
    }
    auto world =
        build_loader_world(unicorn, mode, *system_loaded, *image, mapped_base, info->image_size);
    if (!world.has_value()) {
        return std::unexpected(world.error());
    }
    const auto teb_va = world->teb_va;
    const auto peb_va = world->peb_va;
    if (const auto wow64 =
            seed_wow64_transition(unicorn, mode, *system_loaded, synthetic_module_dir, teb_va);
        !wow64.has_value()) {
        return std::unexpected(wow64.error());
    }
    // Directory mode: the versioned metadata region at its fixed base - the
    // module source table, the actual boundary dispositions, the intercept
    // registrations, the counting whitelist and the complete embedded API
    // Set map. Read-only MEM_PRIVATE region, no host paths, capacity-capped
    // at encode time. The e_res2 marker the derived ntdll carries points
    // here; the replay-side bilateral check reads both (design D6).
    if (!system_modules_dir.empty()) {
        namespace bm = boundary_metadata;
        bm::MetadataInput meta;
        // the counting whitelist (event-ledger source rules): derived compat
        // entries plus every fallback synthetic module's exports; trap
        // dispositions join the named stop points (klass 255 rows keep the
        // trap names in the record without joining the count set)
        for (const auto& [name, dispositions] : system_loaded->boundary_dispositions) {
            const auto module =
                std::find_if(system_loaded->modules.begin(), system_loaded->modules.end(),
                             [&name](const loader::LoadedModule& m) {
                                 return std::string_view(m.name.data()) == name;
                             });
            if (module == system_loaded->modules.end()) {
                continue;
            }
            for (const auto& disposition : dispositions) {
                if (disposition.name.empty()) {
                    // unnamed EAT slots carry no name-keyed row: the record's
                    // counters restore by (module, name), which an empty name
                    // can never match on replay - the body's disposition
                    // still rides the image (ud2 for a trap), only the named
                    // stop-point row is absent
                    continue;
                }
                if (disposition.kind == loader::BoundaryKind::kTrap) {
                    guest_boundary_trap_vas.push_back(module->base + disposition.body_rva);
                    guest_boundary_trap_names.emplace(
                        module->base + disposition.body_rva,
                        std::make_tuple(name, disposition.name, disposition.ordinal));
                    meta.counters.push_back({name, disposition.name, 255});
                } else if (disposition.kind == loader::BoundaryKind::kCompat) {
                    guest_stub_whitelist.push_back(
                        {module->base, module->base + disposition.body_rva, disposition.name});
                    meta.counters.push_back({name, disposition.name, 0});
                }
            }
        }
        // fallback synthetic modules count under the existing synthetic rule
        // (every export); their rows re-derive at replay from the source
        // table's kFallbackSynthetic marks, so the payload stays bounded
        for (std::size_t i = 0; i < system_loaded->modules.size(); ++i) {
            if (system_loaded->sources[i].second != SystemModuleSource::kFallbackSynthetic) {
                continue;
            }
            const auto& module = system_loaded->modules[i];
            for (const auto& [export_name, va] : module.exports) {
                guest_stub_whitelist.push_back({module.base, va, export_name});
            }
        }
        meta.modules.resize(system_loaded->modules.size());
        for (std::size_t i = 0; i < system_loaded->modules.size(); ++i) {
            const auto& module = system_loaded->modules[i];
            auto& record = meta.modules[i];
            record.name = std::string(std::string_view(module.name.data()));
            record.base = module.base;
            record.size = static_cast<std::uint32_t>(module.image.size());
            record.source = static_cast<std::uint8_t>(system_loaded->sources[i].second);
            record.image_xxhash64 = system_loaded->image_hashes[i];
        }
        for (const auto& [name, dispositions] : system_loaded->boundary_dispositions) {
            const auto module =
                std::find_if(system_loaded->modules.begin(), system_loaded->modules.end(),
                             [&name](const loader::LoadedModule& m) {
                                 return std::string_view(m.name.data()) == name;
                             });
            if (module == system_loaded->modules.end()) {
                return std::unexpected(
                    failure(RebuildError::kBadSnapshot,
                            std::format("{}: boundary record lost its module", name)));
            }
            bm::BoundaryRecord record;
            record.name = name;
            record.exports.reserve(dispositions.size());
            for (const auto& disposition : dispositions) {
                record.exports.push_back({disposition.name, disposition.ordinal,
                                          static_cast<std::uint8_t>(disposition.kind),
                                          module->base + disposition.body_rva,
                                          disposition.syscall_number});
            }
            meta.boundaries.push_back(std::move(record));
        }
        meta.intercepts.reserve(system_loaded->intercepts.size());
        for (const auto& [va, id] : system_loaded->intercepts) {
            meta.intercepts.push_back({va, id});
        }
        std::sort(meta.intercepts.begin(), meta.intercepts.end(),
                  [](const bm::InterceptRecord& a, const bm::InterceptRecord& b) {
                      return a.va != b.va ? a.va < b.va : a.id < b.id;
                  });
        meta.apiset_bytes = system_loaded->apiset_file_bytes;
        meta.apiset_anchor = system_loaded->apiset_anchor;
        const auto payload = bm::encode(meta);
        if (!payload.has_value()) {
            return std::unexpected(
                failure(RebuildError::kBadSnapshot,
                        std::format("boundary metadata rejected: {} ({})",
                                    boundary_metadata::metadata_error_message(payload.error().code),
                                    payload.error().detail)));
        }
        if (uc_mem_map(unicorn.get(), bm::kMetadataBase,
                       static_cast<std::size_t>(bm::kMetadataMaxBytes),
                       UC_PROT_READ) != UC_ERR_OK ||
            uc_mem_write(unicorn.get(), bm::kMetadataBase, payload->data(), payload->size()) !=
                UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
        world->regions.push_back(mem_region::RegionRecord{
            bm::kMetadataBase, static_cast<std::uint32_t>(bm::kMetadataMaxBytes), 0x02,
            kMemPrivate});
        // the region readers binary-search; the metadata record joins sorted
        std::sort(world->regions.begin(), world->regions.end(),
                  [](const mem_region::RegionRecord& a, const mem_region::RegionRecord& b) {
                      return a.base < b.base;
                  });
    }
    snapshot::Metadata metadata;
    metadata.entry_address = base + info->entry_rva;
    metadata.image_base = base;
    metadata.teb_address = teb_va;
    metadata.peb_address = peb_va;
    const auto entry_offset = static_cast<std::size_t>(info->entry_rva);
    std::memcpy(metadata.original_entry_bytes.data(), image->data() + entry_offset,
                metadata.original_entry_bytes.size());

    // registers: natural entry state - zeroed GPRs, stack from the reserved
    // region, RIP written by the run start; GS_BASE points at the TEB
    const snapshot::Registers registers{}; // natural entry state: zeroed GPRs
    if (const auto written = write_registers(unicorn, registers, metadata, mode); !written) {
        return std::unexpected(written.error());
    }
    const std::uint64_t rsp = layout.stack_base + layout.stack_size - 0x1000;
    uc_reg_write(unicorn.get(), gpr_register_for(mode, 4), &rsp);

    std::vector<mem_region::ModuleRecord> loader_modules;
    for (const auto& image_rec : world->images) {
        loader_modules.push_back(image_rec.module);
    }

    PreparedGuest guest{std::move(unicorn),
                        mode,
                        std::move(metadata),
                        mem_region::MemRegionMap{world->images, world->regions},
                        std::move(world->images),
                        std::move(world->regions),
                        std::move(*callbacks),
                        std::move(loader_modules),
                        std::move(world->exports),
                        std::move(intercepts),
                        std::move(world->module_entry_vas)};
    guest.loader_route = true; // synthetic Ldr: LdrLoadDll misses stay answered
    // directory-mode world facts: empty in the synthetic/host routes
    guest.directory_mode = !system_modules_dir.empty();
    guest.module_sources = std::move(system_loaded->sources);
    guest.boundary_rules = std::move(system_loaded->boundary_rules);
    guest.api_set_map = std::move(system_loaded->api_set_map);
    guest.stub_whitelist = std::move(guest_stub_whitelist);
    guest.boundary_trap_vas = std::move(guest_boundary_trap_vas);
    guest.boundary_trap_names = std::move(guest_boundary_trap_names);
    return guest;
}

std::expected<PreparedGuest, RebuildFailure> prepare_guest(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::unexpected(failure(RebuildError::kIoFailure));
    }
    return prepare_guest_stream(in);
}

namespace {

std::uint64_t read_u64(uc_engine* const uc, const std::uint64_t address)
{
    std::uint64_t value = 0;
    static_cast<void>(uc_mem_read(uc, address, &value, sizeof value));
    return value;
}

std::uint32_t read_u32(uc_engine* const uc, const std::uint64_t address)
{
    std::uint32_t value = 0;
    static_cast<void>(uc_mem_read(uc, address, &value, sizeof value));
    return value;
}

// Walks PEB->Ldr.InLoadOrderModuleList and records (DllBase, entry VA) in
// chain order. The environment layout puts the entry base on the
// InLoadOrderLinks node itself (env.cpp), so the node address is the handle
// LdrLoadDll hands out.
std::vector<std::pair<std::uint64_t, std::uint64_t>>
read_ldr_entries(uc_engine* const uc, const snapshot::Metadata& metadata, const GuestMode mode)
{
    std::vector<std::pair<std::uint64_t, std::uint64_t>> entries;
    const auto peb = metadata.peb_address;
    if (peb == 0) {
        return entries;
    }
    constexpr std::size_t kMaxWalk = mem_region::kMaxModuleImages;
    if (mode == GuestMode::kX86) {
        const auto ldr = static_cast<std::uint64_t>(read_u32(uc, peb + 0x0C));
        if (ldr == 0) {
            return entries;
        }
        const auto head = ldr + 0x0C;
        auto node = static_cast<std::uint64_t>(read_u32(uc, head));
        for (std::size_t i = 0; i < kMaxWalk && node != 0 && node != head; ++i) {
            const auto base = static_cast<std::uint64_t>(read_u32(uc, node + 0x18));
            entries.emplace_back(base, node);
            node = static_cast<std::uint64_t>(read_u32(uc, node));
        }
        return entries;
    }
    const auto ldr = read_u64(uc, peb + 0x18);
    if (ldr == 0) {
        return entries;
    }
    const auto head = ldr + 0x10;
    auto node = read_u64(uc, head);
    for (std::size_t i = 0; i < kMaxWalk && node != 0 && node != head; ++i) {
        const auto base = read_u64(uc, node + 0x30);
        entries.emplace_back(base, node);
        node = read_u64(uc, node);
    }
    return entries;
}

// Reads the sample image's TLS callback array from guest memory: PE data
// directory 9 -> IMAGE_TLS_DIRECTORY64.AddressOfCallBacks -> NUL-terminated
// array of absolute VAs (the loader applied relocations before mapping).
std::vector<std::uint64_t> read_tls_callbacks(uc_engine* const uc, const std::uint64_t image_base)
{
    std::vector<std::uint64_t> callbacks;
    std::array<std::uint8_t, 0x1000> headers{};
    if (uc_mem_read(uc, image_base, headers.data(), headers.size()) != UC_ERR_OK) {
        return callbacks;
    }
    const auto read16 = [&](const std::size_t at) {
        return static_cast<std::uint16_t>(headers[at] | (headers[at + 1] << 8));
    };
    const auto read32 = [&](const std::size_t at) {
        return static_cast<std::uint32_t>(headers[at]) |
               (static_cast<std::uint32_t>(headers[at + 1]) << 8) |
               (static_cast<std::uint32_t>(headers[at + 2]) << 16) |
               (static_cast<std::uint32_t>(headers[at + 3]) << 24);
    };
    if (read16(0) != 0x5A4D) {
        return callbacks;
    }
    const auto pe = read32(0x3C);
    if (pe + 24 > headers.size() || read32(pe) != 0x00004550 || read16(pe + 24) != 0x20B) {
        return callbacks;
    }
    const auto optional = static_cast<std::size_t>(pe) + 24;
    const auto tls_rva = read32(optional + 0x70 + 9 * 8);
    if (tls_rva == 0) {
        return callbacks;
    }
    const auto directory = image_base + tls_rva;
    const auto callbacks_va = read_u64(uc, directory + 0x18);
    if (callbacks_va == 0) {
        return callbacks;
    }
    constexpr std::size_t kMaxCallbacks = 64;
    for (std::size_t i = 0; i < kMaxCallbacks; ++i) {
        const auto callback = read_u64(uc, callbacks_va + i * sizeof(std::uint64_t));
        if (callback == 0) {
            break;
        }
        callbacks.push_back(callback);
    }
    return callbacks;
}

} // namespace

std::optional<std::pair<std::string, std::string>>
find_directory_range_overlap(const std::span<const loader::LoadedModule> modules,
                             const GuestMode mode, const std::uint64_t sample_base,
                             const std::uint64_t sample_size)
{
    // every interval the constructed world maps, whole-range: the resident
    // modules, the sample image, and the fixed environment regions (the
    // allocator bump range covers the run-time trampoline/allocations)
    struct Interval {
        std::uint64_t lo;
        std::uint64_t hi; // exclusive
        std::string name;
    };
    std::vector<Interval> intervals;
    intervals.reserve(modules.size() + 8);
    for (const auto& module : modules) {
        intervals.push_back({module.base, module.base + module.image.size(),
                             std::string(std::string_view(module.name.data()))});
    }
    intervals.push_back({sample_base, sample_base + sample_size, "<sample image>"});
    intervals.push_back({boundary_metadata::kMetadataBase,
                         boundary_metadata::kMetadataBase + boundary_metadata::kMetadataMaxBytes,
                         "<boundary metadata>"});
    intervals.push_back({0, kLoaderNullBytes, "<null range>"});
    intervals.push_back({kLoaderKUser, kLoaderKUser + 0x1000, "<kuser>"});
    const auto& layout = layout_for(mode);
    intervals.push_back({layout.stack_base, layout.stack_base + layout.stack_size, "<stack>"});
    intervals.push_back({layout.heap_base, layout.heap_base + layout.heap_size, "<heap>"});
    intervals.push_back(
        {layout.env_base, layout.env_base + layout.env_block_size, "<environment>"});
    // the allocator's construction-time reservation: the SEH trampoline page
    // block the run maps first (the bump range grows at run time, and the
    // fixed heap/environment sit inside the nominal range)
    intervals.push_back({layout.alloc_base, layout.alloc_base + 0x21000, "<alloc range>"});
    if (mode == GuestMode::kX86) {
        intervals.push_back({kX86GdtBase, kX86GdtBase + kX86GdtSize, "<gdt>"});
        intervals.push_back({kLoaderWow64StubBase, kLoaderWow64StubBase + 0x1000, "<wow64 stub>"});
    }
    // zero-size intervals claim nothing and cannot overlap
    intervals.erase(std::remove_if(intervals.begin(), intervals.end(),
                                   [](const Interval& i) { return i.hi <= i.lo; }),
                    intervals.end());
    std::sort(intervals.begin(), intervals.end(),
              [](const Interval& a, const Interval& b) { return a.lo < b.lo; });
    for (std::size_t i = 1; i < intervals.size(); ++i) {
        if (intervals[i].lo < intervals[i - 1].hi) {
            return std::make_pair(intervals[i - 1].name, intervals[i].name);
        }
    }
    return std::nullopt;
}

std::expected<std::optional<boundary_metadata::MetadataInput>, RebuildFailure>
inspect_replay_metadata(const std::vector<snapshot::Region>& regions)
{
    namespace bm = boundary_metadata;
    // side one: the fixed metadata region
    const snapshot::Region* meta_region = nullptr;
    for (const auto& region : regions) {
        if (region.header.base_address == bm::kMetadataBase) {
            if (region.header.content != snapshot::kContentPresent) {
                // a mapped-but-absent record: the payload was deleted
                meta_region = &region;
                break;
            }
            meta_region = &region;
            break;
        }
    }
    // side two: the derived ntdll's e_res2 marker (the directory world maps
    // its boundary ntdll at the first reserved base)
    std::optional<std::uint64_t> marker_va;
    bool marker_side_present = false;
    for (const auto& region : regions) {
        if (region.header.base_address != kBases64[0] ||
            region.header.content != snapshot::kContentPresent || region.content.size() < 0x1000) {
            continue;
        }
        auto marked = bm::read_marker(std::span<const std::uint8_t>(region.content.data(), 0x1000));
        if (marked.has_value()) {
            // a value: the marked ntdll; nullopt: checked, unmarked image
            if (marked->has_value()) {
                marker_side_present = true;
                marker_va = **marked;
            }
        } else if (marked.error().code != bm::MetadataError::kBadMarker) {
            return std::unexpected(
                failure(RebuildError::kBadSnapshot,
                        std::format("replay mode marker rejected: {} ({})",
                                    bm::metadata_error_message(marked.error().code),
                                    marked.error().detail)));
        }
        break; // one region carries the ntdll's first page
    }
    if (meta_region == nullptr && !marker_side_present) {
        return std::nullopt; // both sides absent: the legacy route
    }
    if (meta_region == nullptr) {
        return std::unexpected(failure(RebuildError::kBadSnapshot,
                                       "directory-mode marker present but the metadata "
                                       "region is missing"));
    }
    if (!marker_side_present) {
        return std::unexpected(failure(RebuildError::kBadSnapshot,
                                       "directory-mode metadata region present but the "
                                       "ntdll mode marker is missing"));
    }
    if (meta_region->header.content != snapshot::kContentPresent) {
        return std::unexpected(failure(RebuildError::kBadSnapshot,
                                       "directory-mode metadata region carries no record"));
    }
    if (marker_va != bm::kMetadataBase) {
        return std::unexpected(failure(
            RebuildError::kBadSnapshot,
            std::format("mode marker points at 0x{:x}, not the metadata base", *marker_va)));
    }
    auto decoded = bm::decode(meta_region->content);
    if (!decoded.has_value()) {
        return std::unexpected(failure(RebuildError::kBadSnapshot,
                                       std::format("directory-mode metadata rejected: {} ({})",
                                                   bm::metadata_error_message(decoded.error().code),
                                                   decoded.error().detail)));
    }
    return std::optional(std::move(*decoded));
}

std::vector<std::uint64_t> synthetic_world_bases(const GuestMode mode,
                                                 const std::filesystem::path& module_dir)
{
    const auto& core = mode == GuestMode::kX64 ? kBases64 : kBases86;
    // The three main bases always count: a container built with the
    // synthetic directory is recognizable even when the directory is not at
    // hand (the rebuild then reports the explicit missing-modules failure).
    std::vector<std::uint64_t> bases{core[0], core[1], core[2]};
    if (!module_dir.empty()) {
        const auto plan = plan_synthetic_directory(mode, module_dir);
        for (const auto index : plan.core_indices) {
            bases.push_back(core[index]);
        }
        for (std::size_t i = 0; i < plan.extras.size(); ++i) {
            bases.push_back(extra_module_base(mode, i));
        }
    }
    std::sort(bases.begin(), bases.end());
    bases.erase(std::unique(bases.begin(), bases.end()), bases.end());
    return bases;
}

std::size_t count_synthetic_module_pages(std::span<const mem_region::ModuleImage> images,
                                         std::span<const std::uint64_t> bases)
{
    // Exact equality only: real captures share the address bands and the
    // step, so interval or modulo membership would misfire (review P1).
    std::size_t hits = 0;
    for (const auto& image : images) {
        if (image.module.synthesized) {
            continue;
        }
        if (std::find(bases.begin(), bases.end(), image.module.base) != bases.end()) {
            ++hits;
        }
    }
    return hits;
}

// Forward: the shared table rebuild, defined after this function. The
// optional API Set context carries the directory map into forwarder-chain
// resolution (a real system module's forwarders can target api-set names).
std::expected<void, SyscallRunError>
reattach_tables_from_images(PreparedGuest& guest, const loader::ApiSetContext* api_set_ctx);

std::expected<bool, SyscallRunError>
reattach_synthetic_world(PreparedGuest& guest, const std::filesystem::path& synthetic_module_dir)
{
    // a directory-mode container sits on the same fixed bases and must never
    // be re-hooked as the synthetic world: its bilateral marks say so, and
    // its tables were already restored at rebuild time
    if (guest.directory_metadata.has_value()) {
        return false;
    }
    const auto bases = synthetic_world_bases(guest.guest_mode, synthetic_module_dir);
    // A single exact coincidence is not the synthetic world. Replay with a
    // directory present (the CLI locates one on every non-Windows run, so a
    // replayed capture container is judged against the full ~7-value set)
    // would silently graft the synthetic Ldr semantics onto a real capture
    // at roughly 1e-4 per module per replay; two distinct hits are either
    // the construction's resident core (every canonical-directory module
    // sits on the set) or a coincidence squared (~1e-8). A directory with
    // fewer than two set-resident modules has no CLI producer and cannot
    // produce a recognizable container - out of contract by construction.
    if (count_synthetic_module_pages(guest.images, bases) < 2) {
        return false;
    }
    if (synthetic_module_dir.empty()) {
        return std::unexpected(SyscallRunError::kSyntheticModulesMissing);
    }
    guest.loader_modules.clear();
    guest.loader_exports.clear();
    guest.intercepts.clear();
    guest.ldr_entry_vas.clear();
    guest.tls_callbacks.clear();
    if (const auto reattached = reattach_tables_from_images(guest, nullptr);
        !reattached.has_value()) {
        return std::unexpected(reattached.error());
    }
    guest.loader_route = true;
    return true;
}

// The shared table rebuild over the guest's own images: loader modules,
// export index (with interception registration), Ldr entry VAs and the main
// image's TLS callbacks. Callers pre-clear the tables and decide the
// route semantics (synthetic vs resident) themselves.
std::expected<void, SyscallRunError>
reattach_tables_from_images(PreparedGuest& guest, const loader::ApiSetContext* api_set_ctx)
{
    const auto uc = guest.unicorn.get();
    // Pass 1: byte-complete module views (the forwarder-capable resolver
    // reads export directories, so the tables need the bytes, not a name
    // index).
    for (const auto& image : guest.images) {
        if (image.module.synthesized) {
            continue;
        }
        loader::LoadedModule module;
        module.base = image.module.base;
        module.image.assign(static_cast<std::size_t>(image.module.size), std::uint8_t{0});
        if (uc_mem_read(uc, module.base, module.image.data(), module.image.size()) != UC_ERR_OK) {
            return std::unexpected(SyscallRunError::kUnicornFailure);
        }
        std::memcpy(module.name.data(), image.module.name.data(), module.name.size());
        if (!loader::index_exports(module).has_value()) {
            return std::unexpected(SyscallRunError::kUnicornFailure);
        }
        guest.loaded_modules.push_back(std::move(module));
        guest.loader_modules.push_back(image.module);
    }
    // Pass 2: exports resolve through forwarder chains to their final VA -
    // a GetProcAddress caller must never receive a forwarder-string RVA as
    // code. The lookup key keeps the owning module (caller-side handle),
    // the registered VA is the callable endpoint.
    // a directory context means forwarder chains can target api-set names
    // (real system modules do); the synthetic routes keep the prefix rules
    const loader::ApiSetContext synthetic_ctx{};
    const loader::ApiSetContext& ctx = api_set_ctx != nullptr ? *api_set_ctx : synthetic_ctx;
    for (const auto& module : guest.loaded_modules) {
        for (const auto& [name, unresolvered_va] : module.exports) {
            static_cast<void>(unresolvered_va);
            const auto resolved =
                loader::resolve_export(guest.loaded_modules, std::string_view(module.name.data()),
                                       name, ctx, std::string_view(module.name.data()));
            if (!resolved.ok || resolved.module == nullptr) {
                continue; // unresolvable forwarder: not callable, skip
            }
            guest.loader_exports.push_back({module.base, resolved.va, name});
            if (const auto id = intercept_id_for(name); id.has_value()) {
                guest.intercepts.emplace_back(resolved.va, *id);
            }
        }
    }
    const auto entries = read_ldr_entries(uc, guest.metadata, guest.guest_mode);
    for (const auto& module : guest.loader_modules) {
        const auto found =
            std::find_if(entries.begin(), entries.end(),
                         [&module](const std::pair<std::uint64_t, std::uint64_t>& entry) {
                             return entry.first == module.base;
                         });
        if (found == entries.end()) {
            return std::unexpected(SyscallRunError::kBadSnapshot);
        }
        guest.ldr_entry_vas.push_back(found->second);
    }
    guest.tls_callbacks = read_tls_callbacks(uc, guest.metadata.image_base);
    return {};
}

// The directory-mode replay attach (design D6): the same registration logic
// the construction used - the tables rebuild from the guest's own images
// through reattach_tables_from_images, the API Set map reloads from the
// embedded record, the source table and boundary rules restore from the
// metadata - and every restored table is verified against the record. An
// incomplete restoration is the named rejection, never a half-attached run.
std::expected<void, SyscallRunError> attach_directory_world(PreparedGuest& guest)
{
    namespace bm = boundary_metadata;
    const auto& meta = *guest.directory_metadata;
    guest.loader_modules.clear();
    guest.loader_exports.clear();
    guest.intercepts.clear();
    guest.ldr_entry_vas.clear();
    guest.tls_callbacks.clear();
    guest.loaded_modules.clear();
    // the API Set map reloads FIRST (arch + anchor bound): the forwarder
    // chains in the rebuilt export tables can target api-set names, so the
    // context must be live before the tables resolve
    auto map_view = loader::ApiSetMapView::load(meta.apiset_bytes, loader::kApiSetMapArchX64,
                                                meta.apiset_anchor);
    if (!map_view.has_value()) {
        return std::unexpected(SyscallRunError::kBadSnapshot);
    }
    guest.api_set_map = std::move(*map_view);
    const loader::ApiSetContext api_set_ctx = [&] {
        loader::ApiSetContext ctx;
        ctx.mode = loader::ApiSetContext::Mode::kDirectoryMap;
        ctx.directory_map = &guest.api_set_map;
        return ctx;
    }();
    if (const auto reattached = reattach_tables_from_images(guest, &api_set_ctx);
        !reattached.has_value()) {
        return std::unexpected(reattached.error());
    }
    // the module records must match the restored resident set (the sample
    // image joins the Ldr set but carries no metadata record)
    for (const auto& record : meta.modules) {
        const auto found = std::find_if(guest.loader_modules.begin(), guest.loader_modules.end(),
                                        [&record](const mem_region::ModuleRecord& m) {
                                            return m.base == record.base && m.size == record.size &&
                                                   fold_name(std::string_view(m.name.data())) ==
                                                       fold_name(record.name);
                                        });
        if (found == guest.loader_modules.end()) {
            sheller::log::write(
                sheller::log::level::kWarning,
                std::format("attach-directory: module record missing: {}", record.name));
            return std::unexpected(SyscallRunError::kBadSnapshot);
        }
    }
    // the recorded intercept registrations must all be covered by the
    // rebuilt table (the rebuilt set is the name-driven superset)
    for (const auto& recorded : meta.intercepts) {
        const auto found = std::find_if(
            guest.intercepts.begin(), guest.intercepts.end(), [&recorded](const auto& registered) {
                return registered.first == recorded.va && registered.second == recorded.id;
            });
        if (found == guest.intercepts.end()) {
            sheller::log::write(sheller::log::level::kWarning,
                                std::format("attach-directory: intercept missing: va={:#x} id={}",
                                            recorded.va, recorded.id));
            return std::unexpected(SyscallRunError::kBadSnapshot);
        }
    }
    // the counting whitelist and trap stop points restore from the record,
    // resolved against the rebuilt tables (a counter or trap whose export
    // no longer resolves is an incomplete restoration)
    guest.stub_whitelist.clear();
    guest.boundary_trap_vas.clear();
    guest.boundary_trap_names.clear();
    // module base -> folded name, for matching the record's rows
    std::map<std::uint64_t, std::string> module_names;
    for (const auto& module : guest.loader_modules) {
        module_names.emplace(module.base, fold_name(std::string_view(module.name.data())));
    }
    for (const auto& counter : meta.counters) {
        const auto folded_module = fold_name(counter.module);
        const auto entry =
            std::find_if(guest.loader_exports.begin(), guest.loader_exports.end(),
                         [&](const LoaderExportEntry& candidate) {
                             const auto owner = module_names.find(candidate.module_base);
                             return owner != module_names.end() && owner->second == folded_module &&
                                    candidate.name == counter.name;
                         });
        if (entry == guest.loader_exports.end()) {
            sheller::log::write(sheller::log::level::kWarning,
                                std::format("attach-directory: counter export missing: {}!{}",
                                            counter.module, counter.name));
            return std::unexpected(SyscallRunError::kBadSnapshot); // incomplete restoration
        }
        if (counter.klass == 255) {
            // a trap row: the named stop point (ordinal from the record)
            std::uint32_t ordinal = 0;
            for (const auto& boundary : meta.boundaries) {
                if (fold_name(boundary.name) != folded_module) {
                    continue;
                }
                for (const auto& exported : boundary.exports) {
                    if (exported.name == counter.name) {
                        ordinal = exported.ordinal;
                    }
                }
            }
            guest.boundary_trap_vas.push_back(entry->function_va);
            guest.boundary_trap_names.emplace(
                entry->function_va, std::make_tuple(folded_module, counter.name, ordinal));
            continue;
        }
        guest.stub_whitelist.push_back(*entry);
    }
    // the source table and the boundary rules restore from the record (the
    // rules re-derive from the build-pinned manifest over the recorded
    // source-image hashes)
    guest.module_sources.clear();
    guest.boundary_rules.clear();
    for (const auto& record : meta.modules) {
        guest.module_sources.emplace_back(record.name,
                                          static_cast<SystemModuleSource>(record.source));
        auto rules =
            BoundaryManifest::committed().rules_for(record.name, "x64", record.image_xxhash64);
        if (rules.has_value()) {
            guest.boundary_rules.emplace(record.name, std::move(*rules));
        }
    }
    // fallback synthetic modules: the source table's kFallbackSynthetic
    // marks re-derive their whitelist rows (the existing synthetic rule -
    // every export counts); they never persist in the record
    for (const auto& [name, source] : guest.module_sources) {
        if (source != SystemModuleSource::kFallbackSynthetic) {
            continue;
        }
        const auto found =
            std::find_if(guest.loader_modules.begin(), guest.loader_modules.end(),
                         [&name](const mem_region::ModuleRecord& m) {
                             return fold_name(std::string_view(m.name.data())) == fold_name(name);
                         });
        if (found == guest.loader_modules.end()) {
            return std::unexpected(SyscallRunError::kBadSnapshot);
        }
        for (const auto& entry : guest.loader_exports) {
            if (entry.module_base == found->base) {
                guest.stub_whitelist.push_back(entry);
            }
        }
    }
    guest.directory_mode = true;
    guest.loader_route = true;
    return {};
}

// DLL-input route (photographed-world container, Windows capture):
// arrives with no loader tables - the rebuild fills images only. This
// rebuilds loader_modules/loader_exports/intercepts/ldr_entry_vas from the
// photographed world itself, so the run-time assembly (synthetic load,
// GetProcAddress, heap/Ldr interception) has its substrate. Armed only for
// containers carrying a pending block; construction-attached guests pass
// through untouched (false).
std::expected<bool, SyscallRunError> attach_resident_world(PreparedGuest& guest)
{
    if (!guest.pending.has_value() || guest.pending->bytes.empty()) {
        return false;
    }
    if (!guest.loader_modules.empty() || !guest.loader_exports.empty()) {
        return false; // construction already attached its tables
    }
    if (const auto reattached = reattach_tables_from_images(guest, nullptr);
        !reattached.has_value()) {
        return std::unexpected(reattached.error());
    }
    return true;
}

} // namespace sheller::engine
