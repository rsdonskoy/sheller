// Loader import resolution: IAT walk and
// export lookup with bounded forwarder chaining, over host-side module
// images. Pure byte functions - no unicorn - so resolution is unit-testable
// and deterministic. Unresolvable thunks are recorded, never fatal (the
// IAT-repair "best effort" principle).

#ifndef SHELLER_LOADER_IMPORTS_H
#define SHELLER_LOADER_IMPORTS_H

#include "apiset_map.h"
#include "loader.h"

#include <array>

#include <string>
#include <vector>

namespace sheller::loader {

// One mapped module's host-side view: image bytes at SizeOfImage, folded
// lowercase name, and its export name->function-VA index.
struct LoadedModule {
    std::uint64_t base{};
    std::vector<std::uint8_t> image; // SizeOfImage bytes
    std::array<char, 64> name{};     // folded lowercase with extension
    // name-sorted export index (exact-match lookup)
    std::vector<std::pair<std::string, std::uint64_t>> exports;
};

// Parses the module's export directory into the name-sorted index. Forwarder
// entries are flagged: their "address" is the RVA of the forwarder string
// inside the export directory.
std::expected<void, LoadError> index_exports(LoadedModule& module);

// API Set Schema pre-pass (real loader: PEB.ApiSetMap): an api-ms-win-* set
// name reduces to its host DLL name before any module or export lookup - the
// set name itself is never a module. Static prefix rules cover the real
// schema (the crt sets are hosted by ucrtbase, the core/shell sets by
// kernelbase). Takes and returns folded names; empty when not a set.
std::string_view api_set_host(std::string_view folded_name);

struct ResolvedExport {
    bool ok{};        // false: unresolvable (recorded by the caller)
    bool forwarded{}; // the export was a forwarder string
    // Directory-map mode only: the requested name has the api-set shape
    // (api-ms-* / ext-ms-*) and the map does not cover it. The caller turns
    // this into its named rejection - the map never falls back to a prefix
    // guess, and no other failure path sets this flag.
    bool unmapped_api_set{};
    std::string missing_module{}; // actual missing host, including forwarder endpoints
    std::uint64_t va{};           // resolved function VA (ok && !forwarded)
    const LoadedModule* module{}; // owning module of the final resolution
    std::string final_name{};     // final resolved function name
};

// The API-set resolution policy, explicit per world: the
// synthetic-mode static prefix rules, or the directory-delivered map. One
// world carries one context object, and the same context backs import
// admission, resident-module IAT binding, the runtime DLL route and the
// dynamic queries - a resolution answer never depends on which call site
// asked.
struct ApiSetContext {
    enum class Mode {
        kSyntheticPrefixes, // api_set_host prefix rules (the existing route)
        kDirectoryMap,      // the directory's apiset-map.bin; no fallback
    };
    Mode mode{Mode::kSyntheticPrefixes};
    const ApiSetMapView* directory_map{}; // kDirectoryMap: the loaded map view
};

// Exact-name export lookup in one module. A forwarder entry ("dll.func")
// starts a bounded chain across `modules` (up to 4 hops); the final stop's
// function VA wins and `module`/`final_name` describe it. The context
// decides how api-set names reduce: the two-argument spelling keeps the
// synthetic prefix rules (the existing route, byte-for-byte unchanged).
ResolvedExport resolve_export(const std::vector<LoadedModule>& modules,
                              const std::string_view module_name,
                              const std::string_view function_name);
// Import-by-ordinal: the ordinal rides as typed data, never re-encoded as a
// name string - a requested export literally named "#5" resolves by that
// exact name. EAT index arithmetic against the target's image; a forwarded
// slot follows the same bounded chain as a named export, including API Set
// targets and ordinal forwarders (the PE-format "dll.#N" forwarder spelling
// is the one place '#' means an ordinal).
ResolvedExport resolve_ordinal_export(const std::vector<LoadedModule>& modules,
                                      const std::string_view module_name,
                                      const std::uint32_t ordinal);
ResolvedExport resolve_ordinal_export(const std::vector<LoadedModule>& modules,
                                      std::string_view module_name, std::uint32_t ordinal,
                                      const ApiSetContext& ctx, std::string_view importer_name);
ResolvedExport resolve_export(const std::vector<LoadedModule>& modules,
                              const std::string_view module_name,
                              const std::string_view function_name, const ApiSetContext& ctx);
// importer_name: the importing module's folded name - importer-conditional
// map entries answer only when it is non-empty.
ResolvedExport resolve_export(const std::vector<LoadedModule>& modules,
                              const std::string_view module_name,
                              const std::string_view function_name, const ApiSetContext& ctx,
                              const std::string_view importer_name);

struct ImportFixup {
    std::uint64_t iat_rva{};  // image RVA of the IAT slot written
    std::uint64_t resolved{}; // function VA written into the slot
};

struct UnresolvedImport {
    std::string dll_name{};
    std::string function_name{};
    std::string missing_module{};
    bool unmapped_api_set{};
};

// Walks the sample image's import directory and resolves every thunk against
// `modules`, writing resolved VAs into the FirstThunk array in place.
// Unresolvable thunks are appended to `unresolved` (never fatal). The
// import directory is optional: absent (RVA 0) is a clean no-op. The
// two-context spelling threads an explicit API-set context plus the
// importing module's name (importer-conditional map entries answer only
// when the caller can name the importer); the short spelling keeps the
// synthetic prefix rules.
std::expected<std::vector<ImportFixup>, LoadError>
resolve_imports(std::span<std::uint8_t> image, const std::vector<LoadedModule>& modules,
                std::vector<UnresolvedImport>* unresolved);
std::expected<std::vector<ImportFixup>, LoadError>
resolve_imports(std::span<std::uint8_t> image, const std::vector<LoadedModule>& modules,
                std::vector<UnresolvedImport>* unresolved, const ApiSetContext& ctx,
                std::string_view importer_name, bool write = true);

// The directory mode's eager delayed-import binding (the construction-time
// policy over the delay-load directory, DataDirectory[13]): every
// RVA-addressed ImgDelayDescr's IAT slots that RESOLVE against the resident
// set take the final VAs; every resolution miss - the bound DLL absent, the
// map not covering the contract, the host missing the export - is
// tolerated with the slot keeping its construction-input bytes, because
// MSVC statically initializes failed-delay IAT entries to the module's own
// helper thunks and the real loader leaves them there (the capture
// corpus's slots match the file bytes + relocation delta slot-for-slot).
// That is the whole write set - the descriptor timestamps, module-handle
// slots, bound-IAT copies and unload tables also stay at their file bytes
// (the capture's records: zero/untouched with the IAT bound). `unresolved`
// is never filled; only a malformed descriptor (VA-addressed legacy form,
// fields out of range) is the named rejection via the returned error.
// `write=false` walks and reports without touching the image (the closure
// pass), `write=true` writes back (the binding pass). No delay directory
// is a clean no-op.
std::expected<std::vector<ImportFixup>, LoadError>
bind_delayed_imports(std::span<std::uint8_t> image, const std::vector<LoadedModule>& modules,
                     std::vector<UnresolvedImport>* unresolved, const ApiSetContext& ctx,
                     std::string_view importer_name, bool write);

} // namespace sheller::loader

#endif // SHELLER_LOADER_IMPORTS_H
