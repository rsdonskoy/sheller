// Guest construction for both rebuild routes: prepare_guest rebuilds a
// captured snapshot at its original addresses, prepare_pe_file builds the
// loader route from a PE file (layered layout with resident system modules).
// Both produce the PreparedGuest the run stage executes.

#ifndef SHELLER_ENGINE_LOADER_ROUTE_H
#define SHELLER_ENGINE_LOADER_ROUTE_H

#include "rebuild_state.h"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <istream>
#include <optional>
#include <span>
#include <vector>

namespace sheller::engine {

std::expected<PreparedGuest, RebuildFailure> prepare_guest_stream(std::istream& in);

// DLL-input route: rebuild the loader tables for a photographed-world
// container that carries a pending-module block (Windows capture route).
// Construction-attached guests (synthetic route) pass through untouched.
std::expected<bool, SyscallRunError> attach_resident_world(PreparedGuest& guest);

// The finite base set the synthetic construction actually uses: the three
// main module bases (always, so a container without the directory is still
// recognized) plus the extras continuation positions bounded by the module
// directory's actual contents. Exact equality only - never interval or
// modulo membership (review P1).
std::vector<std::uint64_t> synthetic_world_bases(GuestMode mode,
                                                 const std::filesystem::path& module_dir);

// The synthetic-world predicate over enumerated Ldr module images: how many
// distinct images have a base that equals a member of the finite set exactly.
// Exact equality only - never interval or modulo membership (review P1).
std::size_t count_synthetic_module_pages(std::span<const mem_region::ModuleImage> images,
                                         std::span<const std::uint64_t> bases);

// Rebuilds the five loader-side tables (modules, exports, LDR entry VAs,
// interception pairs, TLS callbacks) and the loader_route marker from a
// replayed container plus the synthetic module directory. Returns false when
// the container does not carry the synthetic module pages (capture containers
// keep their replay behavior untouched); recognition needs at least two
// distinct module pages on the finite base set - a single exact coincidence
// is the capture-replay noise floor, not the synthetic world. A hit without
// a directory is the explicit missing-modules failure.
std::expected<bool, SyscallRunError>
reattach_synthetic_world(PreparedGuest& guest, const std::filesystem::path& synthetic_module_dir);

// The directory-mode replay attach: rebuilds the full run
// tables (modules, exports, normal semantic intercepts, API Set context,
// source table, boundary rules) from the guest's own images plus the
// decoded metadata record, verifying each against the record. Declared for
// the run-stage tests; prepare_guest_stream calls it before execution.
std::expected<void, SyscallRunError> attach_directory_world(PreparedGuest& guest);

// The bilateral replay-side check: the derived ntdll's e_res2
// mode marker and the fixed metadata region must both be present and agree
// (version, address); either side alone, or a damaged payload, is the named
// rejection - never a silent fall back to the legacy route. Both sides
// absent: nullopt, the container route without a directory.
std::expected<std::optional<boundary_metadata::MetadataInput>, RebuildFailure>
inspect_replay_metadata(const std::vector<snapshot::Region>& regions);

// The directory mode's full-interval overlap gate: every mapped
// interval - the resident modules, the sample image, the fixed environment
// regions (stack, heap, environment block, KUSER, the null range, the
// allocator bump range) - must be pairwise disjoint, whole-interval, never
// base-equality-only. Returns the two interval names that overlap;
// nullopt = disjoint.
std::optional<std::pair<std::string, std::string>>
find_directory_range_overlap(std::span<const loader::LoadedModule> modules, GuestMode mode,
                             std::uint64_t sample_base, std::uint64_t sample_size);

// Loader route: build the address space
// from a PE file instead of a snapshot, and produce the same PreparedGuest
// the snapshot path runs. An empty system_modules_dir keeps the existing
// synthetic/host routes; a set one switches to the directory mode's strict
// source tiers.
std::expected<PreparedGuest, RebuildFailure>
prepare_pe_file(const std::filesystem::path& path, bool fidelity_seams = true,
                const std::filesystem::path& synthetic_module_dir = {},
                const std::filesystem::path& system_modules_dir = {},
                bool system_modules_fallback = false);

std::expected<PreparedGuest, RebuildFailure> prepare_guest(const std::filesystem::path& path);

} // namespace sheller::engine

#endif // SHELLER_ENGINE_LOADER_ROUTE_H
