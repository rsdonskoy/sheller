// Container construction: turn a prepared guest (memory + registers +
// metadata, built by the loader route) into a v1 snapshot container the
// replay route consumes. The container is the single artifact the non-Windows
// sample route executes and the unpack pipeline repairs.

#ifndef SHELLER_ENGINE_CRAFT_H
#define SHELLER_ENGINE_CRAFT_H

#include "rebuild_state.h"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <vector>

namespace sheller::engine {

// Serializes the guest's live state: regions sorted by base with their
// payload read back from guest memory (all-zero payloads are recorded as
// content-absent), the current general registers, and the filled metadata.
// Deterministic: the same guest state yields byte-identical output.
std::expected<std::vector<std::uint8_t>, RebuildFailure>
craft_container_from_guest(const PreparedGuest& guest);

// Prepares a sample through the loader construction and serializes the
// result. Requires the synthetic module directory (the container is meant
// to carry those pages); 32-bit samples are refused - the non-Windows
// sample route reports that failure as a capture-class error.
std::expected<std::vector<std::uint8_t>, RebuildFailure>
craft_sample_container(const std::filesystem::path& pe_path, bool fidelity_seams,
                       const std::filesystem::path& synthetic_module_dir,
                       const std::filesystem::path& system_modules_dir = {},
                       bool system_modules_fallback = false);

} // namespace sheller::engine

#endif // SHELLER_ENGINE_CRAFT_H
