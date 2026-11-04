// Module-private test probe: rebuild + bounded run, then read the live
// Unicorn state back (registers, GS_BASE, memory spot checks). Keeps the
// public facade free of unicorn types while letting tests pin the rebuild
// semantics on both platforms.

#ifndef SHELLER_ENGINE_REBUILD_PROBE_H
#define SHELLER_ENGINE_REBUILD_PROBE_H

#include <sheller/rebuild.h>

#include "../syscalls/syscall_number_map.h"
#include "mem_region_map.h"

#include <array>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <vector>

namespace sheller::engine::detail {

struct RebuildProbe {
    RebuildStats stats{};
    std::uint64_t gs_base{};
    std::uint64_t rip{};
    std::uint64_t rflags{};
    std::array<std::uint64_t, 16> gpr{};
    // The first bytes at the entry address, read back from Unicorn memory.
    std::array<std::uint8_t, 2> entry_bytes{};
};

std::expected<RebuildProbe, RebuildFailure>
rebuild_and_probe(const std::filesystem::path& snapshot_path);

// Attribution probe: the enumerated module images, the snapshot regions,
// and the real syscall numbers resolved from the guest ntdll stubs, for the
// region-map and syscall-number e2e tests.
struct ExportSlotProbe {
    std::uint64_t module_base{}; // owning module (join against images)
    std::uint64_t slot_va{};     // functions-array entry a walking reader touches
    std::uint64_t function_va{}; // the exported function itself
    std::array<char, 64> name{}; // folded export name
};

struct AttributionProbe {
    std::vector<mem_region::ModuleImage> images;
    // Unknown-image synthesis products (the map's module tail): kept apart
    // from the Ldr set so consumers iterating images (export enumeration,
    // the IAT repair's whole-image reads) never see a synthesized record.
    std::vector<mem_region::ModuleImage> unknown_images;
    std::vector<mem_region::RegionRecord> regions;
    std::vector<syscalls::SyscallNumberEntry> syscall_numbers;
    // Per-module export functions-array slots (behavior-layer export-walk
    // table); bounded by the export enumerator's own caps.
    std::vector<ExportSlotProbe> export_slots;
    // Snapshot metadata basics the behavior layer's params need.
    std::uint64_t teb_address{};
    std::uint64_t peb_address{};
    std::uint64_t image_base{};
    std::uint64_t image_size{};
};

std::expected<AttributionProbe, RebuildFailure>
attribute_snapshot_modules(const std::filesystem::path& snapshot_path);

// Same probe from in-memory snapshot bytes (the one-shot unpack flow).
std::expected<AttributionProbe, RebuildFailure>
attribute_snapshot_modules(const std::vector<std::uint8_t>& snapshot);

// Full module images from a rebuilt snapshot: every Ldr module's
// [base, base + size) bytes read back from the live Unicorn instance, for
// consumers that need more than the header (the IAT repair's export
// mapper).
struct ModuleImageProbe {
    mem_region::ModuleRecord module{};
    std::vector<std::uint8_t> image{};
};

std::expected<std::vector<ModuleImageProbe>, RebuildFailure>
read_module_images(const std::filesystem::path& snapshot_path);

std::expected<std::vector<ModuleImageProbe>, RebuildFailure>
read_module_images(const std::vector<std::uint8_t>& snapshot);

// Reads [base, base + size) from the rebuilt snapshot's memory. Fails when
// the range is not fully mapped (the caller decides what a partial view
// means for its own byte-sourcing policy).
std::expected<std::vector<std::uint8_t>, RebuildFailure>
read_snapshot_range(const std::filesystem::path& snapshot_path, std::uint64_t base,
                    std::uint32_t size);

std::expected<std::vector<std::uint8_t>, RebuildFailure>
read_snapshot_range(const std::vector<std::uint8_t>& snapshot, std::uint64_t base,
                    std::uint32_t size);

} // namespace sheller::engine::detail

#endif // SHELLER_ENGINE_REBUILD_PROBE_H
