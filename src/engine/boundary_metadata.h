// The directory-mode metadata region (design D6, change real-dll-module-dir):
// a versioned, bounded, deterministic payload at the fixed guest base
// 0x7FF500000000, plus the independent mode marker in the derived ntdll's
// DOS e_res2 slot. The payload records the world's module source table
// (with source-image bindings), the actual boundary dispositions (semantic
// intercept ids, trap/compat VAs, syscall numbers), the counting whitelist
// and the complete API Set map (embedded verbatim, anchor included) - so a
// replay can recover the full boundary runtime without the original
// directory. No host paths anywhere. Pure bytes: no unicorn.

#ifndef SHELLER_ENGINE_BOUNDARY_METADATA_H
#define SHELLER_ENGINE_BOUNDARY_METADATA_H

#include "../loader/boundary_derive.h"
#include "../loader/imports.h"

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace sheller::engine::boundary_metadata {

// the fixed guest base and the hard capacity: an over-limit payload is a
// named rejection, never a truncation. The capacity sizes for a fully
// derived boundary pair: the real-build dispositions run ~62 bytes per
// export (2523 ntdll + ~1900 win32u slots), the module source table and
// the embedded apiset-map bytes ride alongside - 64KB (the fixture-scale
// first cut) overflowed at 163KB with the real ntdll alone.
inline constexpr std::uint64_t kMetadataBase = 0x7FF500000000ULL;
inline constexpr std::uint64_t kMetadataMaxBytes = 0x100000;
// the payload's semantic version - a reader that does not know it rejects
inline constexpr std::uint32_t kSemanticVersion = 1;

// The DOS e_res2 mode marker (design D6): 8-byte signature, u32 version,
// u64 metadata VA, little-endian, inside the reserved zero slot the
// derived image keeps at offset 0x28.
inline constexpr std::uint32_t kMarkerOffset = loader::kBoundaryMarkerOffset;
inline constexpr std::uint32_t kMarkerBytes = loader::kBoundaryMarkerSize;
inline constexpr std::uint8_t kMarkerMagic[8] = {'S', 'B', 'D', 'M', 'M', 'A', 'R', 'K'};

enum class MetadataError {
    kNone = 0,
    kOverLimit,      // the encoded payload exceeds the fixed capacity
    kBadMagic,       // decode: the payload does not carry the metadata magic
    kUnknownVersion, // decode: header version this reader does not know
    kBadPayloadHash, // decode: the payload's checksum does not match
    kOutOfBounds,    // decode: record counts, string ranges or the embedded
                     // API Set map exceed the payload
    kBadMarker,      // marker write/read: the reserved slot is not zero
};

std::string_view metadata_error_message(MetadataError error);

struct Failure {
    MetadataError code{};
    std::string detail;
};

// One resident module's source record. image_xxhash64 binds the record to
// the exact bytes this world was built from (the directory file for
// real-byte modules, the directory file behind the derivation for the
// boundary pair, the synthetic image for fallbacks).
struct ModuleRecord {
    std::string name; // folded, with extension
    std::uint64_t base{};
    std::uint32_t size{};
    std::uint8_t source{}; // SystemModuleSource
    std::uint64_t image_xxhash64{};
};

// One boundary export's actual disposition (the runtime contract the replay
// restores and verifies against guest memory).
struct BoundaryExportRecord {
    std::string name; // source spelling; empty: unnamed ordinal
    std::uint32_t ordinal{};
    std::uint8_t kind{}; // loader::BoundaryKind
    std::uint64_t va{};
    std::uint32_t syscall_number{};
};

struct BoundaryRecord {
    std::string name; // folded module name
    std::vector<BoundaryExportRecord> exports;
};

// One counting-whitelist row (event-ledger source rules): the (module,
// export) pairs whose stub entries count, with their class
// (compat / fallback synthetic).
struct CounterRecord {
    std::string module;   // folded
    std::string name;     // export spelling
    std::uint8_t klass{}; // 0 = derived compat, 1 = fallback synthetic stub
};

// The semantic intercept registrations the world actually made, so a replay
// verifies its rebuilt table against the record instead of trusting it.
struct InterceptRecord {
    std::uint64_t va{};
    std::uint32_t id{};
};

struct MetadataInput {
    std::vector<ModuleRecord> modules;
    std::vector<BoundaryRecord> boundaries;
    std::vector<CounterRecord> counters;
    std::vector<InterceptRecord> intercepts;
    // the complete API Set map, embedded verbatim (the directory's
    // apiset-map.bin bytes) with its anchor
    std::vector<std::uint8_t> apiset_bytes;
    std::uint64_t apiset_anchor{};
};

// Encodes the payload. Deterministic: same input, byte-identical output.
// kOverLimit when the payload would exceed the fixed capacity.
std::expected<std::vector<std::uint8_t>, Failure> encode(const MetadataInput& input);

// Decodes and validates a payload: magic, version, checksum, every record
// and string range bounded, the embedded API Set map fully inside.
std::expected<MetadataInput, Failure> decode(std::span<const std::uint8_t> payload);

// Writes the e_res2 mode marker into a derived image (the slot must be the
// reserved zeros). Deterministic.
std::expected<void, Failure> write_marker(std::span<std::uint8_t> derived_image,
                                          std::uint64_t metadata_va);

// Reads the marker: nullopt when the slot is the reserved zeros (an
// unmarked image); a failure when the slot carries a damaged or
// foreign-version marker.
std::expected<std::optional<std::uint64_t>, Failure>
read_marker(std::span<const std::uint8_t> image);

} // namespace sheller::engine::boundary_metadata

#endif // SHELLER_ENGINE_BOUNDARY_METADATA_H
