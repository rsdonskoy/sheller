// The directory-delivered API Set map (design D5, change
// real-dll-module-dir): a versioned binary the user's system-module
// directory carries alongside its raw ntdll, generated offline from a
// reviewed text source. The reader is bounded over untrusted bytes and
// binds the map to exactly one (architecture, whole-file ntdll xxhash64)
// anchor - the unique applicability anchor, never a guess across several
// module hashes. Pure bytes: no unicorn, no filesystem.

#ifndef SHELLER_LOADER_APISET_MAP_H
#define SHELLER_LOADER_APISET_MAP_H

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sheller::loader {

enum class ApiSetMapError {
    kNone = 0,
    kTooSmall,       // less than the fixed header
    kBadMagic,       // the file does not carry the map magic
    kUnknownVersion, // header version this reader does not know
    kArchMismatch,   // the map was built for another architecture
    kAnchorMismatch, // the anchor ntdll hash differs from the query
    kOutOfBounds,    // entry count, pool range or a string range exceeds the file
    kConflict,       // the same (contract, importer) pair maps to two hosts
};

std::string_view apiset_map_error_message(ApiSetMapError error);

// Named rejection: the detail names the field and the offending value.
struct ApiSetMapFailure {
    ApiSetMapError code{};
    std::string detail;
};

// The architecture byte the format carries today. Phase 1 ships x64 maps
// only; the byte exists so a mismatch names itself.
inline constexpr std::uint8_t kApiSetMapArchX64 = 1;

// Loaded map view: validated once, queried per resolution. Copies the pool
// and the entry tuples out of the source bytes, so the view outlives them.
class ApiSetMapView {
  public:
    // Validates and loads a map. The (arch, ntdll_xxhash64) arguments are
    // the caller's world facts - the map must carry exactly them.
    static std::expected<ApiSetMapView, ApiSetMapFailure>
    load(std::span<const std::uint8_t> bytes, std::uint8_t arch, std::uint64_t ntdll_xxhash64);

    // The host module (folded, with extension) for one contract, honoring an
    // optional importer condition: an importer-specific entry beats the
    // unconditional entry for the same contract. Contract and importer are
    // folded names; the contract carries no ".dll". nullopt: unmapped.
    std::optional<std::string_view> host_for(std::string_view contract,
                                             std::string_view importer) const;

    std::size_t entry_count() const
    {
        return entries_.size();
    }

  private:
    struct Entry {
        std::string contract;
        std::string importer; // empty: unconditional
        std::string host;
    };
    std::vector<Entry> entries_;
};

} // namespace sheller::loader

#endif // SHELLER_LOADER_APISET_MAP_H
