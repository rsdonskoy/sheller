// Memory region map: every region of the
// captured guest address space attributed to its owner - module images
// refined to PE32+ sections from the Ldr list and image headers, and every
// other snapshot region (private/mapped) attributed at region level with
// its captured protection and MEM type. The shared substrate for xfer
// attribution, the export-walk / direct-syscall signals and
// dump metadata. The map is a run-time ledger: memory-map seams register
// guest allocations and protection flips as they happen (register_region /
// apply_protection), and the evolution is a pure function of the call
// sequence, so replays stay byte-identical. Construct-injected and
// stateless by the house rules; the section-table parse is a pure byte
// function, fuzzable. The unicorn handle is forward declared so
// this header keeps the engine boundary free of third-party includes.

#ifndef SHELLER_ENGINE_MEM_REGION_MAP_H
#define SHELLER_ENGINE_MEM_REGION_MAP_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

struct uc_struct;
typedef struct uc_struct uc_engine;

namespace sheller::engine {

// winnt.h MEM_* types: the captured facts and the types the allocation
// seams register (the loader maps and the guest allocates at run time).
inline constexpr std::uint32_t kMemPrivate = 0x20000;
inline constexpr std::uint32_t kMemMapped = 0x40000;
inline constexpr std::uint32_t kMemImage = 0x1000000;

// winnt.h PAGE_* protections (the low byte the engine switches on).
inline constexpr std::uint32_t kPageReadonly = 0x02;
inline constexpr std::uint32_t kPageReadwrite = 0x04;
inline constexpr std::uint32_t kPageWritecopy = 0x08;
inline constexpr std::uint32_t kPageExecute = 0x10;
inline constexpr std::uint32_t kPageExecuteRead = 0x20;
inline constexpr std::uint32_t kPageExecuteReadwrite = 0x40;
inline constexpr std::uint32_t kPageExecuteWritecopy = 0x80;
inline constexpr std::uint32_t kPageGuard = 0x100;

// All PAGE_EXECUTE* protections share the high nibble of the low byte.
inline constexpr std::uint32_t kProtectionExecuteBits =
    kPageExecuteRead | kPageExecuteReadwrite | kPageExecuteWritecopy;

// True when the captured page protection is executable (any EXECUTE_*
// protection): the code-execution qualifier of "private executable memory".
inline constexpr bool protection_executable(const std::uint32_t protection)
{
    return (protection & kProtectionExecuteBits) != 0;
}

namespace mem_region {

// Name capacity for module records: BaseDllName folds into lowercase ASCII
// and truncates here - names only feed reports and by-name lookups of the
// well-known system modules, all far below this bound.
inline constexpr std::size_t kModuleNameBytes = 64;
// Section names are 8 bytes in the PE spec; +1 for the NUL.
inline constexpr std::size_t kSectionNameBytes = 9;
// DOS + NT headers + section table fit in the first page of every real
// image; reads are capped there.
inline constexpr std::size_t kImageHeaderBytes = 0x1000;

// Module-walk capacity: the Ldr enumeration truncates here, so the module
// index space can never reach the xfer sentinel segment below.
inline constexpr std::size_t kMaxModuleImages = 64;

// xfer payload sentinel segment for region-level landings (no module/section
// refinement): 0xFF0x = snapshot-captured region classes, 0xFF1x =
// runtime-registered region classes (the same class rides the same slot in
// both tiers - only the signal layer tells them apart), 0xFF00 =
// unclassified fallback, 0xFFFF = the legacy no-module sentinel.
inline constexpr std::uint16_t kRegionSentinelBase = 0xFF00;
inline constexpr std::uint16_t kRegionSentinelUnclassified = 0xFF00;
inline constexpr std::uint16_t kRegionSentinelSnapshotBase = 0xFF00; // 0xFF0x tier
inline constexpr std::uint16_t kRegionSentinelRuntimeBase = 0xFF10;  // 0xFF1x tier

// One loaded module: Ldr DllBase / SizeOfImage plus the folded BaseDllName
// (UTF-16 guest text folded to lowercase ASCII, NUL-padded). synthesized
// marks an unknown-image synthesis product (never a real Ldr entry): the
// engine-side module iterations (ISA gate normalization, SEH dispatch
// attribution) skip these records, keeping their behavior byte-identical.
struct ModuleRecord {
    std::uint64_t base{};
    std::uint64_t size{};
    std::array<char, kModuleNameBytes> name{};
    bool synthesized{};
};

// A module plus the first kImageHeaderBytes of its guest image - the parse
// input for the section table. Short reads surface as parse errors, never
// as silently ignored sections.
struct ModuleImage {
    ModuleRecord module{};
    std::vector<std::uint8_t> header_bytes;
};

// Enumerates all modules of the rebuilt guest from its Ldr list, collecting
// each image's header bytes. Defensively bounded (kMaxModuleImages entries;
// failed reads truncate the walk) - the guest is untrusted input.
std::vector<ModuleImage> enumerate_guest_images(uc_engine* uc, bool wow64 = false,
                                                std::uint64_t wow64_teb = 0);

// Region-level classification: private-exec / private-data / mapped /
// unclassified, derived from the raw (PAGE_*, MEM_*) facts. MEM_IMAGE
// never classifies - an image's alignment gap must not turn private-exec
// from its execute bits - and neither do unknown types or zero protection.
enum class RegionClass : std::uint32_t {
    kUnclassified = 0,
    kPrivateExec = 1,
    kPrivateData = 2,
    kMapped = 3,
};

[[nodiscard]] constexpr RegionClass region_class(const std::uint32_t protection,
                                                 const std::uint32_t type)
{
    if (protection == 0) {
        return RegionClass::kUnclassified;
    }
    if (type == kMemPrivate) {
        // "Carries an execute bit": the whole PAGE_EXECUTE* family, the
        // high nibble of the low byte.
        return (protection & 0xF0u) != 0 ? RegionClass::kPrivateExec : RegionClass::kPrivateData;
    }
    if (type == kMemMapped) {
        return RegionClass::kMapped;
    }
    return RegionClass::kUnclassified;
}

// The xfer payload module slot for a region-level landing: the class rides
// its tier's sentinel (0xFF0x snapshot / 0xFF1x runtime), unclassified
// falls back to 0xFF00 regardless of tier.
[[nodiscard]] constexpr std::uint16_t region_class_sentinel(const RegionClass classification,
                                                            const bool runtime_registered)
{
    if (classification == RegionClass::kUnclassified) {
        return kRegionSentinelUnclassified;
    }
    const auto slot = static_cast<std::uint16_t>(classification);
    return runtime_registered ? static_cast<std::uint16_t>(kRegionSentinelRuntimeBase + slot)
                              : static_cast<std::uint16_t>(kRegionSentinelSnapshotBase + slot);
}

// The runtime-registered tier's sentinels (0xFF11..0xFF13): the signal
// layer treats these module slots as sample territory (arming source).
[[nodiscard]] constexpr bool is_runtime_region_sentinel(const std::uint16_t module_slot)
{
    return module_slot > kRegionSentinelRuntimeBase &&
           module_slot <= kRegionSentinelRuntimeBase + 3;
}

// One non-image region: the captured facts (raw PAGE_* protection
// and raw MEM_* type), not interpretations. origin is the stable
// allocation identity (monotonic per map: snapshot regions take their
// construction index, each registered allocation the next counter value);
// runtime_registered marks the sample's own run-time allocations - issued
// from sample territory. System-issued run-time allocations (CRT/CLR JIT
// machinery) are infrastructure and carry false, like snapshot captures.
// Protection updates carve NEW records - a record's facts are immutable
// once appended.
struct RegionRecord {
    std::uint64_t base{};
    std::uint64_t size{};
    std::uint32_t protection{};
    std::uint32_t type{};
    std::uint32_t origin{};
    bool runtime_registered{};
};

// Errors of pe_parse_error / parse_section_table only - the map
// construction itself has no failure path (images that fail to parse
// contribute no section intervals).
enum class PeParseError {
    kNone = 0,
    kBadDos,       // missing MZ signature or e_lfanew out of range
    kBadPe,        // missing PE signature or headers truncated
    kNotPe32Plus,  // not a PE32+ image (x86 images are not supported)
    kTruncated,    // section table extends past the input
    kBadImageSize, // SizeOfImage outside [1, 4GB)
};

std::string_view pe_parse_error_message(PeParseError error);

// One section of a parsed image: guest-relative span [rva, rva + span) and
// the raw section characteristics. span is align_up(max(virtual_size,
// size_of_raw_data), section_alignment) with overflow clamped.
struct SectionRecord {
    std::uint32_t rva{};
    std::uint32_t span{};
    std::uint32_t characteristics{};
    std::array<char, kSectionNameBytes> name{};
};

struct ImageLayout {
    std::uint32_t size_of_headers{};
    std::uint32_t size_of_image{}; // optional-header value, [1, 4GB) or the parse failed
    std::vector<SectionRecord> sections;
};

// Parses the section table from the first bytes of a loaded PE32+ image.
PeParseError parse_section_table(const std::uint8_t* image, std::size_t size, ImageLayout& out);

// One synthesis candidate: a snapshot region's captured facts (base, size,
// MEM_* type) plus the span of its content bytes (empty when the region
// carried no content). A plain value view on purpose - the synthesis below
// is a pure function of these and never sees the snapshot file format.
struct UnknownImageCandidate {
    std::uint64_t base{};
    std::uint64_t size{};
    std::uint32_t type{};
    std::span<const std::uint8_t> content{};
};

// Image-group synthesis of hand-mapped images the Ldr walk never
// enumerated (reflective loads): candidates are chained while adjacent
// (previous end == next base) and MEM_IMAGE, a chain overlapping any Ldr
// module span is abandoned whole, and the lowest 64KB-aligned member base
// anchors the image - the PE32+ headers parse from that member's content.
// Size is min(size_of_image, chain union); the name is
// "unknown-image-<16 lowercase hex digits of base>". Products are appended
// after the Ldr set ascending by base (the load-bearing order: sample
// module ordinals and signal arming align against it), self-clamped to
// kMaxModuleImages minus the Ldr count (candidates skip, never Ldr). Every
// product carries the synthesized flag. Deterministic: same input, same
// output; candidates that fail any criterion contribute nothing and keep
// their region-level attribution.
std::vector<ModuleImage>
synthesize_unknown_images(std::span<const ModuleImage> ldr_images,
                          std::span<const UnknownImageCandidate> candidates);

enum class AttributionKind {
    kImageSection, // inside a module image section interval
    kImageHeaders, // inside a module image header pseudo-section
    kRegion,       // inside a non-image region (snapshot or runtime-registered)
};

// Stable value identity of an attribution interval: the image layer keys on
// (module, section), the region layer on (allocation origin, class). The
// class rides its wire sentinel (see region_class_sentinel), so the tier is
// part of the key. Interval storage indexes change on split/re-sort; this
// key survives them, which is what the xfer capture compares.
struct AttributionIdentity {
    AttributionKind kind{};
    std::uint32_t primary{};   // image: module index; region: allocation origin
    std::uint32_t secondary{}; // image: section index; region: class sentinel
};

[[nodiscard]] constexpr bool operator==(const AttributionIdentity& a, const AttributionIdentity& b)
{
    return a.kind == b.kind && a.primary == b.primary && a.secondary == b.secondary;
}

// xfer payload slots (module u16, section u16) of one identity: the image
// layer emits module/section; the region layer emits the class sentinel in
// the module slot and the no-section sentinel.
[[nodiscard]] constexpr std::pair<std::uint16_t, std::uint16_t>
xfer_payload_slots(const AttributionIdentity& identity)
{
    if (identity.kind == AttributionKind::kRegion) {
        return {static_cast<std::uint16_t>(identity.secondary), 0xFFFF};
    }
    return {static_cast<std::uint16_t>(identity.primary),
            static_cast<std::uint16_t>(identity.secondary)};
}

// True when the executed block transitioned to a different attribution
// identity; whether that transition emits an xfer event is the edge
// rules' call (is_xfer_edge) - same-identity steps stay silent regardless.
[[nodiscard]] constexpr bool is_xfer_transition(const AttributionIdentity& previous,
                                                const AttributionIdentity& current)
{
    return !(previous == current);
}

// Sentinels for region-level attributions: no module/section refinement
// exists there; the xfer payload spells region classes through the sentinel
// segment above.
inline constexpr std::size_t kNoModuleIndex = 0xFFFF;
inline constexpr std::size_t kNoSectionIndex = 0xFFFF;

struct MemAttribution {
    AttributionKind kind{};
    std::size_t region_index{};     // always set: the owning region record
    std::uint32_t protection{};     // raw PAGE_* of the owning region record
    std::uint32_t type{};           // raw MEM_* of the owning region record
    AttributionIdentity identity{}; // stable interval identity (xfer compare key)
    bool runtime_registered{};      // region attributions: sample-issued run-time allocation
    bool runtime_event{};           // region attributions: registered during this run
                                    // (any issuer) - distinguishes infrastructure
                                    // allocations from captured snapshot regions
    std::size_t module_owner{kNoModuleIndex}; // region attributions: overlapping or
                                              // contiguous module span (image gaps,
                                              // companion thunk pages), if any
    std::uint32_t origin{};                   // region attributions: allocation identity
    std::size_t module_index{};               // image attributions only
    std::string_view module_name{};
    std::size_t section_index{}; // 0 = headers pseudo-section
    std::string_view section_name{};
    std::uint32_t characteristics{}; // section characteristics (image only)
};

// Sample-territory class of one attribution for the xfer edge rules: the
// sample's own image (its span gaps included), memory the sample allocated
// at run time, orphan captured regions (outside every module span and not
// contiguous with one - the packed sample's out-of-image stub page), or
// everything else (system modules, their gaps and companion pages,
// system-issued infrastructure allocations).
enum class XferTerritory : std::uint8_t { kOther, kSampleImage, kSampleAlloc };

[[nodiscard]] constexpr XferTerritory xfer_territory(const MemAttribution& attribution,
                                                     std::size_t sample_module_index)
{
    if (attribution.kind == AttributionKind::kRegion) {
        if (attribution.runtime_registered) {
            return XferTerritory::kSampleAlloc;
        }
        if (attribution.runtime_event) {
            return XferTerritory::kOther; // system-issued allocation: infrastructure
        }
        if (attribution.module_owner == kNoModuleIndex) {
            return XferTerritory::kSampleAlloc; // orphan captured region: sample side
        }
        // Captured region tied to a module: the sample's own span gaps are
        // sample image (the packed stub's tail page); system modules' gaps
        // and companion pages (ntdll's forwarder-thunk page) are theirs.
        return attribution.module_owner == sample_module_index ? XferTerritory::kSampleImage
                                                               : XferTerritory::kOther;
    }
    return attribution.module_index == sample_module_index ? XferTerritory::kSampleImage
                                                           : XferTerritory::kOther;
}

// The xfer edge rules, exhaustively: sample image section -> sample image
// section, sample image -> sample-allocated memory, sample-allocated
// memory -> sample image. Everything else - system-module crossings in
// both directions, allocation-to-allocation hops, entries into system-
// issued (infrastructure) memory - stays silent.
[[nodiscard]] constexpr bool is_xfer_edge(XferTerritory previous, XferTerritory current)
{
    if (previous == XferTerritory::kSampleImage) {
        return current == XferTerritory::kSampleImage || current == XferTerritory::kSampleAlloc;
    }
    if (previous == XferTerritory::kSampleAlloc) {
        return current == XferTerritory::kSampleImage;
    }
    return false;
}

static_assert(kMaxModuleImages < kRegionSentinelBase,
              "module indexes must never reach the region sentinel segment");

// Interval attribution over the enumerated module images and the remaining
// snapshot regions, evolving at run time: allocations register, protection
// flips carve. Intervals are sorted by start; of all intervals holding
// an address the most specific one (smallest span) wins, so image sections
// and the header pseudo-section refine their containing image region.
class MemRegionMap {
  public:
    MemRegionMap(std::span<const ModuleImage> images, std::span<const RegionRecord> regions);

    // Run-time registration of one guest allocation (the memory-map seams).
    // Appends the region record - monotonic origin, runtime_registered per
    // the issuer - and its interval. sample_issued marks the sample's own
    // allocation (sample territory: xfer edges, arming, read facts);
    // system-issued allocations register with false (infrastructure: mapped
    // and answered, but event-silent). The sequence of calls is the state:
    // same sequence, same map.
    void register_region(std::uint64_t base, std::uint64_t size, std::uint32_t protection,
                         std::uint32_t type, bool sample_issued);
    // Run-time registration of a synthesized module image (the DLL-input
    // route's synthetic load): the span becomes a MEM_IMAGE region record
    // (infrastructure-issued - the engine maps it, not the sample) refined
    // by the module's section intervals. Returns the new module's index.
    std::size_t register_module_image(const ModuleImage& image,
                                      std::uint32_t protection = kPageExecuteReadwrite);
    // Page-granular protection update: the covered part of every region
    // interval is carved into a NEW region record (new protection, inherited
    // origin and runtime flag) and the interval re-pointed there; uncovered
    // parts keep the original record. Image section intervals keep their
    // owning-record reference - image refinement is structural, and MEM_IMAGE
    // never classifies anyway. Consumers reading through region() see the
    // carved record.
    void apply_protection(std::uint64_t base, std::uint64_t size, std::uint32_t protection);

    [[nodiscard]] std::optional<MemAttribution> query(std::uint64_t address) const;

    // Case-sensitive lookup against the folded (lowercase) module names.
    [[nodiscard]] std::optional<std::size_t> module_index_by_name(std::string_view name) const;

    [[nodiscard]] std::size_t module_count() const
    {
        return modules_.size();
    }

    [[nodiscard]] const ModuleRecord& module(std::size_t index) const
    {
        return modules_[index];
    }

    // Region-level extent/protection/type of one owning region record - the
    // MEMORY_BASIC_INFORMATION source for NtQueryVirtualMemory semantics.
    // After a protection flip the owning index resolves to the carved
    // record: the answer carries the new protection and the split extent.
    [[nodiscard]] const RegionRecord& region(std::size_t index) const
    {
        return regions_[index];
    }

    [[nodiscard]] std::size_t region_count() const
    {
        return regions_.size();
    }

  private:
    struct Interval {
        std::uint64_t start{};
        std::uint64_t end{};
        std::size_t region_index{};
        std::size_t module_index{};
        std::size_t section_index{};
        bool image{};
        std::uint32_t protection{};
        std::uint32_t type{};
        std::uint32_t characteristics{};
        std::array<char, kSectionNameBytes> section_name{};
    };

    void sort_intervals();

    // Resolves one region record's module owner: a module whose span it
    // overlaps (image alignment gaps sit inside the module span) or is
    // contiguous with (companion thunk pages). kNoModuleIndex when neither.
    void set_region_owner(std::size_t index);

    std::vector<ModuleRecord> modules_;
    std::vector<RegionRecord> regions_;
    std::vector<std::uint8_t> region_runtime_event_; // parallel to regions_: run-time registered
    std::vector<std::size_t> region_module_owner_;   // parallel to regions_: kNoModuleIndex = none
    std::vector<Interval> intervals_;
    std::uint32_t next_origin_{}; // monotonic allocation identity source
};

} // namespace mem_region

} // namespace sheller::engine

#endif // SHELLER_ENGINE_MEM_REGION_MAP_H
