// sheller public snapshot format header - the v1 on-disk contract between the
// Win32 capture path (producer) and the engine rebuild path (consumer).
// Standard fixed-width integers only: no Windows or unicorn headers may leak
// in here, both sides include this file on any platform.

#ifndef SHELLER_SNAPSHOT_H
#define SHELLER_SNAPSHOT_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <iosfwd>
#include <string>
#include <string_view>
#include <vector>

namespace sheller::snapshot {

// The byte layout is fully determined and little-endian; both facts are
// golden-file tested. Any change here requires a format version bump.
inline constexpr std::uint8_t kMagic[8] = {'S', 'H', 'E', 'L', 'L', 'S', 'N', 'P'};
inline constexpr std::uint32_t kVersion = 1;
// v2 = v1 layout plus one trailing pending-module block (DLL-input route).
// v1 readers reject v2 at the header version check - that is the designed
// refusal channel (a v1 reader stops after region_count regions and would
// silently ignore trailing bytes otherwise).
inline constexpr std::uint32_t kVersionV2 = 2;
inline constexpr std::uint8_t kBitness64 = 64;
inline constexpr std::uint8_t kBitness32 = 32;

inline constexpr std::size_t kGprCount = 16;
inline constexpr std::size_t kOriginalEntryBytes = 16;

// v1 byte layout, derived from field widths with sizeof so the constants stay
// honest when a field width changes under a version bump. Header:
// magic | version | bitness | 3 reserved | region_count | 4 reserved.
inline constexpr std::size_t kVersionOffset = sizeof kMagic;
inline constexpr std::size_t kBitnessOffset = kVersionOffset + sizeof(std::uint32_t);
inline constexpr std::size_t kRegionCountOffset =
    kBitnessOffset + sizeof(std::uint8_t) + 3; // 3 reserved bytes
inline constexpr std::size_t kHeaderSize = kRegionCountOffset + sizeof(std::uint32_t) + 4;
// Register block: gpr[kGprCount] | rip | rflags.
inline constexpr std::size_t kRipOffset = kGprCount * sizeof(std::uint64_t);
inline constexpr std::size_t kRflagsOffset = kRipOffset + sizeof(std::uint64_t);
inline constexpr std::size_t kRegistersSize = kRflagsOffset + sizeof(std::uint64_t);
// Metadata block: peb | teb | image_base | entry_address | original_entry_bytes.
inline constexpr std::size_t kMetadataTebOffset = sizeof(std::uint64_t);
inline constexpr std::size_t kMetadataImageBaseOffset = 2 * sizeof(std::uint64_t);
inline constexpr std::size_t kMetadataEntryOffset = 3 * sizeof(std::uint64_t);
inline constexpr std::size_t kMetadataOriginalEntryOffset = 4 * sizeof(std::uint64_t);
inline constexpr std::size_t kMetadataSize = kMetadataOriginalEntryOffset + kOriginalEntryBytes;
// Region record: base | size | protection | type | content flag, then the
// payload bytes when the flag says present.
inline constexpr std::size_t kRegionSizeOffset = sizeof(std::uint64_t);
inline constexpr std::size_t kRegionProtectionOffset = 2 * sizeof(std::uint64_t);
inline constexpr std::size_t kRegionTypeOffset = kRegionProtectionOffset + sizeof(std::uint32_t);
inline constexpr std::size_t kRegionContentFlagOffset = kRegionTypeOffset + sizeof(std::uint32_t);
inline constexpr std::size_t kRegionRecordSize = kRegionContentFlagOffset + sizeof(std::uint8_t);

// v2 trailing pending-module block: marker | name_len (u32) | name (UTF-8) |
// bitness (u8) | 3 reserved | payload_len (u64) | payload bytes. Exactly one
// block on a v2 file; a v1 file never carries one.
inline constexpr std::uint8_t kPendingMarker[8] = {'P', 'E', 'N', 'D', 'M', 'O', 'D', '1'};
inline constexpr std::size_t kPendingNameLenOffset = sizeof kPendingMarker;
inline constexpr std::size_t kPendingNameOffset = kPendingNameLenOffset + sizeof(std::uint32_t);
// Bounds keep a corrupt file from driving huge allocations; a real DLL
// corpus sits far below them.
inline constexpr std::uint32_t kMaxPendingNameBytes = 260;
inline constexpr std::uint64_t kMaxPendingModuleBytes = 64ull * 1024 * 1024;

// Canonical x64 GPR order: rax rcx rdx rbx rsp rbp rsi rdi r8..r15.
enum class Gpr : std::uint8_t {
    kRax = 0,
    kRcx,
    kRdx,
    kRbx,
    kRsp,
    kRbp,
    kRsi,
    kRdi,
    kR8,
    kR9,
    kR10,
    kR11,
    kR12,
    kR13,
    kR14,
    kR15,
};

struct Header {
    std::uint32_t version{};
    std::uint8_t bitness{};
    std::uint32_t region_count{};

    friend constexpr bool operator==(const Header&, const Header&) = default;
};

// v1 carries the general register file only: GS_BASE is derived from the TEB
// address on the engine side, and float/debug registers join via a version
// bump when the format needs them.
struct Registers {
    std::array<std::uint64_t, kGprCount> gpr{};
    std::uint64_t rip{};
    std::uint64_t rflags{};

    friend constexpr bool operator==(const Registers&, const Registers&) = default;
};

struct Metadata {
    // 32 or 64 (kBitness32/kBitness64); v1 files carry it in the header
    // and the engine selects the guest mode from it.
    std::uint8_t bitness{kBitness64};
    std::uint64_t peb_address{};
    std::uint64_t teb_address{};
    // Base of the main image as loaded (the kernel may relocate it); the
    // engine side anchors module attribution and entry restoration on it.
    std::uint64_t image_base{};
    // Entry VA at snapshot time plus the bytes the capture path overwrote
    // with the spin patch (EB FE); the engine side restores them before
    // executing the real entry code.
    std::uint64_t entry_address{};
    std::array<std::uint8_t, kOriginalEntryBytes> original_entry_bytes{};

    friend constexpr bool operator==(const Metadata&, const Metadata&) = default;
};

// Raw PAGE_* / MEM_* values are stored as captured - facts, not
// interpretations; the engine side maps them to its own protection model.
enum ContentFlag : std::uint8_t {
    kContentAbsent = 0,
    kContentPresent = 1,
};

struct RegionHeader {
    std::uint64_t base_address{};
    std::uint64_t size{};
    std::uint32_t protection{};
    std::uint32_t type{};
    std::uint8_t content{kContentAbsent};

    friend constexpr bool operator==(const RegionHeader&, const RegionHeader&) = default;
};

struct Region {
    RegionHeader header{};
    // Empty when header.content == kContentAbsent; sized to header.size
    // otherwise.
    std::vector<std::uint8_t> content{};
};

// The DLL input route's payload: the sample DLL's raw bytes plus the arrival
// file name it was given. Carried in the v2 container's trailing block; the
// engine synthesizes the load inside the emulated world, so the sample never
// touches a real process.
struct PendingModule {
    std::string name{}; // arrival file name, UTF-8
    std::uint8_t bitness{kBitness64};
    std::vector<std::uint8_t> bytes{};

    friend constexpr bool operator==(const PendingModule&, const PendingModule&) = default;
};

enum class Error {
    kNone = 0,
    kIoFailure,          // stream write/read failure
    kBadMagic,           // not a sheller snapshot
    kUnsupportedVersion, // newer than (or foreign to) this reader
    kBitnessMismatch,    // this reader only consumes 64-bit snapshots
    kTruncated,          // stream ended inside a block or payload
    kBadContent,         // content flag is neither absent nor present
    kBadPending,         // pending-module block invalid or out of place
};

std::string_view error_message(Error error);

// Streaming writer: header, registers, metadata, then one write_region call
// per region. Nothing is buffered beyond a single region payload - real
// snapshots carry hundreds of megabytes of process memory.
class Writer {
  public:
    explicit Writer(std::ostream& out);

    std::expected<void, Error> write_header(const Header& header);
    std::expected<void, Error> write_registers(const Registers& registers);
    std::expected<void, Error> write_metadata(const Metadata& metadata);
    // content may be null when region.header.content == kContentAbsent.
    std::expected<void, Error> write_region(const RegionHeader& region,
                                            const std::uint8_t* content);
    // Patches the header's region_count with the number of write_region
    // calls, so the producer can stream without counting regions up front.
    std::expected<void, Error> finalize_region_count();
    // Appends the pending-module block. Only valid on a header written with
    // kVersionV2 (a v1 file must keep its exact legacy layout); call once,
    // after finalize_region_count.
    std::expected<void, Error> write_pending(const PendingModule& pending);

  private:
    std::expected<void, Error> write_bytes(const void* data, std::size_t size);

    std::ostream& out_;
    std::uint32_t region_count_{};
    std::uint32_t header_version_{kVersion}; // write_pending requires kVersionV2
};

class Reader {
  public:
    explicit Reader(std::istream& in);

    // Validates magic, version and bitness per the format contract. Accepts
    // both v1 and v2; anything else is kUnsupportedVersion (the v1 reader's
    // designed refusal channel for v2 files).
    std::expected<Header, Error> read_header();
    std::expected<Registers, Error> read_registers();
    std::expected<Metadata, Error> read_metadata();
    std::expected<Region, Error> read_region();
    // Reads the trailing pending-module block. v2 files must carry exactly
    // one: a second call, or the first call on a v1 file, is kBadPending; a
    // v2 file that ends before the block is kTruncated.
    std::expected<PendingModule, Error> read_pending();

  private:
    Error read_bytes(void* data, std::size_t size);

    std::istream& in_;
    std::uint8_t header_bitness{kBitness64}; // captured from read_header
    std::uint32_t header_version{kVersion};  // captured from read_header
    bool pending_read_{false};
};

} // namespace sheller::snapshot

#endif // SHELLER_SNAPSHOT_H
