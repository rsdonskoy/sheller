// Boundary derivation: the pure byte-level
// function from a user-supplied system-module directory file to the guest
// image the directory mode maps for a boundary-pair module (ntdll, win32u).
// The real file is the base: the derived image is the source's own folded
// image (SizeOfImage and the section list are the source's), taken through
// the same load pipeline as every real module - build, real relocation
// table, then the resident IAT/delayed-import binding that happens after
// the whole set is known. The boundary dispositions (syscall numbers, the
// four-kind classification, the counting whitelist, compat answers) ride
// the address-level runtime table this function returns - the EAT keeps
// its source addresses and the verified syscall stubs keep their source
// bytes, so nothing in the image depends on a synthesized stub. Image
// writes are limited to the explicit whitelist: the reserved DOS e_res2
// marker slot (verified zero in the source), manifest-declared data slots
// whose mapped bytes are free (all zero), and manifest-defined
// compat/intercept stub bodies at their own export addresses. The
// synthetic-era fixed weld slots are retired on this route - the derive
// never lays out or overwrites image content outside the whitelist.
// Syscall service exports keep their `mov eax, <num>` shape only after the
// source body passes stub-shape validation - the name prefix never
// decides. Same input bytes and base in, byte-identical image out. The
// classification input is the versioned boundary manifest's rule set; an
// export it does not cover is a named rejection, never a guessed stub. No
// unicorn, no host state - fully unit-testable.

#ifndef SHELLER_LOADER_BOUNDARY_DERIVE_H
#define SHELLER_LOADER_BOUNDARY_DERIVE_H

#include "loader.h"

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sheller::loader {

// The boundary export dispositions (the loader environment's classification):
// syscall stubs answer through the engine's syscall layer, intercepted
// entries are replaced wholesale by built-in implementations, traps
// terminate the run with a named diagnostic, compat stubs return the
// manifest's per-function answer, data exports expose known-layout slots.
// kForwarder and kEmpty are disposition-only kinds: a forwarded export has
// no local body and is classified along its chain at bind time; an empty
// EAT entry has nothing to classify. Neither can appear in a manifest rule.
enum class BoundaryKind : std::uint8_t {
    kSyscallStub,
    kIntercept,
    kTrap,
    kCompat,
    kData,
    kForwarder,
    kEmpty,
};

// One manifest rule: the classification for a single export of one boundary
// module. Named exports match by exact source spelling (the manifest is
// generated from the same image); ordinal-only rules cover unnamed exports.
struct BoundaryRule {
    std::string name;        // exact export name; empty: match by ordinal
    std::uint32_t ordinal{}; // source ordinal (EAT index + export base)
    BoundaryKind kind{};
    // kCompat: the value eax/rax carries on return (the manifest defines the
    // failure return per function; no family-wide default exists).
    std::uint64_t compat_return{};
    // kCompat: the manifest's OUT-parameter recipes (';'-separated spelling;
    // the runtime compat handler consumes them - the derived body stays
    // return-only until that work lands).
    std::string compat_out;
    // kData: the known layout. data_bytes must hold exactly data_size bytes;
    // data_align must be a power of two.
    std::uint32_t data_size{};
    std::uint32_t data_align{};
    std::vector<std::uint8_t> data_bytes;
};

struct DerivedBoundaryExport {
    std::string name;        // source spelling; empty for an unnamed export
    std::uint32_t ordinal{}; // source ordinal (EAT index + export base)
    BoundaryKind kind{};
    bool forwarded{};               // forwarder relation preserved from the source
    std::string forwarder_target;   // the preserved "dll.func" spelling
    std::uint64_t body_rva{};       // the source EAT value: the export's own
                                    // address (a forwarder keeps the string's
                                    // RVA inside the export directory); 0 for
                                    // EAT holes
    std::uint32_t syscall_number{}; // kSyscallStub only: number validated in the source body
};

enum class BoundaryDeriveError {
    kNone = 0,
    kBadSource,          // the directory file is not a walkable PE, cannot
                         // take its mapped base, or carries a dirty marker slot
    kUnsupportedMachine, // the derivation covers AMD64 boundary images only
    kNoExportDirectory,  // a boundary-pair member must export
    kUnknownExport,      // export outside the manifest rule set
    kManifestMismatch,   // rule and source disagree (shape, forwarder, hole)
    kBadRule,            // rule payload invalid for its kind, or duplicated
};

std::string_view boundary_derive_error_message(BoundaryDeriveError error);

// Named rejection: the detail text names the module and the export (or the
// mismatched field) so construction failures are diagnostic, not silent.
struct BoundaryDeriveFailure {
    BoundaryDeriveError code{};
    std::string detail;
};

struct DerivedBoundary {
    std::vector<std::uint8_t> image; // the source's folded SizeOfImage bytes:
                                     // built, relocated to `base`, whitelist
                                     // slots written - ready to map
    // Every source export in source ordinal order, names in source name
    // order within an ordinal (aliases appear once per name).
    std::vector<DerivedBoundaryExport> exports;
};

// Derives the guest image for one boundary-pair module from its directory
// file bytes and the base the module maps at. The reserved DOS e_res2
// marker slot stays zero here; the engine's directory-mode marker writes
// it after the load pipeline.
std::expected<DerivedBoundary, BoundaryDeriveFailure>
derive_boundary_image(std::span<const std::uint8_t> file, std::string_view module_name,
                      const std::vector<BoundaryRule>& rules, std::uint64_t base);

// Stub-shape validation over host-side bytes: the x64 canonical ntdll stub
// prefix `4C 8B D1 B8` (mov r10, rcx; mov eax, imm32) with the number at
// +4. The mirror of the engine's syscall_number_map reader - a name prefix
// is not consulted. nullopt when the body is not a syscall stub.
std::optional<std::uint32_t> syscall_stub_number_from_bytes(std::span<const std::uint8_t> body);

// The DOS-header mode-marker slot: the derived image keeps
// e_res2 at offset 0x28, 20 bytes, zero - the slot the directory-mode
// marker is written into.
inline constexpr std::uint32_t kBoundaryMarkerOffset = 0x28;
inline constexpr std::uint32_t kBoundaryMarkerSize = 20;

} // namespace sheller::loader

#endif // SHELLER_LOADER_BOUNDARY_DERIVE_H
