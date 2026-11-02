// Boundary derivation (change real-dll-module-dir): the pure byte-level
// function from a user-supplied system-module directory file to the stub
// image the directory mode maps for a boundary-pair module (ntdll, win32u).
// Export names, ordinals, aliases and forwarder relations survive verbatim;
// every EAT address is rebuilt against the derived image (never a copied
// RVA into the source). Syscall service exports keep their `mov eax, <num>`
// shape only after the source body passes stub-shape validation - the name
// prefix never decides. Bodies for manifest-classified trap exports are
// ud2; compat exports carry the manifest's deterministic return; data
// exports land in known-layout slots. Same input bytes in, byte-identical
// image out. The classification input is the versioned boundary manifest's
// rule set; an export it does not cover is a named rejection, never a
// guessed stub. No unicorn, no host state - fully unit-testable.

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

// The boundary export dispositions (loader-env「边界导出分类与不支持陷阱」):
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
    std::uint64_t body_rva{};       // the derived EAT value: body/slot RVA, or
                                    // the preserved forwarder-string RVA inside
                                    // this image; 0 for EAT holes
    std::uint32_t syscall_number{}; // kSyscallStub only: number validated in the source body
};

enum class BoundaryDeriveError {
    kNone = 0,
    kBadSource,          // the directory file is not a walkable PE
    kUnsupportedMachine, // phase 1 derives AMD64 boundary images only
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
    std::vector<std::uint8_t> image; // full SizeOfImage bytes (a parse_pe-able PE)
    // Every source export in source ordinal order, names in source name
    // order within an ordinal (aliases appear once per name).
    std::vector<DerivedBoundaryExport> exports;
    std::uint64_t weld_data_rva{}; // engine weld-slot section RVA; ntdll only, else 0
};

// Derives the stub image for one boundary-pair module from its directory
// file bytes. The weld-slot layout (ntdll .data at the engine's fixed RVA)
// and the reserved DOS e_res2 marker slot (design D6) are part of the
// generated-image contract.
std::expected<DerivedBoundary, BoundaryDeriveFailure>
derive_boundary_image(std::span<const std::uint8_t> file, std::string_view module_name,
                      const std::vector<BoundaryRule>& rules);

// Stub-shape validation over host-side bytes: the x64 canonical ntdll stub
// prefix `4C 8B D1 B8` (mov r10, rcx; mov eax, imm32) with the number at
// +4. The mirror of the engine's syscall_number_map reader - a name prefix
// is not consulted. nullopt when the body is not a syscall stub.
std::optional<std::uint32_t> syscall_stub_number_from_bytes(std::span<const std::uint8_t> body);

// The DOS-header mode-marker slot (design D6): the derived image keeps
// e_res2 at offset 0x28, 20 bytes, zero - the slot the directory-mode
// marker is written into.
inline constexpr std::uint32_t kBoundaryMarkerOffset = 0x28;
inline constexpr std::uint32_t kBoundaryMarkerSize = 20;

// The engine weld-slot contract the derived ntdll honors (parity with
// tools/gen_synth_modules.py): .text spans 0x40000 and the fixed .data
// section sits at 0x41000.
inline constexpr std::uint32_t kBoundaryNtdllTextSpan = 0x40000;
inline constexpr std::uint32_t kBoundaryNtdllWeldDataRva = 0x41000;

} // namespace sheller::loader

#endif // SHELLER_LOADER_BOUNDARY_DERIVE_H
