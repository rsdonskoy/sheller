// The boundary description manifest's runtime face (design D2, change
// real-dll-module-dir): the committed seed table is the only manifest the
// engine sees - applicability is a named (module, arch, image-xxhash64)
// verdict, seed rows map one-to-one onto loader::BoundaryRule vectors, and
// forwarded boundary exports classify along their resolution chain to the
// target's disposition. Pure data + queries: no unicorn, no filesystem.

#ifndef SHELLER_ENGINE_BOUNDARY_MANIFEST_H
#define SHELLER_ENGINE_BOUNDARY_MANIFEST_H

#include "../loader/boundary_derive.h"
#include "../loader/imports.h"
#include "boundary_seed.inc"

#include <cstdint>
#include <expected>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace sheller::engine {

// The seed's kind constants and the loader's disposition enum are two
// spellings of one classification - a drift would misclassify every seed
// row silently.
static_assert(static_cast<std::uint8_t>(loader::BoundaryKind::kSyscallStub) ==
                  boundary_seed::kSeedSyscallStub,
              "seed kind constants must mirror loader::BoundaryKind");
static_assert(static_cast<std::uint8_t>(loader::BoundaryKind::kIntercept) ==
                  boundary_seed::kSeedIntercept,
              "seed kind constants must mirror loader::BoundaryKind");
static_assert(static_cast<std::uint8_t>(loader::BoundaryKind::kTrap) == boundary_seed::kSeedTrap,
              "seed kind constants must mirror loader::BoundaryKind");
static_assert(static_cast<std::uint8_t>(loader::BoundaryKind::kCompat) ==
                  boundary_seed::kSeedCompat,
              "seed kind constants must mirror loader::BoundaryKind");
static_assert(static_cast<std::uint8_t>(loader::BoundaryKind::kData) == boundary_seed::kSeedData,
              "seed kind constants must mirror loader::BoundaryKind");

enum class BoundaryManifestError {
    kNone = 0,
    kUnknownModule,  // no seed rows exist for this (module, arch) pair
    kHashMismatch,   // module manifested, this image's content hash is not
    kBadSeedPayload, // a committed row fails its own decoding (build defect)
};

const char* boundary_manifest_error_message(BoundaryManifestError error);

class BoundaryManifest {
  public:
    // The committed seed as the manifest view: the JSON sources never reach
    // the runtime, so every consumer reads one build-pinned table.
    static const BoundaryManifest& committed();

    // Applicability verdict + seed-row conversion. The rules apply only to
    // the exact (module, arch, whole-file xxhash64); anything else is a
    // named rejection - never a guess across a version drift. The data
    // payload decodes to the rule's exact initial bytes.
    std::expected<std::vector<loader::BoundaryRule>, BoundaryManifestError>
    rules_for(std::string_view module, std::string_view arch, std::uint64_t xxhash64) const;

    // Whether the (module, arch) pair has seed rows at all (the applicability
    // pre-check the directory-mode loader runs before hashing).
    bool covers(std::string_view module, std::string_view arch) const;
};

// The chain-walked classification of one boundary export (spec「转发沿链
// 分类」): a forwarded boundary export inherits the chain target's
// disposition, and a chain that exits the manifested boundary set lands in
// real-byte code - executed as-is, no boundary disposition, no guessing.
struct BoundaryChainDisposition {
    bool resolved{}; // false: the chain dangles (unresolvable target)
    bool boundary{}; // true: the endpoint lives in a manifested boundary module
    loader::BoundaryKind kind{};
    std::uint32_t syscall_number{}; // endpoint stub number (kSyscallStub)
    std::string final_name;         // the chain endpoint's export name
};

// boundary_rules: folded module name -> the applicability-checked rules of
// each derived boundary module in this world (the loader route builds it
// once per construction). Lookup keys and module names fold the same way.
BoundaryChainDisposition classify_export_chain(
    const std::vector<loader::LoadedModule>& modules,
    const std::map<std::string, std::vector<loader::BoundaryRule>>& boundary_rules,
    std::string_view module_name, std::string_view function_name);

} // namespace sheller::engine

#endif // SHELLER_ENGINE_BOUNDARY_MANIFEST_H
