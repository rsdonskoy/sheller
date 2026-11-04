// Shellcode blob wrapping: a bare blob is embedded into a minimal wrapper PE - one
// code section, entry pointing at the section start - so shellcode rides the
// standard capture route. The wrapper is pure byte construction: no runtime
// linking, no interpretation of the blob, sizes bounded. The generated PE
// must load in a real Windows process (the capture path spawns it), which
// the e2e exercises end to end.

#ifndef SHELLER_CAPTURE_WRAPPER_H
#define SHELLER_CAPTURE_WRAPPER_H

#include <sheller/capture.h>

#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <vector>

namespace sheller::capture {

enum class WrapArch { kX64, kX86 };

enum class WrapError {
    kNone = 0,
    kEmptyBlob,
    kTooLarge,
    // The temp directory itself could not be resolved. Its own enumerator, not
    // a folded "capture failed": the wrapper's other failures say the blob is
    // unusable, this one says the host has nowhere to put it.
    kTempDirUnavailable,
};

std::string_view wrap_error_message(WrapError error);

// Which of the wrapper's failures is whose fault, expressed in the status the
// capture route reports. An unusable blob is an input problem - the sample is not a
// runnable x64 image, which is what kNotX64Pe says. A host with nowhere to put the
// wrapper PE is the capture route failing, and reporting that as "not a PE" would
// tell the caller to go fix a file that was never the problem. kNone has no status
// of its own (a caller checks the expected value first); it maps to kNotX64Pe so the
// table has no unhandled enumerator rather than because "ok" is a failure.
Status wrap_status(WrapError error);

// The wrapper takes a fresh process, so the default image base is reliably
// free; ASLR is left off (no relocation directory) for a deterministic load.
// Blob cap: msfvenom-class payloads sit far below it; the bound keeps the
// generated image two-dimensional-simple.
inline constexpr std::size_t kMaxBlobBytes = 1024 * 1024;

// A leading MZ marks a PE input; anything else is treated as a bare blob.
bool looks_like_pe(std::span<const std::uint8_t> bytes);

// Builds the wrapper PE: headers + one RX section whose first byte is the
// entry and whose content is the blob verbatim.
std::expected<std::vector<std::uint8_t>, WrapError> wrap_blob(WrapArch arch,
                                                              std::span<const std::uint8_t> blob);

// --- load-stub runner (DLL-input route) ---
//
// A deterministic byte-construction function in the wrapper family: the
// entry stub calls LoadLibraryW on the sample's arrival file name, then
// exits through ExitProcess with a fixed code - that exit is the DLL
// route's designed finish line, not a fallback. The import table is
// variable-length: the two kernel32 base entries plus every verified
// system dependency of the pending sample (see the admission step in the
// capture path), so the real loader initializes all of them into the
// captured world. Same bitness/arrival name/dependency plan must produce
// byte-identical output; no prebuilt asset, no runtime compilation.

struct RunnerImport {
    std::string module;      // dependency DLL name as verified (ASCII, e.g. "USER32.dll")
    std::string symbol;      // by-name import when non-empty (exact referenced name)
    std::uint16_t ordinal{}; // by-ordinal import when symbol is empty

    friend constexpr bool operator==(const RunnerImport&, const RunnerImport&) = default;
};

struct RunnerPlan {
    WrapArch arch{WrapArch::kX64};
    std::string arrival_name;            // sample file name, UTF-8 (the stub's path string)
    std::vector<RunnerImport> imports{}; // base pair first, then verified system deps

    // The differential admission tests compare the two routes' plans
    // field-by-field; the member order here is the plan's wire shape.
    friend constexpr bool operator==(const RunnerPlan&, const RunnerPlan&) = default;
};

enum class RunnerError {
    kNone = 0,
    kBadArrivalName,  // empty, path separators, or not representable
    kReservedArrival, // collides with a planned import's module name
    kNoImports,       // plan lacks the base LoadLibraryW/ExitProcess pair
    kTooManyImports,  // plan exceeds the bounded import capacity
    kBadSymbol,       // by-name and by-ordinal both empty, or name too long
};

std::string_view runner_error_message(RunnerError error);

inline constexpr std::size_t kMaxRunnerImports = 96;

std::expected<std::vector<std::uint8_t>, RunnerError> build_runner(const RunnerPlan& plan);

} // namespace sheller::capture

#endif // SHELLER_CAPTURE_WRAPPER_H
