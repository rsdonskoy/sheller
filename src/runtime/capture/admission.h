// Runner admission: the one algorithm behind the Windows capture route and the
// synthetic construction route.
//
// A runner plan is built by walking a DLL sample's direct imports in order:
// verify each module against a trusted module source, pick the first reference
// that the module actually exports, and emit one runner import per verified
// direct dependency. The Windows route's trusted world is the operating
// system, so it also walks each module's own imports (verification only); the
// synthetic route's trusted world is the generated module directory, so direct
// imports are the whole closure. That closure depth is a source policy, not a
// second algorithm.
//
// The admission code never owns a module: ModuleSource::acquire returns a
// borrowed view good for the current dependency, and the source decides how to
// obtain it (LoadLibraryExW probe, synthetic directory parse, ...). Error
// wording stays with the source: the two routes' messages are deliberately
// different, and unifying them would flip CLI/golden assertions.

#ifndef SHELLER_CAPTURE_ADMISSION_H
#define SHELLER_CAPTURE_ADMISSION_H

#include "pe_headers.h"
#include "wrapper.h"

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sheller::capture {

// Windows module-name matching folds ASCII only; both routes and the runner
// builder share this one rule.
std::string fold_module_name(std::string_view name);
bool fold_module_name_equals(std::string_view a, std::string_view b);

// One verified module, borrowed for the current dependency. A source may keep
// the view in a container it grows later, so the skeleton never holds it past
// the loop iteration that acquired it.
struct ModuleView {
    std::string_view name; // original spelling, for diagnostics only

    struct Hit {
        bool exported{};
        bool forwarder{};       // the export forwards to another module
        std::string forward_to; // target DLL spelling when forwarder
    };

    virtual ~ModuleView() = default;

    // Resolves one referenced symbol (by name when `symbol` is non-empty, by
    // ordinal otherwise). An unexpected error aborts admission with that text
    // (a chain endpoint could not be loaded); an unexported symbol is a miss.
    virtual std::expected<Hit, std::string> resolves(std::string_view symbol,
                                                     std::uint16_t ordinal) = 0;

    // The module's own imports, for the full-closure policy. Sources that do
    // not expose them (or could not parse them) return an empty span.
    virtual std::span<const PeImportThunk> imports() const
    {
        return {};
    }
};

// Which dependency-level refusal an admission pass is reporting.
enum class AdmissionProblem {
    kCollisionWithSample,
    kPathShapedName,
    kNoImportableExport,
};

// The injected module source. The skeleton owns the algorithm; a source owns
// module acquisition, its trusted world's closure depth, and its own wording.
class ModuleSource {
  public:
    virtual ~ModuleSource() = default;

    // Source-specific setup that must succeed before the first dependency is
    // fetched (the synthetic world's kernel32 host, its API-set map).
    virtual std::expected<void, std::string> prepare()
    {
        return {};
    }

    // Borrows the module `spelled` (original spelling) / `folded` (its lookup
    // key). Returns nullptr and sets `error` when the module cannot be
    // verified; the text is the rejection the caller reports.
    virtual ModuleView* acquire(std::string_view spelled, std::string_view folded,
                                std::string& error) = 0;

    // Whether transitively imported modules are pulled in for verification
    // only (the Windows route) or direct imports are the whole closure.
    virtual bool walk_full_closure() const
    {
        return false;
    }

    // Modules the plan's base pair already covers.
    virtual bool is_base_module(std::string_view folded_name) const;

    // Wording for the dependency-level refusals.
    virtual std::string dependency_error(std::string_view spelled,
                                         AdmissionProblem problem) const = 0;
};

// Builds the runner plan for one DLL sample against `source`.
std::expected<RunnerPlan, std::string> admit_sample(const std::vector<std::uint8_t>& sample_bytes,
                                                    const std::string& arrival_name,
                                                    ModuleSource& source);

} // namespace sheller::capture

#endif // SHELLER_CAPTURE_ADMISSION_H
