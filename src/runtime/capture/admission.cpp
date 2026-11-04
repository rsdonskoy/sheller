// The shared runner-admission algorithm. See admission.h for the contract.

#include "admission.h"

#include <algorithm>
#include <cctype>
#include <set>
#include <utility>

namespace sheller::capture {
namespace {

// The arrival name becomes the runner's path string and the emulated Ldr
// entry's BaseDllName (bounded to 64 chars there) - enforce one bound at the
// source. Non-ASCII is rejected honestly rather than through a lossy widening
// the engine cannot round-trip.
bool valid_arrival_name(const std::string& arrival_name)
{
    return !arrival_name.empty() && arrival_name.size() <= 64 &&
           std::all_of(arrival_name.begin(), arrival_name.end(),
                       [](const unsigned char c) { return c >= 0x20 && c < 0x7F && c != '\\'; });
}

bool path_shaped(const std::string& module)
{
    return module.empty() || module.find('\\') != std::string::npos ||
           module.find('/') != std::string::npos || module.find(':') != std::string::npos ||
           module.find("..") != std::string::npos;
}

} // namespace

bool ModuleSource::is_base_module(const std::string_view folded_name) const
{
    return folded_name == "kernel32.dll";
}

std::expected<RunnerPlan, std::string> admit_sample(const std::vector<std::uint8_t>& sample_bytes,
                                                    const std::string& arrival_name,
                                                    ModuleSource& source)
{
    if (!valid_arrival_name(arrival_name)) {
        return std::unexpected("sample file name: empty, non-ASCII, or over 64 characters");
    }
    std::vector<PeImportThunk> imports;
    if (const auto error = parse_imports(sample_bytes.data(), sample_bytes.size(), imports);
        error != PeError::kNone) {
        return std::unexpected(std::string(pe_error_message(error)));
    }

    RunnerPlan plan;
    plan.arch = WrapArch::kX64;
    plan.arrival_name = arrival_name;
    plan.imports.push_back({"kernel32.dll", "LoadLibraryW", 0});
    plan.imports.push_back({"kernel32.dll", "ExitProcess", 0});

    if (auto prepared = source.prepare(); !prepared.has_value()) {
        return std::unexpected(prepared.error());
    }

    // BFS over the dependency closure. Level 0 entries (the sample's direct
    // imports) each contribute one runner import; deeper levels are
    // verification-only when the source walks the full closure - the loader
    // resolves the chain through the same search when it initializes the
    // runner's imports.
    struct QueueEntry {
        std::string module;
        bool direct;
    };
    std::vector<QueueEntry> queue;
    for (const auto& import : imports) {
        if (std::none_of(queue.begin(), queue.end(), [&](const QueueEntry& entry) {
                return fold_module_name(entry.module) == fold_module_name(import.module);
            })) {
            queue.push_back({import.module, true});
        }
    }

    const std::string arrival_key = fold_module_name(arrival_name);
    std::set<std::string> processed{fold_module_name("kernel32.dll")}; // base pair covers it
    const auto pending = [&](const std::string& module_key) {
        return std::any_of(queue.begin(), queue.end(), [&](const QueueEntry& entry) {
            return fold_module_name(entry.module) == module_key;
        });
    };

    std::size_t cursor = 0;
    while (cursor < queue.size()) {
        const QueueEntry entry = queue[cursor++];
        const std::string key = fold_module_name(entry.module);
        if (key == arrival_key) {
            return std::unexpected(
                source.dependency_error(entry.module, AdmissionProblem::kCollisionWithSample));
        }
        if (processed.count(key) != 0) {
            continue;
        }
        processed.insert(key);
        if (path_shaped(entry.module)) {
            return std::unexpected(
                source.dependency_error(entry.module, AdmissionProblem::kPathShapedName));
        }

        std::string source_error;
        ModuleView* module = source.acquire(entry.module, key, source_error);
        if (module == nullptr) {
            return std::unexpected(std::move(source_error));
        }

        // The full-closure policy: the module's own imports join the queue for
        // verification only (no runner import, no export selection below).
        if (source.walk_full_closure()) {
            for (const auto& imported : module->imports()) {
                const std::string dependency_key = fold_module_name(imported.module);
                if (!source.is_base_module(dependency_key) && dependency_key != arrival_key &&
                    processed.count(dependency_key) == 0 && !pending(dependency_key)) {
                    queue.push_back({imported.module, false});
                }
            }
        }
        if (!entry.direct) {
            continue;
        }

        // Pick the first referenced symbol that resolves in this module, in
        // the sample's own import order (one corpus yields one plan
        // everywhere). A forwarder adds its target DLL to the closure.
        bool selected = false;
        for (const auto& import : imports) {
            if (fold_module_name(import.module) != key) {
                continue;
            }
            const auto resolved = module->resolves(import.name, import.ordinal);
            if (!resolved.has_value()) {
                return std::unexpected(resolved.error());
            }
            const auto& hit = *resolved;
            if (!hit.exported) {
                continue;
            }
            if (hit.forwarder) {
                const std::string target_key = fold_module_name(hit.forward_to);
                if (!source.is_base_module(target_key) && target_key != arrival_key &&
                    processed.count(target_key) == 0 && !pending(target_key)) {
                    queue.push_back({hit.forward_to, false});
                }
            }
            plan.imports.push_back({entry.module, import.name, import.ordinal});
            if (plan.imports.size() > kMaxRunnerImports) {
                return std::unexpected("dependency closure exceeds the runner capacity");
            }
            selected = true;
            break;
        }
        if (!selected) {
            // Without an importable symbol the runner cannot preload this
            // dependency - out of contract, by name.
            return std::unexpected(
                source.dependency_error(entry.module, AdmissionProblem::kNoImportableExport));
        }
    }

    return plan;
}

} // namespace sheller::capture
