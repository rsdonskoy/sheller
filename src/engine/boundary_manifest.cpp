#include "boundary_manifest.h"

#include <algorithm>
#include <charconv>
#include <format>
#include <utility>

namespace sheller::engine {
namespace {

std::string fold(std::string_view name)
{
    std::string out;
    for (const char c : name) {
        out.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c));
    }
    return out;
}

// A module+arch pair may carry several registered builds (the fixture build
// and real Windows builds), each a separate SeedModule entry with its own
// image list and export rows. Selection is by whole-file hash across all
// entries — never by order.
const boundary_seed::SeedModule* find_seed_build(const std::string_view module,
                                                 const std::string_view arch,
                                                 const std::uint64_t xxhash64)
{
    for (const auto& candidate : boundary_seed::kModules) {
        if (std::string_view(candidate.module) != module ||
            std::string_view(candidate.arch) != arch) {
            continue;
        }
        for (std::size_t i = 0; i < candidate.image_count; ++i) {
            if (candidate.images[i].xxhash64 == xxhash64) {
                return &candidate;
            }
        }
    }
    return nullptr;
}

std::vector<std::uint8_t> decode_hex(const std::string_view hex)
{
    std::vector<std::uint8_t> bytes;
    if (hex.size() % 2 != 0) {
        return bytes;
    }
    bytes.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        std::uint8_t value = 0;
        const auto first = std::from_chars(hex.data() + i, hex.data() + i + 2, value, 16);
        if (first.ec != std::errc{} || first.ptr != hex.data() + i + 2) {
            return {};
        }
        bytes.push_back(value);
    }
    return bytes;
}

std::vector<loader::BoundaryRule> seed_rows_to_rules(const boundary_seed::SeedModule& seed)
{
    std::vector<loader::BoundaryRule> rules;
    rules.reserve(seed.export_count);
    for (std::size_t i = 0; i < seed.export_count; ++i) {
        const auto& row = seed.exports[i];
        loader::BoundaryRule rule;
        rule.name = row.name;
        rule.ordinal = row.ordinal;
        rule.kind = static_cast<loader::BoundaryKind>(row.kind);
        rule.compat_return = row.compat_return;
        rule.compat_out = row.out;
        rule.data_size = row.data_size;
        rule.data_align = row.data_align;
        if (rule.kind == loader::BoundaryKind::kData) {
            rule.data_bytes = decode_hex(row.data_hex);
        }
        rules.push_back(std::move(rule));
    }
    return rules;
}

} // namespace

const char* boundary_manifest_error_message(const BoundaryManifestError error)
{
    switch (error) {
    case BoundaryManifestError::kNone:
        return "ok";
    case BoundaryManifestError::kUnknownModule:
        return "no boundary manifest rows exist for this module and architecture";
    case BoundaryManifestError::kHashMismatch:
        return "image content hash is not in the boundary manifest's applicability list";
    case BoundaryManifestError::kBadSeedPayload:
        return "a committed boundary seed row failed its own decoding";
    }
    return "unknown boundary manifest error";
}

const BoundaryManifest& BoundaryManifest::committed()
{
    static const BoundaryManifest manifest{};
    return manifest;
}

bool BoundaryManifest::covers(const std::string_view module, const std::string_view arch) const
{
    for (const auto& candidate : boundary_seed::kModules) {
        if (std::string_view(candidate.module) == module &&
            std::string_view(candidate.arch) == arch) {
            return true;
        }
    }
    return false;
}

std::expected<std::vector<loader::BoundaryRule>, BoundaryManifestError>
BoundaryManifest::rules_for(const std::string_view module, const std::string_view arch,
                            const std::uint64_t xxhash64) const
{
    const auto* seed = find_seed_build(module, arch, xxhash64);
    if (seed == nullptr) {
        // distinguish: the module has registered builds but this image's hash
        // is not among them
        if (covers(module, arch)) {
            return std::unexpected(BoundaryManifestError::kHashMismatch);
        }
        return std::unexpected(BoundaryManifestError::kUnknownModule);
    }
    auto rules = seed_rows_to_rules(*seed);
    for (const auto& rule : rules) {
        if (rule.kind == loader::BoundaryKind::kData && rule.data_bytes.size() != rule.data_size) {
            return std::unexpected(BoundaryManifestError::kBadSeedPayload);
        }
    }
    return rules;
}

BoundaryChainDisposition classify_export_chain(
    const std::vector<loader::LoadedModule>& modules,
    const std::map<std::string, std::vector<loader::BoundaryRule>>& boundary_rules,
    const std::string_view module_name, const std::string_view function_name)
{
    BoundaryChainDisposition out;
    const auto resolved = loader::resolve_export(modules, module_name, function_name);
    if (!resolved.ok || resolved.module == nullptr) {
        return out; // dangling chain: nothing to classify
    }
    out.resolved = true;
    out.final_name = resolved.final_name;
    const auto endpoint_module = fold(std::string_view(resolved.module->name.data()));
    const auto rules = boundary_rules.find(endpoint_module);
    if (rules == boundary_rules.end()) {
        return out; // the chain exits into real-byte code: no boundary disposition
    }
    out.boundary = true;
    const auto rule = std::find_if(rules->second.begin(), rules->second.end(),
                                   [&name = out.final_name](const loader::BoundaryRule& candidate) {
                                       return candidate.name == name;
                                   });
    if (rule == rules->second.end()) {
        // a manifested module always covers every export (the derive enforces
        // it); reaching here means the caller passed rules of another image
        out.boundary = false;
        return out;
    }
    out.kind = rule->kind;
    if (out.kind == loader::BoundaryKind::kSyscallStub) {
        // the derived stub body carries the canonical prefix; read the
        // number where the endpoint actually lives
        const auto body_rva = static_cast<std::size_t>(resolved.va - resolved.module->base);
        const auto& image = resolved.module->image;
        if (body_rva < image.size()) {
            const auto body = std::span<const std::uint8_t>(image).subspan(
                body_rva, std::min<std::size_t>(16, image.size() - body_rva));
            if (const auto number = loader::syscall_stub_number_from_bytes(body);
                number.has_value()) {
                out.syscall_number = *number;
            }
        }
    }
    return out;
}

} // namespace sheller::engine
