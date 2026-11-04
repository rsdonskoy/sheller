// Hand-built guest environment path: serializes the loader-constructed guest
// (loader, PEB/TEB/Ldr, KUSER_SHARED_DATA, sample image and synthetic system
// module pages) into a v1 snapshot container. The replay route executes this
// container, and the unpack pipeline sources its clean pages from the same
// bytes - the world described and the world executed are one artifact.
//
// DLL-input branch: a DLL sample never becomes the
// sample image. The deterministic load-stub runner (the wrapper family's
// build_runner) is the image the world is constructed from, and the sample
// bytes plus arrival name ride the container's v2 pending block - the same
// shape the Windows capture route photographs. Admission reads no host
// state: the synthetic module directory is the only trusted system world,
// every direct dependency must resolve to a frozen module there and every
// referenced symbol must verify against its export table, or the rejection
// names the dependency.

#include "../../engine/craft.h"
#include "../../engine/craft_admission.h"
#include "../../engine/loader_route.h"

#include "../../loader/imports.h"
#include "../capture/admission.h"
#include "../capture/pe_headers.h"
#include "../capture/wrapper.h"

#include <sheller/snapshot.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <xxhash.h>

namespace sheller::engine {
namespace {

bool all_zero(const std::vector<std::uint8_t>& bytes)
{
    return std::all_of(bytes.begin(), bytes.end(),
                       [](const std::uint8_t byte) { return byte == 0; });
}

std::string folded(std::string_view name)
{
    std::string out;
    out.reserve(name.size());
    for (const char c : name) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

// Export-directory facts of a MAPPED image (RVAs index the buffer directly -
// build_image already folded the section layout). Just enough for the
// ordinal verification: the name index lives in loader::index_exports.
struct ExportDirFacts {
    std::uint32_t rva{};
    std::uint32_t size{};
    std::uint32_t ordinal_base{};
    std::uint32_t function_count{};
    bool valid{};
};

std::uint32_t read_le32(const std::vector<std::uint8_t>& image, const std::size_t offset)
{
    std::uint32_t value = 0;
    if (offset + sizeof value > image.size()) {
        return 0;
    }
    std::memcpy(&value, image.data() + offset, sizeof value);
    return value;
}

ExportDirFacts export_dir_facts(const std::vector<std::uint8_t>& image)
{
    ExportDirFacts facts;
    const auto pe = read_le32(image, 0x3C);
    if (pe == 0 || pe + 4 + 20 + 128 > image.size() || read_le32(image, pe) != 0x00004550) {
        return facts;
    }
    const std::size_t dirs =
        read_le32(image, pe + 4 + 20) == 0x010B ? 96u : 112u; // optional header magic
    const auto dir_base = pe + 4 + 20 + dirs;
    facts.rva = read_le32(image, dir_base);
    facts.size = read_le32(image, dir_base + 4);
    if (facts.rva == 0 || facts.rva + 40 > image.size()) {
        return facts;
    }
    facts.ordinal_base = read_le32(image, facts.rva + 0x10);
    facts.function_count = read_le32(image, facts.rva + 0x14);
    facts.valid = facts.function_count > 0;
    return facts;
}

// Whether the ordinal sits in the module's exported function range and its
// slot carries a callable (non-forwarder) entry. The synthetic module set
// carries no forwarders by construction - a forwarder slot cannot be
// verified here and fails the symbol, mirroring the named-failure contract.
bool ordinal_exported(const loader::LoadedModule& module, const std::uint16_t ordinal)
{
    const auto facts = export_dir_facts(module.image);
    if (!facts.valid || ordinal < facts.ordinal_base ||
        static_cast<std::uint32_t>(ordinal - facts.ordinal_base) >= facts.function_count) {
        return false;
    }
    const auto functions_va = read_le32(module.image, facts.rva + 0x1C);
    const auto function_rva =
        read_le32(module.image, functions_va + 4ULL * (ordinal - facts.ordinal_base));
    if (function_rva == 0) {
        return false;
    }
    return !(function_rva >= facts.rva && function_rva < facts.rva + facts.size);
}

class SyntheticModuleSource;

// One synthetic-world module, borrowed for the current dependency. The view
// stores the module's index, never a pointer into the source's module store:
// directory-mode forwarder resolution may append modules while the view is in
// use, and a vector element address is not stable across that growth.
class SyntheticModuleView final : public capture::ModuleView {
  public:
    SyntheticModuleView(SyntheticModuleSource* source, std::string spelled, std::string key,
                        const std::size_t index)
        : source_(source), spelled_(std::move(spelled)), key_(std::move(key)), index_(index)
    {
        name = spelled_;
    }

    std::expected<capture::ModuleView::Hit, std::string> resolves(std::string_view symbol,
                                                                  std::uint16_t ordinal) override;

  private:
    SyntheticModuleSource* source_;
    std::string spelled_;
    std::string key_;
    std::size_t index_;
};

// The synthetic route's module source: the frozen module directory is the
// trusted world. Directory mode reads real DLL bytes and walks forwarder
// chains through the API Set map; the generated-module mode maps an
// api-set-prefix host to <module>.x64.dll. The closure is direct imports only -
// asking the frozen set's own imports would only circle an already-trusted
// set - so walk_full_closure() stays false.
class SyntheticModuleSource final : public capture::ModuleSource {
  public:
    SyntheticModuleSource(std::filesystem::path synth_dir, std::filesystem::path system_modules_dir,
                          const bool system_modules_fallback, std::string arrival_name)
        : synth_dir_(std::move(synth_dir)), system_modules_dir_(std::move(system_modules_dir)),
          system_modules_fallback_(system_modules_fallback), arrival_name_(std::move(arrival_name)),
          directory_mode_(!system_modules_dir_.empty())
    {
    }

    std::expected<void, std::string> prepare() override
    {
        if (directory_mode_) {
            const auto read = [](const std::filesystem::path& path) {
                std::ifstream in(path, std::ios::binary);
                return std::vector<std::uint8_t>{std::istreambuf_iterator<char>(in),
                                                 std::istreambuf_iterator<char>()};
            };
            const auto ntdll = read(system_modules_dir_ / "ntdll.dll");
            const auto bytes = read(system_modules_dir_ / "apiset-map.bin");
            auto map = loader::ApiSetMapView::load(bytes, loader::kApiSetMapArchX64,
                                                   XXH64(ntdll.data(), ntdll.size(), 0));
            if (!map) {
                return std::unexpected("apiset-map.bin: " + map.error().detail);
            }
            directory_map_ = std::move(*map);
            ctx_.mode = loader::ApiSetContext::Mode::kDirectoryMap;
            ctx_.directory_map = &directory_map_;
        }
        // The base pair's host must exist even though it contributes no runner
        // import: a world without kernel32 cannot answer the stub's calls.
        std::string error;
        if (load_module("kernel32.dll", error) == nullptr) {
            return std::unexpected(std::move(error));
        }
        return {};
    }

    capture::ModuleView* acquire(const std::string_view spelled, const std::string_view folded,
                                 std::string& error) override
    {
        const loader::LoadedModule* loaded = load_module(std::string{folded}, error);
        if (loaded == nullptr) {
            return nullptr;
        }
        const auto index = static_cast<std::size_t>(loaded - modules_.data());
        views_.emplace_back(this, std::string{spelled}, std::string{folded}, index);
        return &views_.back();
    }

    // The view's resolution behavior, in one place per world mode.
    std::expected<capture::ModuleView::Hit, std::string> resolve(const std::string& key,
                                                                 const std::size_t index,
                                                                 const std::string_view symbol,
                                                                 const std::uint16_t ordinal)
    {
        capture::ModuleView::Hit hit;
        if (directory_mode_) {
            // Retry only a missing chain endpoint. Each retry must grow the
            // module set; cycles and missing symbols fail closed.
            for (std::size_t hop = 0; hop < 8; ++hop) {
                const auto resolved =
                    symbol.empty()
                        ? loader::resolve_ordinal_export(modules_, key, ordinal, ctx_,
                                                         arrival_name_)
                        : loader::resolve_export(modules_, key, symbol, ctx_, arrival_name_);
                if (resolved.ok) {
                    hit.exported = true;
                    return hit;
                }
                if (resolved.unmapped_api_set || resolved.missing_module.empty()) {
                    break;
                }
                const auto count = modules_.size();
                std::string load_error;
                if (load_module(resolved.missing_module, load_error) == nullptr) {
                    return std::unexpected(std::move(load_error));
                }
                if (modules_.size() == count) {
                    break;
                }
            }
            return hit;
        }
        hit.exported = symbol.empty() ? ordinal_exported(modules_[index], ordinal)
                                      : loader::resolve_export(modules_, key, symbol).ok;
        return hit;
    }

    std::string dependency_error(const std::string_view spelled,
                                 const capture::AdmissionProblem problem) const override
    {
        switch (problem) {
        case capture::AdmissionProblem::kCollisionWithSample:
            return "dependency " + std::string{spelled} +
                   ": name collides with the sample arrival name";
        case capture::AdmissionProblem::kPathShapedName:
            return "dependency " + std::string{spelled} + ": path-shaped import name";
        case capture::AdmissionProblem::kNoImportableExport:
            return "dependency " + std::string{spelled} +
                   ": no verifiable export for the referenced symbols";
        }
        return "dependency " + std::string{spelled} + ": unverifiable dependency";
    }

  private:
    // Loads a module into the store (or finds it there) and returns its
    // element. `original_name` is the folded lookup key; error text is the
    // synthetic route's own wording, in the store's folded spelling.
    const loader::LoadedModule* load_module(const std::string& original_name, std::string& error)
    {
        if (directory_mode_) {
            auto host = folded(original_name);
            if (host.starts_with("api-ms-") || host.starts_with("ext-ms-")) {
                if (host.ends_with(".dll")) {
                    host.resize(host.size() - 4);
                }
                const auto mapped = directory_map_.host_for(host, arrival_name_);
                if (!mapped) {
                    error = "api set not mapped: " + original_name;
                    return nullptr;
                }
                host = folded(*mapped);
            }
            if (!host.ends_with(".dll")) {
                host += ".dll";
            }
            if (host.size() >= 64 || host.find_first_of("/\\:") != std::string::npos ||
                host.find("..") != std::string::npos) {
                error = "path-shaped dependency: " + original_name;
                return nullptr;
            }
            for (const auto& module : modules_) {
                if (std::string_view(module.name.data()) == host) {
                    return &module;
                }
            }
            auto path = system_modules_dir_ / host;
            std::error_code ec;
            if (!std::filesystem::exists(path, ec) || ec) {
                if (!system_modules_fallback_ || synth_dir_.empty()) {
                    error = "missing system module: " + host;
                    return nullptr;
                }
                path = synth_dir_ / (host.substr(0, host.size() - 4) + ".x64.dll");
            }
            std::ifstream in(path, std::ios::binary);
            if (!in) {
                error = "system module unreadable: " + host;
                return nullptr;
            }
            const std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(in),
                                                  std::istreambuf_iterator<char>()};
            const auto info = loader::parse_pe(bytes);
            if (!info || info->bitness != loader::kBitness64) {
                error = "system module is not an x64 PE: " + host;
                return nullptr;
            }
            auto image = loader::build_image(bytes, *info);
            if (!image) {
                error = "system module could not be mapped: " + host;
                return nullptr;
            }
            loader::LoadedModule module;
            module.image = std::move(*image);
            std::memcpy(module.name.data(), host.data(), host.size());
            if (!loader::index_exports(module)) {
                error = "system module export table unreadable: " + host;
                return nullptr;
            }
            modules_.push_back(std::move(module));
            return &modules_.back();
        }
        const std::string key = folded(original_name);
        for (const auto& module : modules_) {
            if (folded(std::string_view(module.name.data())) == key) {
                return &module;
            }
        }
        std::string host{key};
        if (const auto api_host = loader::api_set_host(key); !api_host.empty()) {
            host = std::string(api_host);
        }
        std::string stem{host};
        constexpr std::string_view kDllSuffix = ".dll";
        if (stem.size() > kDllSuffix.size() &&
            stem.compare(stem.size() - kDllSuffix.size(), kDllSuffix.size(), kDllSuffix) == 0) {
            stem.resize(stem.size() - kDllSuffix.size());
        }
        const auto path = synth_dir_ / (stem + ".x64.dll");
        std::error_code ec;
        if (!std::filesystem::exists(path, ec) || ec) {
            error = "dependency " + original_name + ": missing synthetic system module (" + stem +
                    ".x64.dll not in the trusted directory)";
            return nullptr;
        }
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            error = "dependency " + original_name + ": synthetic system module unreadable";
            return nullptr;
        }
        std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(in),
                                        std::istreambuf_iterator<char>()};
        const auto info = loader::parse_pe(bytes);
        if (!info) {
            error =
                "dependency " + original_name + ": synthetic system module is not a loadable PE";
            return nullptr;
        }
        auto image = loader::build_image(bytes, *info);
        if (!image) {
            error = "dependency " + original_name + ": synthetic system module could not be mapped";
            return nullptr;
        }
        loader::LoadedModule module;
        module.base = 0; // verification only: exports carry RVAs
        module.image = std::move(*image);
        const auto name_bytes =
            host.size() < module.name.size() - 1 ? host.size() : module.name.size() - 1;
        std::memcpy(module.name.data(), host.data(), name_bytes);
        if (!loader::index_exports(module).has_value()) {
            error =
                "dependency " + original_name + ": synthetic system module export table unreadable";
            return nullptr;
        }
        modules_.push_back(std::move(module));
        return &modules_.back();
    }

    std::filesystem::path synth_dir_;
    std::filesystem::path system_modules_dir_;
    bool system_modules_fallback_;
    std::string arrival_name_;
    bool directory_mode_;
    loader::ApiSetMapView directory_map_;
    loader::ApiSetContext ctx_;
    std::vector<loader::LoadedModule> modules_;
    std::deque<SyntheticModuleView> views_;
};

std::expected<capture::ModuleView::Hit, std::string>
SyntheticModuleView::resolves(const std::string_view symbol, const std::uint16_t ordinal)
{
    return source_->resolve(key_, index_, symbol, ordinal);
}

} // namespace

// The non-Windows admission: the synthetic module directory is
// the trusted system world. Same runner plan shape as the Windows admission
// (base pair first, then one verified symbol per direct dependency, in the
// sample's own import order) so the same corpus produces the same runner
// bytes on both platforms. Synth modules import nothing and forward nothing
// by construction, so the closure is the direct import set plus kernel32 -
// but every name still resolves through the API-set host rules.
// Public only so the differential test can drive both routes; the container
// construction below is its only product caller.
std::expected<capture::RunnerPlan, std::string>
admit_synth_dll_sample(const std::vector<std::uint8_t>& sample_bytes,
                       const std::string& arrival_name, const std::filesystem::path& synth_dir,
                       const std::filesystem::path& system_modules_dir,
                       const bool system_modules_fallback)
{
    // The arrival name becomes the runner's path string and the emulated
    // Ldr entry's BaseDllName (bounded to 64 chars there) - enforce one
    // bound at the source, matching the Windows admission exactly.
    if (arrival_name.empty() || arrival_name.size() > 64 ||
        !std::all_of(arrival_name.begin(), arrival_name.end(),
                     [](const unsigned char c) { return c >= 0x20 && c < 0x7F && c != '\\'; })) {
        return std::unexpected("sample file name: empty, non-ASCII, or over 64 characters");
    }
    std::vector<capture::PeImportThunk> imports;
    if (const auto error =
            capture::parse_imports(sample_bytes.data(), sample_bytes.size(), imports);
        error != capture::PeError::kNone) {
        return std::unexpected(std::string(capture::pe_error_message(error)));
    }

    capture::RunnerPlan plan;
    plan.arch = capture::WrapArch::kX64;
    plan.arrival_name = arrival_name;
    plan.imports.push_back({"kernel32.dll", "LoadLibraryW", 0});
    plan.imports.push_back({"kernel32.dll", "ExitProcess", 0});

    SyntheticModuleSource source(synth_dir, system_modules_dir, system_modules_fallback,
                                 arrival_name);
    if (const auto prepared = source.prepare(); !prepared.has_value()) {
        return std::unexpected(prepared.error());
    }

    std::set<std::string> processed{folded("kernel32.dll")};
    std::size_t cursor = 0;
    // (folded key, original spelling) - errors name the dependency the way
    // the sample spelled it, not the folded lookup key.
    std::vector<std::pair<std::string, std::string>> queue;
    for (const auto& import : imports) {
        const std::string key = folded(import.module);
        if (std::none_of(queue.begin(), queue.end(),
                         [&](const std::pair<std::string, std::string>& pending) {
                             return pending.first == key;
                         })) {
            queue.push_back({key, import.module});
        }
    }
    while (cursor < queue.size()) {
        const auto [key, spelled] = queue[cursor++];
        if (key == folded(arrival_name)) {
            return std::unexpected(
                source.dependency_error(spelled, capture::AdmissionProblem::kCollisionWithSample));
        }
        if (processed.count(key) != 0) {
            continue;
        }
        processed.insert(key);
        if (key.empty() || key.find('\\') != std::string::npos ||
            key.find('/') != std::string::npos || key.find(':') != std::string::npos ||
            key.find("..") != std::string::npos) {
            return std::unexpected(
                source.dependency_error(spelled, capture::AdmissionProblem::kPathShapedName));
        }
        std::string source_error;
        capture::ModuleView* module = source.acquire(spelled, key, source_error);
        if (module == nullptr) {
            return std::unexpected(std::move(source_error));
        }

        // Pick the first referenced symbol that verifies against the frozen
        // module, in the sample's own import order (the Windows admission's
        // selection rule, so one corpus yields one plan everywhere).
        bool selected = false;
        for (const auto& import : imports) {
            if (folded(import.module) != key) {
                continue;
            }
            const auto resolved = module->resolves(import.name, import.ordinal);
            if (!resolved.has_value()) {
                return std::unexpected(resolved.error());
            }
            if (!resolved->exported) {
                continue;
            }
            plan.imports.push_back({import.module, import.name, import.ordinal});
            if (plan.imports.size() > capture::kMaxRunnerImports) {
                return std::unexpected("dependency closure exceeds the runner capacity");
            }
            selected = true;
            break;
        }
        if (!selected) {
            return std::unexpected(
                source.dependency_error(spelled, capture::AdmissionProblem::kNoImportableExport));
        }
    }
    return plan;
}

namespace {

std::expected<std::vector<std::uint8_t>, RebuildFailure>
serialize_guest(const PreparedGuest& guest, const snapshot::PendingModule* pending)
{
    if (guest.guest_mode != GuestMode::kX64) {
        // The delivered container surface is 64-bit; the non-Windows sample
        // route refuses PE32 before this point.
        return std::unexpected(failure(RebuildError::kBitnessUnsupported));
    }
    if (guest.metadata.peb_address == 0 || guest.metadata.teb_address == 0 ||
        guest.metadata.image_base == 0 || guest.metadata.entry_address == 0) {
        return std::unexpected(failure(RebuildError::kBadSnapshot));
    }

    std::vector<mem_region::RegionRecord> regions = guest.regions;
    std::sort(regions.begin(), regions.end(),
              [](const mem_region::RegionRecord& a, const mem_region::RegionRecord& b) {
                  return a.base < b.base;
              });

    std::ostringstream out;
    snapshot::Writer writer{out};
    if (!writer.write_header(snapshot::Header{.version = pending != nullptr ? snapshot::kVersionV2
                                                                            : snapshot::kVersion,
                                              .bitness = snapshot::kBitness64})) {
        return std::unexpected(failure(RebuildError::kIoFailure));
    }

    snapshot::Registers registers{};
    const auto uc = guest.unicorn.get();
    for (std::size_t i = 0; i < snapshot::kGprCount; ++i) {
        if (uc_reg_read(uc, kGprRegisters64[i], &registers.gpr[i]) != UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
    }
    if (uc_reg_read(uc, UC_X86_REG_EFLAGS, &registers.rflags) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    // The construction leaves RIP at zero ("written by the run start"); the
    // container's register block must name the entry the replay starts at -
    // the reader rejects a container whose RIP disagrees with metadata.
    registers.rip = guest.metadata.entry_address;
    if (!writer.write_registers(registers) || !writer.write_metadata(guest.metadata)) {
        return std::unexpected(failure(RebuildError::kIoFailure));
    }

    for (const auto& region : regions) {
        if (region.size == 0) {
            continue;
        }
        if (region.base % kMapAlignment != 0 || region.size % kMapAlignment != 0) {
            return std::unexpected(failure(RebuildError::kUnalignedRegion));
        }
        std::vector<std::uint8_t> payload(static_cast<std::size_t>(region.size), std::uint8_t{0});
        if (uc_mem_read(uc, region.base, payload.data(), payload.size()) != UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
        // Zero-filled mappings (the deterministic heap, an untouched stack)
        // carry no information; recording them content-absent keeps the
        // container at the module+environment scale and the replay maps the
        // same zeros back. Deterministic: the omission is a pure function of
        // the bytes.
        const bool present = !all_zero(payload);
        const snapshot::RegionHeader header{
            .base_address = region.base,
            .size = region.size,
            .protection = region.protection,
            .type = region.type,
            .content = present ? snapshot::kContentPresent : snapshot::kContentAbsent,
        };
        if (!writer.write_region(header, present ? payload.data() : nullptr)) {
            return std::unexpected(failure(RebuildError::kIoFailure));
        }
    }
    if (!writer.finalize_region_count()) {
        return std::unexpected(failure(RebuildError::kIoFailure));
    }
    if (pending != nullptr && !writer.write_pending(*pending)) {
        return std::unexpected(failure(RebuildError::kIoFailure));
    }
    const std::string bytes = out.str();
    return std::vector<std::uint8_t>{bytes.begin(), bytes.end()};
}

// The DLL-input construction: admit against the frozen directory, build the
// runner, construct the world from the runner image, serialize v2 with the
// pending block. The runner's temp path never enters the container bytes
// (prepare_pe_file reads the file only), so the random name is a
// concurrency guard, not a determinism leak.
std::expected<std::vector<std::uint8_t>, RebuildFailure>
craft_dll_sample_container(const std::filesystem::path& pe_path,
                           const std::vector<std::uint8_t>& sample_bytes, const bool fidelity_seams,
                           const std::filesystem::path& synthetic_module_dir,
                           const std::filesystem::path& system_modules_dir,
                           const bool system_modules_fallback, const capture::PeImageInfo& info)
{
    if (info.bitness != 64) {
        return std::unexpected(failure(RebuildError::kBitnessUnsupported,
                                       std::string{"DLL input is only supported for x64 images"}));
    }
    const std::string arrival_name = pe_path.filename().string();
    const auto plan = admit_synth_dll_sample(sample_bytes, arrival_name, synthetic_module_dir,
                                             system_modules_dir, system_modules_fallback);
    if (!plan) {
        return std::unexpected(
            failure(RebuildError::kBadSnapshot, "DLL input rejected: " + plan.error()));
    }
    const auto runner = capture::build_runner(*plan);
    if (!runner) {
        return std::unexpected(failure(RebuildError::kBadSnapshot,
                                       std::string{capture::runner_error_message(runner.error())}));
    }
    std::error_code ec;
    const auto temp_dir = std::filesystem::temp_directory_path(ec);
    if (ec) {
        return std::unexpected(failure(RebuildError::kIoFailure));
    }
    thread_local std::mt19937_64 generator{std::random_device{}()};
    char name[32] = {};
    std::snprintf(name, sizeof name, "sheller_craft_%llx.exe",
                  static_cast<unsigned long long>(generator()));
    const auto runner_path = temp_dir / name;
    {
        std::ofstream out(runner_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(runner->data()),
                  static_cast<std::streamsize>(runner->size()));
        if (!out) {
            return std::unexpected(failure(RebuildError::kIoFailure));
        }
    }
    auto guest = prepare_pe_file(runner_path, fidelity_seams, synthetic_module_dir,
                                 system_modules_dir, system_modules_fallback);
    std::error_code remove_ec;
    std::filesystem::remove(runner_path, remove_ec); // best effort: the world is built
    if (!guest) {
        return std::unexpected(guest.error());
    }
    const snapshot::PendingModule pending{
        .name = arrival_name, .bitness = snapshot::kBitness64, .bytes = sample_bytes};
    return serialize_guest(*guest, &pending);
}

} // namespace

std::expected<std::vector<std::uint8_t>, RebuildFailure>
craft_container_from_guest(const PreparedGuest& guest)
{
    return serialize_guest(guest, nullptr);
}

std::expected<std::vector<std::uint8_t>, RebuildFailure>
craft_sample_container(const std::filesystem::path& pe_path, const bool fidelity_seams,
                       const std::filesystem::path& synthetic_module_dir,
                       const std::filesystem::path& system_modules_dir,
                       const bool system_modules_fallback)
{
    if (system_modules_dir.empty() && synthetic_module_dir.empty()) {
        return std::unexpected(failure(RebuildError::kSyntheticModulesMissing));
    }
    std::ifstream in(pe_path, std::ios::binary);
    if (!in) {
        return std::unexpected(failure(RebuildError::kIoFailure));
    }
    std::vector<std::uint8_t> sample{std::istreambuf_iterator<char>(in),
                                     std::istreambuf_iterator<char>()};
    if (sample.empty()) {
        return std::unexpected(failure(RebuildError::kIoFailure));
    }
    capture::PeImageInfo info;
    const bool is_dll =
        capture::parse_pe_headers(sample.data(), sample.size(), info) == capture::PeError::kNone &&
        info.is_dll;
    if (!is_dll) {
        auto guest = prepare_pe_file(pe_path, fidelity_seams, synthetic_module_dir,
                                     system_modules_dir, system_modules_fallback);
        if (!guest) {
            return std::unexpected(guest.error());
        }
        return serialize_guest(*guest, nullptr);
    }
    return craft_dll_sample_container(pe_path, sample, fidelity_seams, synthetic_module_dir,
                                      system_modules_dir, system_modules_fallback, info);
}

} // namespace sheller::engine
