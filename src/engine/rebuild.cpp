// Composition layer of the engine's public entry points: the facades wire a
// rebuild route (snapshot or loader) to a run path and translate failures
// between the stage-specific error types, and the sheller::engine::detail
// probes expose intermediate state to the test and repair tooling. The
// stages themselves live in loader_route.* (construction) and run.*
// (execution).

#include "craft.h"
#include "loader_route.h"
#include "rebuild_probe.h"
#include "rebuild_state.h"
#include "run.h"

#include "../syscalls/syscall_number_map.h"
#include <sheller/peloader.h>
#include <sheller/snapshot.h>
#include <sheller/syscallrun.h>

#include <unicorn/unicorn.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <spanstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

// Input stream over in-memory snapshot bytes without copying them: the
// snapshot readers walk the stream strictly sequentially and an ispanstream
// opened for input never writes back, so the const buffer's storage can back
// the span directly (a string-stream wrap would copy the whole snapshot -
// real snapshots carry hundreds of megabytes).
std::ispanstream snapshot_byte_stream(const std::vector<std::uint8_t>& snapshot)
{
    return std::ispanstream{std::span<char>{
        reinterpret_cast<char*>(const_cast<std::uint8_t*>(snapshot.data())), snapshot.size()}};
}

} // namespace

namespace sheller::engine {

namespace {

// The rebuild and run error enums share their historical order; the newer
// value is mapped explicitly so a future insertion cannot silently
// reinterpret one as the other.
SyscallRunError run_error_of(const RebuildError error)
{
    switch (error) {
    case RebuildError::kSyntheticModulesMissing:
        return SyscallRunError::kSyntheticModulesMissing;
    default:
        return static_cast<SyscallRunError>(error);
    }
}

SyscallRunFailure run_failure_of(const RebuildFailure& failure)
{
    // Prepare-stage failures carry no run statistics; the named rejection
    // detail (the loader-route wording names the module and the reason)
    // travels with the mapped error.
    return SyscallRunFailure{run_error_of(failure.error), failure.unicorn_code, {}, failure.detail};
}

} // namespace

std::string_view rebuild_error_message(const RebuildError error)
{
    switch (error) {
    case RebuildError::kNone:
        return "ok";
    case RebuildError::kIoFailure:
        return "snapshot file could not be opened or read";
    case RebuildError::kBadSnapshot:
        return "snapshot rejected by the format reader";
    case RebuildError::kBitnessUnsupported:
        return "snapshot bitness not supported (64-bit only)";
    case RebuildError::kInconsistent:
        return "snapshot inconsistent (RIP disagrees with the entry address)";
    case RebuildError::kUnalignedRegion:
        return "snapshot region violates the 4KB mapping alignment";
    case RebuildError::kUnicornFailure:
        return "unicorn setup call failed";
    case RebuildError::kEmulationFailure:
        return "bounded emulation aborted with an emulation error";
    case RebuildError::kEntryNotReached:
        return "bounded emulation finished without reaching the entrypoint";
    case RebuildError::kSyntheticModulesMissing:
        return "synthetic system modules required but no directory was provided";
    }
    return "unknown rebuild error";
}

std::expected<RebuildStats, RebuildFailure>
run_snapshot_entrypoint(const std::filesystem::path& snapshot_path)
{
    auto guest = prepare_guest(snapshot_path);
    if (!guest) {
        return std::unexpected(guest.error());
    }
    auto run = run_entry_proof(*guest);
    if (!run) {
        return std::unexpected(run.error());
    }
    return run->stats;
}

std::string_view syscall_run_error_message(const SyscallRunError error)
{
    switch (error) {
    case SyscallRunError::kNone:
        return "ok";
    case SyscallRunError::kIoFailure:
        return "snapshot file could not be opened or read";
    case SyscallRunError::kBadSnapshot:
        return "snapshot rejected by the format reader";
    case SyscallRunError::kBitnessUnsupported:
        return "snapshot bitness not supported (64-bit only)";
    case SyscallRunError::kInconsistent:
        return "snapshot inconsistent (RIP disagrees with the entry address)";
    case SyscallRunError::kUnalignedRegion:
        return "snapshot region violates the 4KB mapping alignment";
    case SyscallRunError::kUnicornFailure:
        return "unicorn setup call failed";
    case SyscallRunError::kEmulationFailure:
        return "bounded emulation aborted with an emulation error";
    case SyscallRunError::kBudgetExhausted:
        return "instruction budget expired without termination";
    case SyscallRunError::kTimeout:
        return "wall-clock timeout expired without termination";
    case SyscallRunError::kUnhandledException:
        return "guest crashed on an unhandled exception";
    case SyscallRunError::kSyntheticModulesMissing:
        return "synthetic system modules required to replay this container (none provided)";
    }
    return "unknown syscall run error";
}

std::expected<SyscallRunStats, SyscallRunFailure>
run_snapshot_syscalls(const std::filesystem::path& snapshot_path, const SyscallRunOptions& options)
{
    return detail::run_snapshot_syscalls_with_facts(snapshot_path, options, {});
}

std::expected<SyscallRunStats, SyscallRunFailure> run_pe_file(const std::filesystem::path& pe_path,
                                                              const SyscallRunOptions& options)
{
    return detail::run_pe_file_with_facts(pe_path, options, {});
}

std::expected<SyscallRunStats, SyscallRunFailure>
run_snapshot_syscalls(const std::vector<std::uint8_t>& snapshot, const SyscallRunOptions& options)
{
    return detail::run_snapshot_syscalls_with_facts(snapshot, options, {});
}

} // namespace sheller::engine

namespace sheller::engine::detail {

std::expected<SyscallRunStats, SyscallRunFailure>
run_snapshot_syscalls_with_facts(const std::filesystem::path& snapshot_path,
                                 const SyscallRunOptions& options, const FactChannel& facts)
{
    // Snapshot ntdll carries the captured process's already-initialized IFT
    // data, so the rebuild has no fidelity seam to prepare: the engine-side
    // dispatcher reads .pdata directly and windows_fidelity_dispatch only
    // takes effect at run time (the SEH dispatch state machine).
    auto guest = prepare_guest(snapshot_path);
    if (!guest) {
        return std::unexpected(run_failure_of(guest.error()));
    }
    guest->relative_base = snapshot_path.parent_path();
    if (const auto attached = reattach_synthetic_world(*guest, options.synthetic_module_dir);
        !attached) {
        return std::unexpected(SyscallRunFailure{attached.error(), 0, {}});
    }
    auto run = run_syscalls(*guest, options, facts);
    if (!run) {
        return std::unexpected(run.error());
    }
    return run;
}

std::expected<SyscallRunStats, SyscallRunFailure>
run_pe_file_with_facts(const std::filesystem::path& pe_path, const SyscallRunOptions& options,
                       const FactChannel& facts)
{
#ifdef _WIN32
    // Windows hosts keep the live loader entry: the production sample path is
    // capture, and the loader route here serves the loader corpus tests.
    // The IFT/init-gate seeding is a Windows-fidelity seam (the real ntdll
    // dispatcher consumes it); the engine-side dispatcher reads .pdata
    // directly, so the default path stays zero-touch.
    auto guest = prepare_pe_file(pe_path, options.windows_fidelity_dispatch,
                                 options.synthetic_system_modules ? options.synthetic_module_dir
                                                                  : std::filesystem::path{},
                                 options.system_modules_dir, options.system_modules_fallback);
    if (!guest) {
        return std::unexpected(run_failure_of(guest.error()));
    }
    auto run = run_syscalls(*guest, options, facts);
    if (!run) {
        return std::unexpected(run.error());
    }
    return run;
#else
    // Non-Windows hosts execute the constructed container, never the live
    // loader guest: construction is the only producer, replay the only
    // executor.
    auto container = craft_sample_container(pe_path, options.windows_fidelity_dispatch,
                                            options.synthetic_module_dir);
    if (!container) {
        return std::unexpected(run_failure_of(container.error()));
    }
    return run_snapshot_syscalls_with_facts(*container, options, facts);
#endif
}

std::expected<SyscallRunStats, SyscallRunFailure>
run_snapshot_syscalls_with_facts(const std::vector<std::uint8_t>& snapshot,
                                 const SyscallRunOptions& options, const FactChannel& facts)
{
    std::ispanstream in = snapshot_byte_stream(snapshot);
    auto guest = prepare_guest_stream(in);
    if (!guest) {
        return std::unexpected(run_failure_of(guest.error()));
    }
    if (const auto attached = reattach_synthetic_world(*guest, options.synthetic_module_dir);
        !attached) {
        return std::unexpected(SyscallRunFailure{attached.error(), 0, {}});
    }
    auto run = run_syscalls(*guest, options, facts);
    if (!run) {
        return std::unexpected(run.error());
    }
    return run;
}

} // namespace sheller::engine::detail

namespace sheller::engine::detail {

std::expected<RebuildProbe, RebuildFailure>
rebuild_and_probe(const std::filesystem::path& snapshot_path)
{
    auto guest = prepare_guest(snapshot_path);
    if (!guest) {
        return std::unexpected(guest.error());
    }
    auto run = run_entry_proof(*guest);
    if (!run) {
        return std::unexpected(run.error());
    }

    RebuildProbe probe{.stats = run->stats};
    if (uc_reg_read(run->unicorn.get(), UC_X86_REG_GS_BASE, &probe.gs_base) != UC_ERR_OK ||
        uc_reg_read(run->unicorn.get(), UC_X86_REG_RIP, &probe.rip) != UC_ERR_OK ||
        uc_reg_read(run->unicorn.get(), UC_X86_REG_EFLAGS, &probe.rflags) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    for (std::size_t i = 0; i < snapshot::kGprCount; ++i) {
        if (uc_reg_read(run->unicorn.get(), kGprRegisters64[i], &probe.gpr[i]) != UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
    }
    if (uc_mem_read(run->unicorn.get(), run->stats.final_rip, probe.entry_bytes.data(),
                    probe.entry_bytes.size()) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    return probe;
}

std::expected<AttributionProbe, RebuildFailure>
attribute_snapshot_modules(const std::filesystem::path& snapshot_path)
{
    auto guest = prepare_guest(snapshot_path);
    if (!guest) {
        return std::unexpected(guest.error());
    }
    AttributionProbe probe;
    // Split the guest's module set on the synthesized flag: the Ldr set
    // stays in images, the unknown-image tail in unknown_images.
    for (auto& image : guest->images) {
        (image.module.synthesized ? probe.unknown_images : probe.images)
            .push_back(std::move(image));
    }
    probe.regions = std::move(guest->regions);
    // Real syscall numbers, resolved while the guest is alive: the map names
    // ntdll, and the stubs decode to per-build numbers.
    std::uint64_t ntdll_base = 0;
    if (const auto ntdll_index = guest->map.module_index_by_name("ntdll.dll");
        ntdll_index.has_value()) {
        ntdll_base = guest->map.module(*ntdll_index).base;
        probe.syscall_numbers =
            syscalls::enumerate_ntdll_syscalls(guest->unicorn.get(), ntdll_base);
    }
    // Export functions-array slots for every module (behavior seam):
    // the table the behavior layer's export-walk signal matches reads
    // against. Bounded by the enumerator's own caps, built once here.
    for (const auto& image : probe.images) {
        for (const auto& export_entry :
             syscalls::enumerate_exports(guest->unicorn.get(), image.module.base)) {
            probe.export_slots.push_back(
                {image.module.base, export_entry.slot_va, export_entry.address, export_entry.name});
        }
    }
    probe.teb_address = guest->metadata.teb_address;
    probe.peb_address = guest->metadata.peb_address;
    probe.image_base = guest->metadata.image_base;
    for (std::size_t i = 0; i < guest->map.module_count(); ++i) {
        if (guest->map.module(i).base == guest->metadata.image_base) {
            probe.image_size = guest->map.module(i).size;
            break;
        }
    }
    return probe;
}

std::expected<AttributionProbe, RebuildFailure>
attribute_snapshot_modules(const std::vector<std::uint8_t>& snapshot)
{
    std::ispanstream in = snapshot_byte_stream(snapshot);
    auto guest = prepare_guest_stream(in);
    if (!guest) {
        return std::unexpected(guest.error());
    }
    AttributionProbe probe;
    // Split the guest's module set on the synthesized flag (see the path
    // overload above).
    for (auto& image : guest->images) {
        (image.module.synthesized ? probe.unknown_images : probe.images)
            .push_back(std::move(image));
    }
    probe.regions = std::move(guest->regions);
    std::uint64_t ntdll_base = 0;
    if (const auto ntdll_index = guest->map.module_index_by_name("ntdll.dll");
        ntdll_index.has_value()) {
        ntdll_base = guest->map.module(*ntdll_index).base;
        probe.syscall_numbers =
            syscalls::enumerate_ntdll_syscalls(guest->unicorn.get(), ntdll_base);
    }
    for (const auto& image : probe.images) {
        for (const auto& export_entry :
             syscalls::enumerate_exports(guest->unicorn.get(), image.module.base)) {
            probe.export_slots.push_back(
                {image.module.base, export_entry.slot_va, export_entry.address, export_entry.name});
        }
    }
    probe.teb_address = guest->metadata.teb_address;
    probe.peb_address = guest->metadata.peb_address;
    probe.image_base = guest->metadata.image_base;
    for (std::size_t i = 0; i < guest->map.module_count(); ++i) {
        if (guest->map.module(i).base == guest->metadata.image_base) {
            probe.image_size = guest->map.module(i).size;
            break;
        }
    }
    return probe;
}

std::expected<std::vector<ModuleImageProbe>, RebuildFailure>
read_module_images(const std::filesystem::path& snapshot_path)
{
    auto guest = prepare_guest(snapshot_path);
    if (!guest) {
        return std::unexpected(guest.error());
    }
    std::vector<ModuleImageProbe> out;
    const auto uc = guest->unicorn.get();
    for (std::size_t i = 0; i < guest->map.module_count(); ++i) {
        const auto& module = guest->map.module(i);
        if (module.synthesized) {
            continue; // synthesized unknown images are not repair targets
        }
        ModuleImageProbe probe;
        probe.module = module;
        probe.image.assign(static_cast<std::size_t>(module.size), std::uint8_t{0});
        // A module that cannot be read whole is skipped: the consumer's
        // coverage report just misses it (the IAT repair's design).
        if (uc_mem_read(uc, module.base, probe.image.data(), probe.image.size()) != UC_ERR_OK) {
            continue;
        }
        out.push_back(std::move(probe));
    }
    return out;
}

std::expected<std::vector<std::uint8_t>, RebuildFailure>
read_snapshot_range(const std::filesystem::path& snapshot_path, const std::uint64_t base,
                    const std::uint32_t size)
{
    auto guest = prepare_guest(snapshot_path);
    if (!guest) {
        return std::unexpected(guest.error());
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size), std::uint8_t{0});
    if (uc_mem_read(guest->unicorn.get(), base, bytes.data(), bytes.size()) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kBadSnapshot));
    }
    return bytes;
}

std::expected<std::vector<ModuleImageProbe>, RebuildFailure>
read_module_images(const std::vector<std::uint8_t>& snapshot)
{
    std::ispanstream in = snapshot_byte_stream(snapshot);
    auto guest = prepare_guest_stream(in);
    if (!guest) {
        return std::unexpected(guest.error());
    }
    std::vector<ModuleImageProbe> out;
    const auto uc = guest->unicorn.get();
    for (std::size_t i = 0; i < guest->map.module_count(); ++i) {
        const auto& module = guest->map.module(i);
        if (module.synthesized) {
            continue; // synthesized unknown images are not repair targets
        }
        ModuleImageProbe probe;
        probe.module = module;
        probe.image.assign(static_cast<std::size_t>(module.size), std::uint8_t{0});
        if (uc_mem_read(uc, module.base, probe.image.data(), probe.image.size()) != UC_ERR_OK) {
            continue;
        }
        out.push_back(std::move(probe));
    }
    return out;
}

std::expected<std::vector<std::uint8_t>, RebuildFailure>
read_snapshot_range(const std::vector<std::uint8_t>& snapshot, const std::uint64_t base,
                    const std::uint32_t size)
{
    std::ispanstream in = snapshot_byte_stream(snapshot);
    auto guest = prepare_guest_stream(in);
    if (!guest) {
        return std::unexpected(guest.error());
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size), std::uint8_t{0});
    if (uc_mem_read(guest->unicorn.get(), base, bytes.data(), bytes.size()) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kBadSnapshot));
    }
    return bytes;
}

} // namespace sheller::engine::detail
