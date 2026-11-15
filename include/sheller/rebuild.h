// sheller public rebuild header - the engine-side consumer of snapshot
// containers (v1/v2/v3): rebuild the captured guest world at its original
// addresses, run a bounded stretch of code, and report whether execution
// reached the entrypoint. Standard library only: no unicorn or Windows
// headers may leak in here; the Unicorn instance lives and dies inside the
// engine.

#ifndef SHELLER_REBUILD_H
#define SHELLER_REBUILD_H

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>

namespace sheller::engine {

enum class RebuildError {
    kNone = 0,
    kIoFailure,          // snapshot file could not be opened or read
    kBadSnapshot,        // reader rejection (magic/version/truncation/content flag)
    kBitnessUnsupported, // snapshot is not a 64-bit capture
    kInconsistent,       // registers.rip disagrees with the entry address
    kUnalignedRegion,    // region base/size violates the 4KB mapping alignment
    kUnicornFailure,     // a unicorn setup call failed (open/map/write/reg/hook)
    kEmulationFailure,   // uc_emu_start aborted with an emulation error
    kEntryNotReached,    // bounded run finished without the three-part proof
    // Crafting a sample container needs the synthetic module pages; the
    // request carried no directory to read them from.
    kSyntheticModulesMissing,
};

// Verdict statistics of a bounded run. reached_entry requires all three
// proofs together: clean count expiry, a block hook hit on the entry address,
// and the final RIP still sitting on the entry.
struct RebuildStats {
    bool reached_entry{};
    std::uint64_t blocks{};
    std::uint64_t entry_hits{};
    std::uint64_t final_rip{};
};

struct RebuildFailure {
    RebuildError error{};
    // Raw unicorn error code; meaningful when error is kUnicornFailure or
    // kEmulationFailure, zero otherwise.
    std::uint32_t unicorn_code{};
    // Partial statistics - filled when the bounded run did execute.
    RebuildStats stats{};
    // Optional named-failure text (the DLL-input construction names the
    // rejected dependency or unbuildable runner part); empty means the
    // consumer should present rebuild_error_message(error) as usual.
    std::string detail{};
};

std::string_view rebuild_error_message(RebuildError error);

std::expected<RebuildStats, RebuildFailure>
run_snapshot_entrypoint(const std::filesystem::path& snapshot_path);

} // namespace sheller::engine

#endif // SHELLER_REBUILD_H
