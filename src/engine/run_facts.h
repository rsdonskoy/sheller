// Read-only run facts: the guest probes the syscall run's state assembly needs,
// gathered once before anything is written. Every field is a plain value, so a
// later plan stage can be a pure function over them (no unicorn handle, no
// state, no writes).
//
// The probes here only read: guest memory for the PEB-derived current
// directory and the ntdll syscall stubs, the region map for the sample's own
// module record. The const reference blocks the region-map write APIs (and
// every state-side helper) at compile time; the unicorn handle itself is a
// bare pointer, so "read-only" for guest memory is a review rule rather than a
// type barrier.

#ifndef SHELLER_ENGINE_RUN_FACTS_H
#define SHELLER_ENGINE_RUN_FACTS_H

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <string>

namespace sheller::engine {

struct PreparedGuest;

struct GuestFacts {
    // The base relative guest paths resolve against, already resolved: the
    // guest's own relative_base, or the captured process's
    // PEB->ProcessParameters->CurrentDirectory when that derivation passes
    // every guard. Each degradation (no PEB, malformed length, non-absolute,
    // not a directory) keeps the input value rather than clearing it.
    std::filesystem::path relative_base;
    // The target ntdll's syscall number <-> name tables (a forward and its
    // exact inverse). Both empty when no ntdll is resident or its stubs do not
    // decode - synthetic numbers never collide with the real ones.
    std::map<std::uint32_t, std::string> syscall_names;
    std::map<std::string, std::uint32_t> syscall_numbers_by_name;
    // The sample's own module record in the region map: the index of the
    // module whose base equals the snapshot image base, and its SizeOfImage
    // (0 when no such module is resident).
    bool sample_module_known{};
    std::size_t sample_module_index{};
    std::uint64_t sample_image_size{};
};

// Reads the guest once; never writes guest memory and never touches the run
// state.
GuestFacts snapshot_guest_facts(const PreparedGuest& guest);

} // namespace sheller::engine

#endif // SHELLER_ENGINE_RUN_FACTS_H
