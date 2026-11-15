// Loader-route environment construction:
// TEB / PEB / Ldr triple-chain / ProcessParameters, built as deterministic
// bytes by pure functions - no unicorn - so shells that walk the environment
// (by-hash API resolution) run against a layout that is unit-testable and
// byte-reproducible.

#ifndef SHELLER_LOADER_ENV_H
#define SHELLER_LOADER_ENV_H

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace sheller::loader {

// Environment block sub-layout (relative to the block base). Fixed so the
// engine, the behavior windows and tests agree on every address.
inline constexpr std::uint64_t kEnvTebOffset = 0x0000;
inline constexpr std::uint64_t kEnvPebOffset = 0x1000;
inline constexpr std::uint64_t kEnvParamsOffset = 0x2000;
inline constexpr std::uint64_t kEnvLdrOffset = 0x3000;
inline constexpr std::uint64_t kEnvBlockSize = 0x13000;

// Per-module LDR_DATA_TABLE_ENTRY stride and field offsets (x64 Win10/11
// shape the by-hash shells walk: InLoadOrder node, DllBase at +0x30,
// BaseDllName UNICODE_STRING at +0x58). The shared name buffer lives at
// +0x80 and the entry stride bounds it: 0x80 bytes for the UTF-16 text plus
// its u16 terminator.
inline constexpr std::uint64_t kLdrEntryStride = 0x100;
inline constexpr std::uint64_t kLdrDataSize = 0x10000;
inline constexpr std::uint64_t kLdrNameBufferBytes = 0x80;

// The named construction rejection: a module name whose UTF-16 form does not
// fit the per-entry name buffer. The build refuses instead of truncating - a
// truncated name is just a second, quieter walk-breaking name. `name`
// identifies the offending module so the caller can name its own failure.
struct EnvNameTooLong {
    std::string name;
};

struct EnvModule {
    std::uint64_t base{};
    std::uint32_t size{};
    std::string name; // folded (lowercase) with extension
};

// The three chains' independent member orders, index-aligned with the
// modules argument. Empty vectors chain every module in argument order
// (the pre-record shape); a real-loader world threads each chain per its
// own record - the capture corpus's shape: load/memory both lead with the
// main image, the init chain excludes it and starts at ntdll (the
// three-chain record in the crafted-world change directory). A chain order
// MUST be a distinct in-range subset of the module indices (the validator
// rejects duplicates and out-of-range indices); modules outside a chain
// keep that chain's node self-looped.
struct ChainOrders {
    std::vector<std::size_t> load;
    std::vector<std::size_t> memory;
    std::vector<std::size_t> init;
};

struct EnvironmentBuild {
    std::uint64_t teb_va{};
    std::uint64_t peb_va{};
    std::uint64_t params_va{};
    std::uint64_t ldr_va{};
    std::uint64_t module_count{};
    // guest VA of each module's LDR_DATA_TABLE_ENTRY base (the
    // InLoadOrderLinks node), index-aligned with the modules argument - the
    // engine hands these out as LdrLoadDll handles
    std::vector<std::uint64_t> module_entry_vas{};
    std::vector<std::uint8_t> env; // kEnvBlockSize bytes, deterministic
};

// Builds the whole environment block (x64 layout). modules are chained in
// the order given (the sample first, then system modules); `orders` (when
// its vectors are non-empty) threads each chain in its own member order
// instead. stack_base/limit feed the TEB NtTib; heap_base feeds
// PEB.ProcessHeap. Every entry's FullDllName/BaseDllName share one UTF-16LE
// buffer at +0x80 with byte-count UNICODE_STRING lengths - the convention
// the real loader and the runtime-inserted Ldr entries carry; a name that
// does not fit the buffer is the named EnvNameTooLong refusal.
std::expected<EnvironmentBuild, EnvNameTooLong>
build_environment(std::uint64_t env_base, std::uint64_t image_base, std::uint64_t stack_base,
                  std::uint64_t stack_limit, std::uint64_t heap_base,
                  const std::vector<EnvModule>& modules, const ChainOrders& orders = {});

// x86 twin: the same block geometry (TEB/PEB/params/Ldr pages) but
// the 32-bit structure shapes - fs:[18h] Self@0x18, ClientId@0x20, PEB@0x30;
// PEB ImageBase@0x08, Ldr@0x0C, Heap@0x18; 4-byte LIST_ENTRY32 chain nodes;
// LDR entry DllBase@0x18, SizeOfImage@0x20, BaseDllName@0x2C with 8-byte
// UNICODE_STRING32. Same UTF-16 name conventions and the same refusal.
std::expected<EnvironmentBuild, EnvNameTooLong>
build_environment_x86(std::uint64_t env_base, std::uint64_t image_base, std::uint64_t stack_base,
                      std::uint64_t stack_limit, std::uint64_t heap_base,
                      const std::vector<EnvModule>& modules, const ChainOrders& orders = {});

// KUSER_SHARED_DATA semantic fields: fixed SystemTime /
// TickCount values plus the NtSystemRoot string - honest zeros everywhere
// else. Deterministic, never wall-clock derived.
void fill_kuser_shared_data(std::span<std::uint8_t> page);

} // namespace sheller::loader

#endif // SHELLER_LOADER_ENV_H
