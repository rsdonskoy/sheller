#include "env.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <span>
#include <string_view>

namespace sheller::loader {
namespace {

void store16(std::vector<std::uint8_t>& out, std::size_t offset, std::uint16_t value)
{
    out[offset] = static_cast<std::uint8_t>(value & 0xFF);
    out[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
}

void store32(std::vector<std::uint8_t>& out, std::size_t offset, std::uint32_t value)
{
    out[offset] = static_cast<std::uint8_t>(value & 0xFF);
    out[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    out[offset + 2] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
    out[offset + 3] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
}

void store64(std::vector<std::uint8_t>& out, std::size_t offset, std::uint64_t value)
{
    for (std::size_t i = 0; i < 8; ++i) {
        out[offset + i] = static_cast<std::uint8_t>((value >> (8 * i)));
    }
}

// Writes the folded module name at the buffer offset as UTF-16LE with a u16
// NUL terminator. UNICODE_STRING conventions: Length counts bytes (2 per
// character) and MaximumLength adds the terminator - the shape the real
// loader and the runtime-inserted Ldr entries carry, and the shape a
// wchar-wise name comparison matches against. Refuses a name that does not
// fit the buffer instead of truncating.
bool store_utf16_name(std::vector<std::uint8_t>& out, const std::size_t offset,
                      const std::string_view name)
{
    if (2 * name.size() + 2 > kLdrNameBufferBytes) {
        return false;
    }
    for (std::size_t i = 0; i < name.size(); ++i) {
        out[offset + 2 * i] = static_cast<std::uint8_t>(name[i]);
        out[offset + 2 * i + 1] = 0;
    }
    out[offset + 2 * name.size()] = 0;
    out[offset + 2 * name.size() + 1] = 0;
    return true;
}

// The three chains' member sequences: an explicit member list per chain
// when given, every module in argument order otherwise. A chain's list is
// a distinct in-range subset of the module indices - the real loader's
// init chain excludes the main image (the capture corpus's three-chain
// record), and a module outside a chain keeps that chain's node
// self-looped (the chain walk never visits it).
std::array<std::vector<std::size_t>, 3> chain_sequences(const std::size_t count,
                                                        const ChainOrders& orders)
{
    const std::array<const std::vector<std::size_t>*, 3> given{&orders.load, &orders.memory,
                                                               &orders.init};
    std::array<std::vector<std::size_t>, 3> out;
    for (std::size_t c = 0; c < 3; ++c) {
        if (given[c]->empty()) {
            // no explicit order: every module, argument order
            out[c].resize(count);
            for (std::size_t i = 0; i < count; ++i) {
                out[c][i] = i;
            }
            continue;
        }
        // subset check: distinct in-range indices, never a silent drop or
        // duplicate member
        std::vector<bool> seen(count, false);
        for (const auto index : *given[c]) {
            if (index >= count || seen[index]) {
                return {};
            }
            seen[index] = true;
        }
        out[c] = *given[c];
    }
    return out;
}

} // namespace

std::expected<EnvironmentBuild, EnvNameTooLong>
build_environment(const std::uint64_t env_base, const std::uint64_t image_base,
                  const std::uint64_t stack_base, const std::uint64_t stack_limit,
                  const std::uint64_t heap_base, const std::vector<EnvModule>& modules,
                  const ChainOrders& orders)
{
    EnvironmentBuild build;
    build.teb_va = env_base + kEnvTebOffset;
    build.peb_va = env_base + kEnvPebOffset;
    build.params_va = env_base + kEnvParamsOffset;
    build.ldr_va = env_base + kEnvLdrOffset;
    build.module_count = modules.size();
    build.module_entry_vas.reserve(modules.size());
    for (std::size_t i = 0; i < modules.size(); ++i) {
        // x64 entry base = the InLoadOrderLinks node (ldr + 0x58 + i*stride)
        build.module_entry_vas.push_back(env_base + kEnvLdrOffset + 0x58 +
                                         i * static_cast<std::size_t>(kLdrEntryStride));
    }
    build.env.assign(static_cast<std::size_t>(kEnvBlockSize), 0);

    auto& env = build.env;
    const auto teb_va = env_base + kEnvTebOffset;
    const auto peb_va = env_base + kEnvPebOffset;

    // -- TEB page (env[0x0000..0x1000]) -- x64 TEB layout
    store64(env, 0x00, 0);                     // NtTib.ExceptionList
    store64(env, 0x08, stack_base);            // NtTib.StackBase
    store64(env, 0x10, stack_limit);           // NtTib.StackLimit
    store64(env, 0x30, teb_va);                // NtTib.Self (gs:[30h])
    store64(env, 0x38, 0x0000012400005678ULL); // ClientId
    store64(env, 0x60, peb_va);                // ProcessEnvironmentBlock

    // -- PEB page (env[0x1000..0x2000]) --
    store64(env, kEnvPebOffset + 0x10, image_base);               // ImageBaseAddress
    store64(env, kEnvPebOffset + 0x18, env_base + kEnvLdrOffset); // Ldr
    store64(env, kEnvPebOffset + 0x20, env_base + kEnvParamsOffset);
    store64(env, kEnvPebOffset + 0x30, heap_base); // ProcessHeap
    store32(env, kEnvPebOffset + 0xBC, 0);         // NtGlobalFlag
    env[kEnvPebOffset + 0x02] = 0;                 // BeingDebugged = 0

    // -- ProcessParameters page (env[0x2000..0x3000]) --
    store32(env, kEnvParamsOffset, 0x1000);

    // -- Ldr area (env[0x3000..0x13000]) --
    // PEB_LDR_DATA header
    store32(env, kEnvLdrOffset, 0x58); // Length
    env[kEnvLdrOffset + 4] = 1;        // Initialized
    // three closed circular chains, heads at ldr+0x10/0x20/0x30
    // nodes: module i chain c at ldr+0x58 + i*0x100 + c*0x10; each chain
    // threads the node slots in its own member order
    // list pointers are guest VAs (env_base + block offset), not offsets
    const std::size_t node_base = kEnvLdrOffset + 0x58;
    const auto node = [&](std::size_t i, std::size_t c) {
        return node_base + i * static_cast<std::size_t>(kLdrEntryStride) + c * 0x10;
    };
    const auto sequences = chain_sequences(modules.size(), orders);
    for (std::size_t c = 0; c < 3; ++c) {
        const auto head_off = kEnvLdrOffset + 0x10 + c * 0x10;
        const auto& sequence = sequences[c];
        if (modules.empty() || sequence.empty()) {
            // no members in this chain: every node self-loops
            for (std::size_t i = 0; i < modules.size(); ++i) {
                const auto nva = node(i, c);
                store64(env, nva, env_base + nva);
                store64(env, nva + 8, env_base + nva);
            }
            store64(env, head_off, env_base + head_off);
            store64(env, head_off + 8, env_base + head_off);
            continue;
        }
        store64(env, head_off, env_base + node(sequence.front(), c));
        store64(env, head_off + 8, env_base + node(sequence.back(), c));
        for (std::size_t p = 0; p < sequence.size(); ++p) {
            const auto nva = node(sequence[p], c);
            const auto next =
                p + 1 < sequence.size() ? node(sequence[p + 1], c) : head_off;
            const auto prev = p == 0 ? head_off : node(sequence[p - 1], c);
            store64(env, nva, env_base + next);
            store64(env, nva + 8, env_base + prev);
        }
        // members only: a module outside the chain keeps its node
        // self-looped (the walk never visits it)
        for (std::size_t i = 0; i < modules.size(); ++i) {
            if (std::find(sequence.begin(), sequence.end(), i) != sequence.end()) {
                continue;
            }
            const auto nva = node(i, c);
            store64(env, nva, env_base + nva);
            store64(env, nva + 8, env_base + nva);
        }
    }

    // -- per-module LDR_DATA_TABLE_ENTRY bodies --
    // entry base = block (InLoadOrderLinks); FullDllName at +0x48,
    // BaseDllName at +0x58 - both UNICODE_STRING {u16 len (bytes), u16 max,
    // pad, u64 buffer} over one shared UTF-16LE buffer at +0x80 (Length = 2
    // per character, MaximumLength adds the u16 NUL - the dll_loader runtime
    // insertions' and real captures' convention)
    for (std::size_t i = 0; i < modules.size(); ++i) {
        const auto block = node_base + i * static_cast<std::size_t>(kLdrEntryStride);
        store64(env, block + 0x30, modules[i].base); // DllBase
        store32(env, block + 0x40, modules[i].size); // SizeOfImage
        if (!store_utf16_name(env, block + 0x80, modules[i].name)) {
            return std::unexpected(EnvNameTooLong{modules[i].name});
        }
        const auto name_va = env_base + block + 0x80;
        const auto name_bytes = static_cast<std::uint16_t>(2 * modules[i].name.size());
        const auto full_bytes = static_cast<std::uint16_t>(name_bytes + 2);
        // FullDllName (entry + 0x48)
        store16(env, block + 0x48, name_bytes);
        store16(env, block + 0x4A, full_bytes);
        store64(env, block + 0x50, name_va);
        // BaseDllName (entry + 0x58) - aliases the same bytes
        store16(env, block + 0x58, name_bytes);
        store16(env, block + 0x5A, full_bytes);
        store64(env, block + 0x60, name_va);
    }

    return build;
}

std::expected<EnvironmentBuild, EnvNameTooLong>
build_environment_x86(const std::uint64_t env_base, const std::uint64_t image_base,
                      const std::uint64_t stack_base, const std::uint64_t stack_limit,
                      const std::uint64_t heap_base, const std::vector<EnvModule>& modules,
                      const ChainOrders& orders)
{
    EnvironmentBuild build;
    build.teb_va = env_base + kEnvTebOffset;
    build.peb_va = env_base + kEnvPebOffset;
    build.params_va = env_base + kEnvParamsOffset;
    build.ldr_va = env_base + kEnvLdrOffset;
    build.module_count = modules.size();
    build.module_entry_vas.reserve(modules.size());
    for (std::size_t i = 0; i < modules.size(); ++i) {
        // x86 entry base = the InLoadOrderLinks node (ldr + 0x30 + i*stride)
        build.module_entry_vas.push_back(env_base + kEnvLdrOffset + 0x30 +
                                         i * static_cast<std::size_t>(kLdrEntryStride));
    }
    build.env.assign(static_cast<std::size_t>(kEnvBlockSize), 0);

    auto& env = build.env;
    const auto teb_va = env_base + kEnvTebOffset;
    const auto peb_va = env_base + kEnvPebOffset;

    // -- TEB page (env[0x0000..0x1000]) -- x86 TEB layout, 4-byte NtTib
    // The initial ExceptionList is the 0xFFFFFFFF sentinel, not zero: the
    // x86 dispatcher's chain walk rejects a registration whose next points
    // at zero and never reaches the handlers.
    store32(env, 0x00, 0xFFFFFFFF);                              // NtTib.ExceptionList
    store32(env, 0x04, static_cast<std::uint32_t>(stack_base));  // NtTib.StackBase
    store32(env, 0x08, static_cast<std::uint32_t>(stack_limit)); // NtTib.StackLimit
    store32(env, 0x18, static_cast<std::uint32_t>(teb_va));      // NtTib.Self (fs:[18h])
    store32(env, 0x20, 0x00005678);                              // ClientId.UniqueProcess
    store32(env, 0x24, 0x00000124);                              // ClientId.UniqueThread
    store32(env, 0x30, static_cast<std::uint32_t>(peb_va));      // ProcessEnvironmentBlock

    // -- PEB page (env[0x1000..0x2000]) -- x86 PEB layout
    env[kEnvPebOffset + 0x02] = 0; // BeingDebugged = 0
    store32(env, kEnvPebOffset + 0x08, static_cast<std::uint32_t>(image_base));
    store32(env, kEnvPebOffset + 0x0C, static_cast<std::uint32_t>(env_base + kEnvLdrOffset));
    store32(env, kEnvPebOffset + 0x10, static_cast<std::uint32_t>(env_base + kEnvParamsOffset));
    store32(env, kEnvPebOffset + 0x18, static_cast<std::uint32_t>(heap_base));
    store32(env, kEnvPebOffset + 0x68, 0); // NtGlobalFlag

    // -- ProcessParameters page (env[0x2000..0x3000]) --
    store32(env, kEnvParamsOffset, 0x1000);

    // -- Ldr area (env[0x3000..0x13000]) --
    // PEB_LDR_DATA32 header: Length 0x30, Initialized; the three LIST_ENTRY32
    // heads sit at +0x0C/+0x14/+0x1C
    store32(env, kEnvLdrOffset, 0x30);
    env[kEnvLdrOffset + 4] = 1;
    // nodes: module i chain c at ldr+0x30 + i*0x100 + c*0x8; each chain
    // threads the node slots in its own member order; list pointers
    // are guest VAs truncated to 32 bits
    const std::size_t node_base = kEnvLdrOffset + 0x30;
    const auto node = [&](std::size_t i, std::size_t c) {
        return node_base + i * static_cast<std::size_t>(kLdrEntryStride) + c * 0x8;
    };
    const auto sequences = chain_sequences(modules.size(), orders);
    for (std::size_t c = 0; c < 3; ++c) {
        const auto head_off = kEnvLdrOffset + 0x0C + c * 0x8;
        const auto& sequence = sequences[c];
        if (modules.empty() || sequence.empty()) {
            // no members in this chain: every node self-loops
            for (std::size_t i = 0; i < modules.size(); ++i) {
                const auto nva = node(i, c);
                store32(env, nva, static_cast<std::uint32_t>(env_base + nva));
                store32(env, nva + 4, static_cast<std::uint32_t>(env_base + nva));
            }
            store32(env, head_off, static_cast<std::uint32_t>(env_base + head_off));
            store32(env, head_off + 4, static_cast<std::uint32_t>(env_base + head_off));
            continue;
        }
        store32(env, head_off,
                static_cast<std::uint32_t>(env_base + node(sequence.front(), c)));
        store32(env, head_off + 4,
                static_cast<std::uint32_t>(env_base + node(sequence.back(), c)));
        for (std::size_t p = 0; p < sequence.size(); ++p) {
            const auto nva = node(sequence[p], c);
            const auto next =
                p + 1 < sequence.size() ? node(sequence[p + 1], c) : head_off;
            const auto prev = p == 0 ? head_off : node(sequence[p - 1], c);
            store32(env, nva, static_cast<std::uint32_t>(env_base + next));
            store32(env, nva + 4, static_cast<std::uint32_t>(env_base + prev));
        }
        // members only: a module outside the chain keeps its node
        // self-looped (the walk never visits it)
        for (std::size_t i = 0; i < modules.size(); ++i) {
            if (std::find(sequence.begin(), sequence.end(), i) != sequence.end()) {
                continue;
            }
            const auto nva = node(i, c);
            store32(env, nva, static_cast<std::uint32_t>(env_base + nva));
            store32(env, nva + 4, static_cast<std::uint32_t>(env_base + nva));
        }
    }

    // -- per-module LDR_DATA_TABLE_ENTRY32 bodies --
    // entry base = block (InLoadOrderLinks); DllBase@0x18, SizeOfImage@0x20,
    // FullDllName@0x24, BaseDllName@0x2C - UNICODE_STRING32 {u16 len (bytes),
    // u16 max, u32 buffer} over one shared UTF-16LE buffer at +0x80 (same
    // byte-count conventions as the x64 entries and the runtime insertions)
    for (std::size_t i = 0; i < modules.size(); ++i) {
        const auto block = node_base + i * static_cast<std::size_t>(kLdrEntryStride);
        store32(env, block + 0x18, static_cast<std::uint32_t>(modules[i].base)); // DllBase
        store32(env, block + 0x20, modules[i].size);                             // SizeOfImage
        if (!store_utf16_name(env, block + 0x80, modules[i].name)) {
            return std::unexpected(EnvNameTooLong{modules[i].name});
        }
        const auto name_va = static_cast<std::uint32_t>(env_base + block + 0x80);
        const auto name_bytes = static_cast<std::uint16_t>(2 * modules[i].name.size());
        const auto full_bytes = static_cast<std::uint16_t>(name_bytes + 2);
        // FullDllName (entry + 0x24)
        store16(env, block + 0x24, name_bytes);
        store16(env, block + 0x26, full_bytes);
        store32(env, block + 0x28, name_va);
        // BaseDllName (entry + 0x2C) - aliases the same bytes
        store16(env, block + 0x2C, name_bytes);
        store16(env, block + 0x2E, full_bytes);
        store32(env, block + 0x30, name_va);
    }

    return build;
}

void fill_kuser_shared_data(std::span<std::uint8_t> page)
{
    if (page.size() < 0x400) {
        return;
    }
    constexpr std::uint64_t kFixedFileTime = 0x01D9000000000000ULL;
    std::memcpy(&page[0x14], &kFixedFileTime, 8);
    // NtSystemRoot: the fixed UTF-16 system root the capture world carries
    // (lowercase `c:\windows`, the capture spelling) - a shell's PEB walk
    // reads it, and a zero-filled field was a structural diff.
    constexpr char16_t kNtSystemRoot[] = u"c:\\windows";
    std::memcpy(&page[0x30], kNtSystemRoot, sizeof kNtSystemRoot);
    constexpr std::uint32_t kFixedTick = 0x10000000;
    std::memcpy(&page[0x320], &kFixedTick, 4);
}

} // namespace sheller::loader
