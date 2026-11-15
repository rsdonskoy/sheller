// x86 environment construction unit tests: byte-level checks of the
// 32-bit TEB/PEB/Ldr shapes against the pinned SysWOW64 offsets.

#include "env.h"

#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

namespace {

using namespace sheller::loader;

std::uint32_t peek32(const std::vector<std::uint8_t>& bytes, std::size_t offset)
{
    std::uint32_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof value);
    return value;
}

std::uint16_t peek16(const std::vector<std::uint8_t>& bytes, std::size_t offset)
{
    std::uint16_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof value);
    return value;
}

TEST(LoaderEnvX86, TebPebLayoutAndDeterminism)
{
    const std::uint64_t env_base = 0x02000000;
    const std::vector<EnvModule> modules{{0x400000, 0x2000, "sample.exe"},
                                         {0x77000000, 0x160000, "ntdll.dll"}};
    const auto build =
        build_environment_x86(env_base, 0x400000, 0x300000, 0x200000, 0x4000000, modules).value();

    EXPECT_EQ(build.teb_va, env_base);
    EXPECT_EQ(build.peb_va, env_base + 0x1000);
    EXPECT_EQ(build.module_count, 2U);
    EXPECT_EQ(build.env.size(), kEnvBlockSize);

    // TEB32: Self@0x18, ClientId@0x20, PEB@0x30
    EXPECT_EQ(peek32(build.env, 0x18), static_cast<std::uint32_t>(build.teb_va));
    EXPECT_EQ(peek32(build.env, 0x20), 0x5678U);
    EXPECT_EQ(peek32(build.env, 0x24), 0x124U);
    EXPECT_EQ(peek32(build.env, 0x30), static_cast<std::uint32_t>(build.peb_va));
    // NtTib stack shape (4-byte fields)
    EXPECT_EQ(peek32(build.env, 0x04), 0x300000U);
    EXPECT_EQ(peek32(build.env, 0x08), 0x200000U);

    // PEB32: ImageBase@0x08, Ldr@0x0C, Params@0x10, Heap@0x18, NtGlobalFlag@0x68
    const auto peb = kEnvPebOffset;
    EXPECT_EQ(peek32(build.env, peb + 0x08), 0x400000U);
    EXPECT_EQ(peek32(build.env, peb + 0x0C), static_cast<std::uint32_t>(env_base + 0x3000));
    EXPECT_EQ(peek32(build.env, peb + 0x10), static_cast<std::uint32_t>(env_base + 0x2000));
    EXPECT_EQ(peek32(build.env, peb + 0x18), 0x4000000U);
    EXPECT_EQ(build.env[peb + 0x02], 0);          // BeingDebugged
    EXPECT_EQ(peek32(build.env, peb + 0x68), 0U); // NtGlobalFlag

    // determinism: same input, same bytes
    const auto again =
        build_environment_x86(env_base, 0x400000, 0x300000, 0x200000, 0x4000000, modules).value();
    EXPECT_EQ(build.env, again.env);
}

TEST(LoaderEnvX86, LdrTripleChainWalksWithNodeShape)
{
    const std::uint64_t env_base = 0x02000000;
    const std::vector<EnvModule> modules{{0x400000, 0x2000, "sample.exe"},
                                         {0x77000000, 0x160000, "ntdll.dll"},
                                         {0x76000000, 0x150000, "kernelbase.dll"},
                                         {0x75000000, 0xF0000, "kernel32.dll"}};
    const auto build =
        build_environment_x86(env_base, 0x400000, 0x300000, 0x200000, 0x4000000, modules).value();

    const auto ldr = kEnvLdrOffset;
    EXPECT_EQ(peek32(build.env, ldr), 0x30U); // PEB_LDR_DATA32 length
    EXPECT_EQ(build.env[ldr + 4], 1);         // Initialized

    // walk the in-memory-order chain (head at ldr+0x14), mirroring an x86
    // by-hash shell: node -> entry base = node-0x08, so DllBase (entry+0x18)
    // sits at node+0x10, SizeOfImage (entry+0x20) at node+0x18
    const auto head = ldr + 0x14;
    const auto head_va = static_cast<std::uint32_t>(env_base + head);
    auto cursor = peek32(build.env, head);
    std::size_t visited = 0;
    while (visited < modules.size() + 1 && cursor != head_va) {
        const auto node_off = cursor - static_cast<std::uint32_t>(env_base);
        ASSERT_LT(node_off, kEnvBlockSize);
        const auto dll_base = peek32(build.env, node_off + 0x10);
        EXPECT_EQ(dll_base, modules[visited].base) << "module " << visited;
        const auto size_of_image = peek32(build.env, node_off + 0x18);
        EXPECT_EQ(size_of_image, modules[visited].size) << "module " << visited;
        // BaseDllName UNICODE_STRING32 at entry+0x2C = node+0x24: Length
        // counts bytes (2 per character), the UTF-16 buffer convention
        EXPECT_EQ(peek16(build.env, node_off + 0x24),
                  static_cast<std::uint16_t>(2 * modules[visited].name.size()));
        cursor = peek32(build.env, node_off);
        ++visited;
    }
    EXPECT_EQ(visited, modules.size());
    // the chain closed back onto the head
    EXPECT_EQ(cursor, head_va);
}

TEST(LoaderEnvX86, LdrEntryNamesAreUtf16WithByteLengths)
{
    // the same name conventions as x64 and the runtime insertions: one
    // UTF-16LE buffer + u16 NUL, both UNICODE_STRING32 lengths in bytes
    const std::uint64_t env_base = 0x02000000;
    const std::vector<EnvModule> modules{{0x400000, 0x2000, "sample.exe"}};
    const auto build =
        build_environment_x86(env_base, 0x400000, 0x300000, 0x200000, 0x4000000, modules).value();
    // entry base = the InLoadOrderLinks node (ldr + 0x30)
    const auto block = static_cast<std::size_t>(kEnvLdrOffset) + 0x30;
    const auto length = static_cast<std::uint16_t>(2 * modules[0].name.size());
    EXPECT_EQ(peek16(build.env, block + 0x24), length); // FullDllName.Length
    EXPECT_EQ(peek16(build.env, block + 0x26), length + 2);
    EXPECT_EQ(peek16(build.env, block + 0x2C), length); // BaseDllName.Length
    EXPECT_EQ(peek16(build.env, block + 0x2E), length + 2);
    // the buffer: UTF-16LE text, u16 NUL, nothing spills past the pair
    for (std::size_t c = 0; c < modules[0].name.size(); ++c) {
        EXPECT_EQ(build.env[block + 0x80 + 2 * c], static_cast<std::uint8_t>(modules[0].name[c]))
            << "char " << c;
        EXPECT_EQ(build.env[block + 0x80 + 2 * c + 1], 0) << "char " << c;
    }
    EXPECT_EQ(build.env[block + 0x80 + length], 0);
    EXPECT_EQ(build.env[block + 0x80 + length + 1], 0);
}

TEST(LoaderEnvX86, OverlongEntryNameIsANamedRefusal)
{
    // exactly 64 characters need 130 bytes and the +0x80 buffer holds 0x80:
    // named refusal, never a truncation
    const std::uint64_t env_base = 0x02000000;
    const std::vector<EnvModule> modules{{0x400000, 0x2000, std::string(60, 'a') + ".dll"}};
    const auto refused =
        build_environment_x86(env_base, 0x400000, 0x300000, 0x200000, 0x4000000, modules);
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().name, modules[0].name);
}

TEST(LoaderEnvX86, ExactlyFullEntryNameStillBuilds)
{
    // 63 characters need 2*63+2 = 0x80 bytes: exactly the +0x80 buffer, so
    // the refusal guard stays exclusive - one more char (the 64-char refusal
    // above) is what flips it
    const std::uint64_t env_base = 0x02000000;
    const std::vector<EnvModule> modules{{0x400000, 0x2000, std::string(63, 'a')}};
    const auto build =
        build_environment_x86(env_base, 0x400000, 0x300000, 0x200000, 0x4000000, modules).value();
    const auto block = static_cast<std::size_t>(kEnvLdrOffset) + 0x30;
    EXPECT_EQ(peek16(build.env, block + 0x24), 126); // FullDllName.Length
    EXPECT_EQ(peek16(build.env, block + 0x26), 128);
    EXPECT_EQ(peek16(build.env, block + 0x2C), 126); // BaseDllName.Length
    EXPECT_EQ(peek16(build.env, block + 0x2E), 128);
    // the shared buffer is exactly full: the u16 NUL lands on its last two bytes
    EXPECT_EQ(build.env[block + 0x80 + 0xFE], 0);
    EXPECT_EQ(build.env[block + 0x80 + 0xFF], 0);
}

} // namespace
