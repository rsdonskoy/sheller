// Loader by-hash shellcode e2e: the NASM-assembled blob
// (tests/corpus/byhash_shell.asm -> byhash_shell.bin) walks the PEB->Ldr
// triple-chain and verifies the MZ signature at each module's DllBase.
// Exit code = the number of valid modules found. Loaded through run_pe_file
// to validate the loader environment construction.

#include "wrapper.h"

#include <sheller/peloader.h>
#include <sheller/syscallrun.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>

namespace fs = std::filesystem;

namespace {

// Advapi32 joined the resident module set (the
// loader route maps ntdll/kernel32/kernelbase/advapi32 for x64); user32
// followed later (the packed-DLL corpus's second import
// module, frozen manifest user32.x64.json).
constexpr std::uint32_t kExpectedModuleCount = 6;

std::vector<std::uint8_t> read_blob(const char* path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

} // namespace

TEST(LoaderByHashE2E, LdrWalkMzVerifyAndCount)
{
    const auto blob = read_blob(SHELLER_BYHASH_BIN);
    ASSERT_FALSE(blob.empty()) << "missing " << SHELLER_BYHASH_BIN;

    const auto dir = fs::temp_directory_path() / "sheller_byhash_e2e";
    fs::create_directories(dir);
    const auto pe_path = dir / "byhash_pe.exe";

    const auto wrapped = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX64, blob);
    ASSERT_TRUE(wrapped.has_value());
    {
        std::ofstream out(pe_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(wrapped->data()),
                  static_cast<std::streamsize>(wrapped->size()));
    }

    sheller::engine::SyscallRunOptions options;
    options.max_blocks = 100000;
    options.timeout_ms = 30000;

    const auto stats = sheller::engine::run_pe_file(pe_path, options);
    if (!stats.has_value()) {
        std::printf("byhash e2e error=%d ucode=%u blocks=%llu\n",
                    static_cast<int>(stats.error().error), stats.error().unicorn_code,
                    static_cast<unsigned long long>(stats.error().stats.blocks));
    }
    ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, kExpectedModuleCount);
}
