// Boundary description seed: the
// codegen is deterministic (same manifest in, byte-identical .inc out), the
// committed seed stays fresh (regenerated output equals the checked-in
// file - editing a manifest JSON without regenerating fails here), and the
// committed table compiles standalone with the pinned fixture binding.
// Portable by design (no unicorn, no engine link).

#include "boundary_seed.inc"

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

namespace seed = sheller::engine::boundary_seed;

constexpr const char* kGenScript = BOUNDARY_GEN_SCRIPT;
constexpr const char* kManifestDir = BOUNDARY_MANIFEST_DIR;
constexpr const char* kCommittedSeed = BOUNDARY_SEED;
constexpr const char* kPython = BOUNDARY_PYTHON;

std::vector<std::uint8_t> read_file(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

int run_generator(const fs::path& out_file)
{
    const std::string cmd = std::string(kPython) + " \"" + kGenScript + "\" \"" + kManifestDir +
                            "\" \"" + out_file.string() + "\"";
    return std::system(cmd.c_str());
}

} // namespace

TEST(BoundarySeed, GenerationIsDeterministicAndFresh)
{
    const auto dir = fs::temp_directory_path() / "sheller_boundary_seed_det";
    fs::create_directories(dir);
    const auto first = dir / "first.inc";
    const auto second = dir / "second.inc";
    ASSERT_EQ(run_generator(first), 0);
    ASSERT_EQ(run_generator(second), 0);
    const auto a = read_file(first);
    const auto b = read_file(second);
    ASSERT_FALSE(a.empty());
    EXPECT_EQ(a, b) << "the same manifest must generate byte-identical output";
    const auto committed = read_file(kCommittedSeed);
    ASSERT_FALSE(committed.empty());
    EXPECT_EQ(a, committed) << "the committed boundary_seed.inc is stale - regenerate it (see the "
                               "file header for the command)";
}

TEST(BoundarySeed, CommittedTableBindsTheFixtureImage)
{
    // two registered builds for ntdll.dll/x64: the fixture corpus and a real
    // Windows build (each with its own export rows, selected by hash)
    ASSERT_EQ(std::size(seed::kModules), 2u);
    const auto& ntdll = seed::kModules[0];
    EXPECT_STREQ(ntdll.module, "ntdll.dll");
    EXPECT_STREQ(ntdll.arch, "x64");
    ASSERT_EQ(ntdll.image_count, 1u);
    // tests/boundary_fixture.h: the self-made mechanism-corpus ntdll image
    EXPECT_EQ(ntdll.images[0].xxhash64, 0x6c806f42b18c5f46ULL);
    ASSERT_EQ(ntdll.export_count, 8u);
    // spot the classification kinds the derive consumes
    EXPECT_EQ(ntdll.exports[0].kind, seed::kSeedSyscallStub);
    EXPECT_EQ(ntdll.exports[4].kind, seed::kSeedTrap);
    EXPECT_EQ(ntdll.exports[5].kind, seed::kSeedData);
    EXPECT_STREQ(ntdll.exports[5].data_hex, "1020304050607080");
    // unnamed exports carry an empty name and their ordinal
    EXPECT_STREQ(ntdll.exports[6].name, "");
    EXPECT_EQ(ntdll.exports[6].ordinal, 5u);
}
