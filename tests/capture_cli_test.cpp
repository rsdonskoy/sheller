// CLI-level capture tests: the positive path on Windows is the
// acceptance invocation (snapshot produced from a sample through the CLI);
// negative paths are checked on every platform.

#include <gtest/gtest.h>

#ifdef _WIN32
#include <sheller/snapshot.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#endif

#include "test_temp.hpp"
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>

namespace {

namespace fs = std::filesystem;

// POSIX shells do not search the current directory; cmd.exe does. The test's
// working directory is the CLI directory, so prefix ./ only where it is needed.
#ifdef _WIN32
constexpr std::string_view kCliCommand = SHELLER_CLI_FILE_NAME;
#else
constexpr std::string_view kCliCommand = "./" SHELLER_CLI_FILE_NAME;
#endif

// Runs the CLI with the given args (output captured), returns "rc|output".
// The capture file is a per-process temp path: every CLI suite runs with its
// working directory set to the CLI directory, so a fixed name here lets
// concurrent ctest jobs clobber each other's output.
std::string run_and_capture(std::string_view args)
{
    const auto out_path = sheller_test::temp_path("sheller_capture_cli_out.txt").string();
    const auto cmd = std::format("{} {} > \"{}\" 2>&1", kCliCommand, args, out_path);
    const auto exit_code = std::system(cmd.c_str());
    std::ifstream file(out_path);
    const std::string output((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
    std::error_code ec;
    fs::remove(out_path, ec);
    return std::format("{}|{}", exit_code, output);
}

#ifdef _WIN32

TEST(CaptureCli, ProducesSnapshotOnWindows)
{
    const auto dir = sheller_test::temp_path("sheller_capture_cli_test");
    fs::create_directories(dir);
    const auto output = dir / "cli_plain.snap";

    const auto result = run_and_capture(
        std::format("capture \"{}\" -o \"{}\"", SHELLER_CAPTURE_SAMPLE_PATH, output.string()));
    EXPECT_EQ(result.substr(0, result.find('|')), "0") << result;
    EXPECT_TRUE(fs::exists(output));

    std::ifstream in(output, std::ios::binary);
    sheller::snapshot::Reader reader{in};
    const auto header = reader.read_header();
    ASSERT_TRUE(header.has_value());
    EXPECT_EQ(header->version, sheller::snapshot::kVersionV3); // production path pins the clock
    EXPECT_EQ(header->bitness, sheller::snapshot::kBitness64);
}

TEST(CaptureCli, PeLookingJunkStillRejectedWithReason)
{
    const auto dir = sheller_test::temp_path("sheller_capture_cli_test");
    fs::create_directories(dir);
    const auto sample = dir / "cli_junk.exe";
    {
        std::ofstream out(sample, std::ios::binary | std::ios::trunc);
        out << "MZ\x0D\x0Astill not a PE"; // PE-looking: the blob wrapper must not engage
    }
    const auto result = run_and_capture(
        std::format("capture \"{}\" -o \"{}\"", sample.string(), (dir / "cli_junk.snap").string()));
    EXPECT_NE(result.substr(0, result.find('|')), "0") << result;
    EXPECT_NE(result.find("PE"), std::string::npos) << result;
}

#else

TEST(CaptureCli, RefusedOnNonWindowsHost)
{
    const auto result = run_and_capture("capture whatever.exe -o whatever.snap");
    EXPECT_NE(result.substr(0, result.find('|')), "0") << result;
    EXPECT_NE(result.find("only supported on Windows"), std::string::npos) << result;
}

#endif

TEST(CaptureCli, MissingSampleExitsNonZero)
{
    const auto result = run_and_capture("capture sheller_missing_sample.exe -o missing.snap");
    EXPECT_NE(result.substr(0, result.find('|')), "0") << result;
}

TEST(CaptureCli, MissingOutputOptionExitsNonZero)
{
    const auto result = run_and_capture("capture whatever.exe");
    EXPECT_NE(result.substr(0, result.find('|')), "0") << result;
}

} // namespace
