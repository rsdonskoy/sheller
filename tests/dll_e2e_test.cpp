// DLL-input route end-to-end (Windows): the acceptance line, pinned against
// the CLI. capture → unpack on the packed corpus must produce a loadable
// .unp whose entry point matches the upx -d reference (0x13E4) with the DLL
// flag intact and an import table matching the same reference (same modules,
// same by-name symbol sets), and --stop xfer=1 must stop at the stub's
// post-restore jump to that entry (the OEP dump stop). The live-capture
// replay chain lives in dll_capture_e2e_test.cpp: the captured world's
// payload is machine-sensitive past the OEP (the per-process entropy
// family), so those tests run outside the shared CI runners.

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

#ifdef _WIN32
#include "pe_headers.h"
#include <algorithm>
#include <cctype>
#include <map>
#include <vector>
#endif

namespace {

namespace fs = std::filesystem;

#ifdef _WIN32
constexpr std::string_view kCliCommand = SHELLER_CLI_FILE_NAME;
#else
constexpr std::string_view kCliCommand = "./" SHELLER_CLI_FILE_NAME;
#endif

std::string run_and_capture(std::string_view args)
{
    const auto out_path = sheller_test::temp_path("sheller_dll_e2e_out.txt").string();
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

fs::path packed_dll()
{
    return fs::path{SHELLER_SAMPLE_PACKED_DLL_PATH};
}

std::vector<std::uint8_t> read_bytes(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::uint32_t entry_rva_of(const std::vector<std::uint8_t>& pe)
{
    const auto e_lfanew =
        static_cast<std::uint32_t>(pe[0x3C]) | (static_cast<std::uint32_t>(pe[0x3D]) << 8);
    return static_cast<std::uint32_t>(pe[e_lfanew + 40]) |
           (static_cast<std::uint32_t>(pe[e_lfanew + 41]) << 8) |
           (static_cast<std::uint32_t>(pe[e_lfanew + 42]) << 16) |
           (static_cast<std::uint32_t>(pe[e_lfanew + 43]) << 24);
}

std::uint16_t characteristics_of(const std::vector<std::uint8_t>& pe)
{
    const auto e_lfanew =
        static_cast<std::uint32_t>(pe[0x3C]) | (static_cast<std::uint32_t>(pe[0x3D]) << 8);
    return static_cast<std::uint16_t>(pe[e_lfanew + 22]) |
           static_cast<std::uint16_t>(pe[e_lfanew + 23] << 8);
}

// The acceptance: capture → unpack on the packed corpus reproduces the
// reference unpack - the entry point (0x13E4 = the real DllMain), the DLL
// flag kept, and the import table rebuilt against the upx -d reference
// (details at the assertions below; no whole-image byte compare).
TEST(DllE2E, UnpackReproducesReferenceEntryPoint)
{
    const auto dir = sheller_test::temp_path("sheller_dll_e2e");
    fs::create_directories(dir);
    const auto output = dir / "packed.dll.unp";
    const auto result =
        run_and_capture(std::format("unpack \"{}\" -o \"{}\" -b 60M --timeout-ms 300000",
                                    packed_dll().string(), output.string()));
    ASSERT_EQ(result.substr(0, result.find('|')), "0") << result;
    ASSERT_TRUE(fs::exists(output));
    const auto bytes = read_bytes(output);
    ASSERT_GE(bytes.size(), 0x200u);
    EXPECT_EQ(entry_rva_of(bytes), 0x13E4u);
    EXPECT_NE(characteristics_of(bytes) & 0x2000, 0); // IMAGE_FILE_DLL kept

    // The repair audit: the unpacked image region lands complete with
    // nothing failed and no uncovered import thunks - the same operational
    // criterion the packed.exe corpus pins at the repair-pipeline level.
    EXPECT_NE(result.find("OEP 0x1800013e4 (rva 0x13e4) stamped"), std::string::npos) << result;
    const auto repair_value = [&result](std::string_view field) {
        const auto at = result.find(std::format("{}=", field));
        if (at == std::string::npos) {
            return -1;
        }
        return std::atoi(result.c_str() + at + field.size() + 1);
    };
    EXPECT_GE(repair_value("complete"), 1) << result;
    EXPECT_EQ(repair_value("failed"), 0) << result;
    EXPECT_EQ(repair_value("uncovered"), 0) << result;

    // The rebuilt import table: well-formed and non-empty, and the
    // reference's non-kernel32 dependencies survive intact. (A per-symbol
    // set compare against the upx -d reference would contradict the
    // documented resolution: the repair follows the host's export forwarder
    // chains, so the reference's KERNEL32.DLL entries legitimately split
    // across kernel32/kernelbase/ntdll - e.g. DeleteCriticalSection lands
    // as ntdll!RtlDeleteCriticalSection. user32 carries no forwarders.)
    const auto reference = read_bytes(packed_dll().parent_path() / "packed.dll.unp");
    ASSERT_GE(reference.size(), 0x200u);
    std::vector<sheller::capture::PeImportThunk> produced_thunks;
    std::vector<sheller::capture::PeImportThunk> reference_thunks;
    ASSERT_EQ(sheller::capture::parse_imports(bytes.data(), bytes.size(), produced_thunks),
              sheller::capture::PeError::kNone);
    ASSERT_EQ(sheller::capture::parse_imports(reference.data(), reference.size(), reference_thunks),
              sheller::capture::PeError::kNone);
    EXPECT_FALSE(produced_thunks.empty()) << "rebuilt .unp must carry an import table";
    const auto module_symbols = [](const std::vector<sheller::capture::PeImportThunk>& thunks) {
        std::map<std::string, std::vector<std::string>> table;
        for (const auto& thunk : thunks) {
            table[thunk.module].push_back(thunk.name.empty() ? "#" + std::to_string(thunk.ordinal)
                                                             : thunk.name);
        }
        for (auto& [module, symbols] : table) {
            std::sort(symbols.begin(), symbols.end());
        }
        return table;
    };
    const auto produced_table = module_symbols(produced_thunks);
    const auto reference_table = module_symbols(reference_thunks);
    for (const auto& [module, symbols] : reference_table) {
        std::string lower = module;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower == "kernel32.dll") {
            continue; // forwarder-host split: covered by the repair audit above
        }
        std::string key;
        for (const auto& [produced_module, produced_symbols] : produced_table) {
            std::string produced_lower = produced_module;
            std::transform(produced_lower.begin(), produced_lower.end(), produced_lower.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (produced_lower == lower) {
                key = produced_module;
            }
        }
        EXPECT_NE(key, "") << "rebuilt .unp lost reference module " << module;
        if (!key.empty()) {
            EXPECT_EQ(produced_table.at(key), symbols)
                << "rebuilt .unp import set drifted from the reference for " << module;
        }
    }
}

// The usable stop face on the packed DLL: --stop xfer=1 stops before the
// landing block of the stub's post-restore jump to the unpacked entry (the
// first counted transfer - the OEP dump stop). The esp faces on this stub
// are a documented silent miss (see dll_capture_e2e_test.cpp).
TEST(DllE2E, Xfer1StopsAtTheOepTransfer)
{
    const auto dir = sheller_test::temp_path("sheller_dll_e2e_xfer");
    fs::create_directories(dir);
    const auto output = dir / "xfer.dll.unp";
    const auto result =
        run_and_capture(std::format("unpack \"{}\" -o \"{}\" --stop xfer=1 -b 60M --timeout-ms"
                                    " 300000",
                                    packed_dll().string(), output.string()));
    ASSERT_EQ(result.substr(0, result.find('|')), "0") << result;
    EXPECT_NE(result.find("xfer target reached (xfers=1)"), std::string::npos) << result;
    EXPECT_NE(result.find("terminated=0"), std::string::npos) << result;
    EXPECT_TRUE(fs::exists(output)); // the OEP-face dump
}

// The captured-world replay is a pure function of (container bytes, engine,
// options): two independent CLI processes replaying one container must write
// byte-identical reports. The per-process entropy leak used to flap this red
// across ctest rounds before it was adopted into the deterministic answer
// face. Pin
// discipline: no wall clock is set (a timeout-driven stop is a
// nondeterministic abort and the engine never arms one at 0 ms), and the
// compare runs only after the deterministic termination (terminated=1).
TEST(DllE2E, ReplayReportIsIdenticalAcrossProcesses)
{
    const auto dir = sheller_test::temp_path("sheller_dll_e2e_determinism");
    fs::create_directories(dir);
    const auto snap = dir / "packed_dll_v2.snap";
    ASSERT_EQ(run_and_capture(
                  std::format("capture \"{}\" -o \"{}\"", packed_dll().string(), snap.string()))
                  .substr(0, 1),
              "0");
    ASSERT_TRUE(fs::exists(snap));
    const auto replay = [&dir, &snap](const std::string_view tag) {
        const auto report = dir / std::format("replay_{}.report.json", tag);
        const auto result =
            run_and_capture(std::format("run --from-snapshot \"{}\" --report \"{}\" -b 0M"
                                        " --timeout-ms 0",
                                        snap.string(), report.string()));
        EXPECT_EQ(result.substr(0, result.find('|')), "0") << result;
        EXPECT_NE(result.find("terminated=1"), std::string::npos) << result;
        return report;
    };
    const auto first = replay("a");
    const auto second = replay("b");
    ASSERT_TRUE(fs::exists(first));
    ASSERT_TRUE(fs::exists(second));
    EXPECT_EQ(read_bytes(first), read_bytes(second))
        << "cross-process replay reports differ on one container";
}

#endif // _WIN32

} // namespace
