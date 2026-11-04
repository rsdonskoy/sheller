// Differential admission tests: the two runner-admission implementations -
// the Windows capture route (capture::admit_dll_sample) and the synthetic
// construction route (engine::admit_synth_dll_sample) - are one algorithm with
// one plan per corpus. This file is the safety net for that claim.
//
//   T1  the same corpus through both routes yields equal plans (Windows only:
//       the capture route needs real LoadLibraryExW and real system DLLs)
//   T2  the plan text (module / symbol / ordinal, in generation order) is
//       frozen against tests/data/admission-plans/*.plan; the synthetic route
//       is checked on every platform, which is the Linux CI's admission
//       coverage
//   T3  the rejection corpus (path-shaped name, missing symbol, collision with
//       the sample, unverifiable module) is refused by both routes; the two
//       routes' wording is deliberately different and is not compared
//
// The over-capacity cell of the assessment's T3 cannot be reached from sample
// bytes: capture::parse_imports bounds a sample at 64 module descriptors, so a
// plan carries at most 66 imports against a 96-entry runner capacity. The
// capacity check survives in the shared admission code as a guard; there is no
// corpus that drives it, and this file does not pretend otherwise.
//
// The fixture is a minimal x64 PE carrying an arbitrary import table: the
// admission reads the sample's import directory from file bytes and never maps
// the sample, so the rest of the image only has to be walkable.

#include "admission.h"
#include "craft_admission.h"
#include "wrapper.h"

#if defined(_WIN32)
#include "dll_admission.h"
#endif

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace fs = std::filesystem;
namespace capture = sheller::capture;
namespace engine = sheller::engine;

// ---- a minimal x64 PE with an arbitrary import table ---------------------

struct FixtureThunk {
    std::string symbol; // empty for a by-ordinal reference
    std::uint16_t ordinal{};
};

struct FixtureImport {
    std::string module;
    std::vector<FixtureThunk> thunks;
};

void put16(std::vector<std::uint8_t>& bytes, const std::size_t offset, const std::uint16_t value)
{
    bytes[offset] = static_cast<std::uint8_t>(value & 0xFF);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

void put32(std::vector<std::uint8_t>& bytes, const std::size_t offset, const std::uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) {
        bytes[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
}

void put64(std::vector<std::uint8_t>& bytes, const std::size_t offset, const std::uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) {
        bytes[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
}

constexpr std::uint32_t kSectionRva = 0x1000;
constexpr std::uint32_t kSectionRaw = 0x200;
constexpr std::size_t kPeHeaderOffset = 0x80;
constexpr std::size_t kOptionalHeaderOffset = 0x98;
constexpr std::size_t kSectionHeaderOffset = 0x188;

std::vector<std::uint8_t> make_import_sample(const std::vector<FixtureImport>& imports)
{
    // The section body starts at RVA 0x1000; descriptor table, ILT, IAT,
    // module names and hint/name entries follow in that order.
    const std::size_t descriptor_bytes = 20 * (imports.size() + 1);
    std::size_t slots = 0;
    for (const auto& import : imports) {
        slots += import.thunks.size() + 1;
    }
    const std::size_t ilt_offset = descriptor_bytes;
    const std::size_t iat_offset = ilt_offset + 8 * slots;

    std::vector<std::uint8_t> body(iat_offset + 8 * slots, 0);

    std::vector<std::size_t> name_offsets(imports.size(), 0);
    for (std::size_t d = 0; d < imports.size(); ++d) {
        name_offsets[d] = body.size();
        const auto& name = imports[d].module;
        body.insert(body.end(), name.begin(), name.end());
        body.push_back(0);
    }

    std::size_t slot = 0;
    for (const auto& import : imports) {
        for (const auto& thunk : import.thunks) {
            std::uint64_t value = 0;
            if (thunk.symbol.empty()) {
                value = 0x8000000000000000ull | thunk.ordinal;
            } else {
                const std::size_t hint_offset = body.size();
                body.push_back(0);
                body.push_back(0); // hint
                body.insert(body.end(), thunk.symbol.begin(), thunk.symbol.end());
                body.push_back(0);
                value = kSectionRva + static_cast<std::uint32_t>(hint_offset);
            }
            put64(body, ilt_offset + 8 * slot, value);
            put64(body, iat_offset + 8 * slot, value);
            ++slot;
        }
        ++slot; // this module's arrays terminate with a zero slot
    }

    slot = 0;
    for (std::size_t d = 0; d < imports.size(); ++d) {
        const std::size_t descriptor = 20 * d;
        put32(body, descriptor + 0,
              kSectionRva + static_cast<std::uint32_t>(ilt_offset + 8 * slot));
        put32(body, descriptor + 12, kSectionRva + static_cast<std::uint32_t>(name_offsets[d]));
        put32(body, descriptor + 16,
              kSectionRva + static_cast<std::uint32_t>(iat_offset + 8 * slot));
        slot += imports[d].thunks.size() + 1;
    }

    const std::size_t raw_size = (body.size() + kSectionRaw - 1) / kSectionRaw * kSectionRaw;
    std::vector<std::uint8_t> file(kSectionRaw + raw_size, 0);
    put16(file, 0, 0x5A4D);  // MZ
    put32(file, 0x3C, 0x80); // e_lfanew
    put32(file, kPeHeaderOffset, 0x00004550);
    put16(file, kPeHeaderOffset + 4, 0x8664); // AMD64
    put16(file, kPeHeaderOffset + 6, 1);      // one section
    put16(file, kPeHeaderOffset + 20, 0xF0);  // SizeOfOptionalHeader
    put16(file, kPeHeaderOffset + 22, 0x2022);
    put16(file, kOptionalHeaderOffset, 0x020B);                // PE32+
    put32(file, kOptionalHeaderOffset + 16, kSectionRva);      // entry point
    put32(file, kOptionalHeaderOffset + 24, 0x400000);         // image base
    put32(file, kOptionalHeaderOffset + 32, 0x1000);           // section alignment
    put32(file, kOptionalHeaderOffset + 36, kSectionRaw);      // file alignment
    put32(file, kOptionalHeaderOffset + 56, 0x2000);           // SizeOfImage
    put32(file, kOptionalHeaderOffset + 60, kSectionRaw);      // SizeOfHeaders
    put16(file, kOptionalHeaderOffset + 68, 3);                // console
    put32(file, kOptionalHeaderOffset + 108, 16);              // NumberOfRvaAndSizes
    put32(file, kOptionalHeaderOffset + 112 + 8, kSectionRva); // import directory
    put32(file, kOptionalHeaderOffset + 112 + 12, static_cast<std::uint32_t>(descriptor_bytes));
    std::memcpy(file.data() + kSectionHeaderOffset, ".text", 5);
    put32(file, kSectionHeaderOffset + 8, static_cast<std::uint32_t>(body.size()));
    put32(file, kSectionHeaderOffset + 12, kSectionRva);
    put32(file, kSectionHeaderOffset + 16, static_cast<std::uint32_t>(raw_size));
    put32(file, kSectionHeaderOffset + 20, kSectionRaw);
    put32(file, kSectionHeaderOffset + 36, 0x60000020); // CODE | EXECUTE | READ
    std::memcpy(file.data() + kSectionRaw, body.data(), body.size());
    return file;
}

// ---- corpus and plan helpers ---------------------------------------------

std::vector<std::uint8_t> read_bytes(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::string read_text(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

struct Sample {
    std::string arrival; // also the fixture/golden label
    std::vector<std::uint8_t> bytes;
};

fs::path packed_dll_path()
{
    return fs::path{SHELLER_SAMPLE_PACKED_DLL_PATH};
}

fs::path synth_module_dir()
{
    return fs::path{SYNTH_MODULE_DIR};
}

std::string golden_name(const std::string& arrival)
{
    constexpr std::string_view kDllSuffix = ".dll";
    if (arrival.size() > kDllSuffix.size() &&
        arrival.compare(arrival.size() - kDllSuffix.size(), kDllSuffix.size(), kDllSuffix) == 0) {
        return arrival.substr(0, arrival.size() - kDllSuffix.size());
    }
    return arrival;
}

// The real-DLL corpus: five samples over kernel32 (the base pair's module,
// imported but not re-planned), user32, ntdll, kernelbase, plus the production
// UPX-packed DLL. Every module name and symbol is a real system export; the
// references cover by-name and by-ordinal.
std::vector<Sample> corpus()
{
    std::vector<Sample> samples;
    samples.push_back({"packed.dll", read_bytes(packed_dll_path())});
    samples.push_back(
        {"kernel32_by_name.dll", make_import_sample({{"kernel32.dll", {{"GetTickCount", 0}}}})});
    samples.push_back(
        {"user32_by_name.dll", make_import_sample({{"user32.dll", {{"MessageBoxW", 0}}}})});
    samples.push_back({"ntdll_by_ordinal.dll", make_import_sample({{"ntdll.dll", {{"", 270}}}})});
    samples.push_back(
        {"kernelbase_by_name.dll", make_import_sample({{"kernelbase.dll", {{"CreateFileW", 0}}}})});
    return samples;
}

std::expected<capture::RunnerPlan, std::string> synth_plan(const Sample& sample)
{
    return engine::admit_synth_dll_sample(sample.bytes, sample.arrival, synth_module_dir());
}

std::string serialize_plan(const capture::RunnerPlan& plan)
{
    std::string text = "# " + plan.arrival_name + "\n";
    for (const auto& import : plan.imports) {
        text += import.module;
        text += '\t';
        text += import.symbol;
        text += '\t';
        text += std::to_string(import.ordinal);
        text += '\n';
    }
    return text;
}

#if defined(_WIN32)
std::expected<capture::RunnerPlan, std::string> windows_plan(const Sample& sample)
{
    return capture::admit_dll_sample(sample.bytes, sample.arrival);
}
#endif

// ---- the shared module-name fold -----------------------------------------

TEST(AdmissionFold, FoldsAsciiCaseOnly)
{
    EXPECT_EQ(capture::fold_module_name("KERNEL32.DLL"), "kernel32.dll");
    EXPECT_EQ(capture::fold_module_name("User32.Dll"), "user32.dll");
    EXPECT_EQ(capture::fold_module_name(""), "");
    // A byte outside ASCII is not locale-folded: the admission's names are
    // ASCII, and a host locale must not change an admission answer.
    EXPECT_EQ(capture::fold_module_name("\xC4"), "\xC4");
}

TEST(AdmissionFold, ComparesFoldedNamesWithoutMaterializingOne)
{
    EXPECT_TRUE(capture::fold_module_name_equals("USER32.dll", "user32.DLL"));
    EXPECT_TRUE(capture::fold_module_name_equals("", ""));
    EXPECT_FALSE(capture::fold_module_name_equals("user32.dll", "user32.dat"));
    EXPECT_FALSE(capture::fold_module_name_equals("user32.dll", "user32.dll "));
}

// ---- T1: both routes, one plan -------------------------------------------

#if defined(_WIN32)
TEST(AdmissionDiff, BothRoutesProduceTheSamePlan)
{
    for (const auto& sample : corpus()) {
        const auto windows = windows_plan(sample);
        const auto synth = synth_plan(sample);
        ASSERT_TRUE(windows.has_value()) << sample.arrival << ": " << windows.error();
        ASSERT_TRUE(synth.has_value()) << sample.arrival << ": " << synth.error();
        EXPECT_EQ(*windows, *synth) << "sample: " << sample.arrival;
    }
}
#endif

// ---- T2: the plan text is frozen -----------------------------------------

TEST(AdmissionDiff, PlanTextMatchesGolden)
{
    const fs::path golden_dir{ADMISSION_PLAN_DIR};
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996) // getenv is fine in a test
#endif
    const bool write_mode = std::getenv("SHELLER_ADMISSION_PLAN_WRITE") != nullptr;
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
    for (const auto& sample : corpus()) {
        const auto synth = synth_plan(sample);
        ASSERT_TRUE(synth.has_value()) << sample.arrival << ": " << synth.error();
        const std::string text = serialize_plan(*synth);
#if defined(_WIN32)
        // The capture route's plan is the production plan; the golden pins
        // that route's content too (T1 already pins it to the synthetic one).
        const auto windows = windows_plan(sample);
        ASSERT_TRUE(windows.has_value()) << sample.arrival << ": " << windows.error();
        EXPECT_EQ(serialize_plan(*windows), text) << "sample: " << sample.arrival;
#endif
        const fs::path golden = golden_dir / (golden_name(sample.arrival) + ".plan");
        if (write_mode) {
            std::error_code ec;
            fs::create_directories(golden_dir, ec);
            std::ofstream out(golden, std::ios::binary | std::ios::trunc);
            out << text;
            ASSERT_TRUE(out.good()) << "cannot write golden: " << golden.string();
            continue;
        }
        const std::string expected = read_text(golden);
        ASSERT_FALSE(expected.empty()) << "missing golden: " << golden.string()
                                       << " (run with SHELLER_ADMISSION_PLAN_WRITE=1 to create)";
        EXPECT_EQ(text, expected) << "sample: " << sample.arrival;
    }
}

// ---- T3: the two routes reject the same corpus ----------------------------

#if defined(_WIN32)
namespace {

struct RejectSample {
    std::string arrival;
    std::string expectation;
    std::vector<std::uint8_t> bytes;
};

std::vector<RejectSample> rejection_corpus()
{
    return {
        // path-shaped dependency name
        {"path_shape.dll", "path-shaped import name",
         make_import_sample({{"..\\evil.dll", {{"GetTickCount", 0}}}})},
        // dependency exists but does not export the referenced symbol
        {"missing_symbol.dll", "no importable export",
         make_import_sample({{"user32.dll", {{"ShellerNoSuchExport", 0}}}})},
        // dependency name collides with the sample's arrival name
        {"USER32.dll", "dependency name collides with the sample",
         make_import_sample({{"user32.dll", {{"MessageBoxW", 0}}}})},
        // a module no system search can verify
        {"unknown_module.dll", "not a verifiable system module",
         make_import_sample({{"sheller_private_module.dll", {{"GetTickCount", 0}}}})},
    };
}

} // namespace

TEST(AdmissionDiff, BothRoutesRejectTheSameCorpus)
{
    for (const auto& sample : rejection_corpus()) {
        const auto windows = capture::admit_dll_sample(sample.bytes, sample.arrival);
        const auto synth =
            engine::admit_synth_dll_sample(sample.bytes, sample.arrival, synth_module_dir());
        EXPECT_FALSE(windows.has_value())
            << "sample: " << sample.arrival << " (windows route accepted)";
        EXPECT_FALSE(synth.has_value())
            << "sample: " << sample.arrival << " (synth route accepted)";
        if (windows.has_value() || synth.has_value()) {
            ADD_FAILURE() << "expectation: " << sample.expectation;
        }
    }
}
#endif

} // namespace
