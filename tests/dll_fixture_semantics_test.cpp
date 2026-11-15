// DLL-input route semantics over a hand-built fixture:
// a tiny x64 DLL with two relocation-covered TLS callbacks, a push-prefixed
// DllMain and one kernel32!ExitProcess import, crafted into a runner-world
// container (the fixture's preferred base 0x400000 collides with the
// runner's mapped slot, so every load takes the rebase path). The guest
// writes markers into its own .data, so the dump carries the observable
// facts: TLS callbacks ran in directory order before DllMain, the ATTACH
// frame passed (rcx=base, rdx=1, [rsp]=resume slot), and the esp monitor
// re-armed at DllMain's save window.
//
// Fixture marker layout (all RVA .data 0x2000-based):
//   +0x00 dword  0xC0FFEE01  DllMain entered
//   +0x04 dword  reason (rdx)
//   +0x08 qword  base (rcx)
//   +0x10 qword  [rsp] at DllMain entry (the resume slot)
//   +0x18 byte   0xA1 written by callback 1
//   +0x19 byte   0xA2 written by callback 2
//   +0x1C byte   order: callback 1 adds 1, callback 2 adds 2 (3 = in order)

#include "craft.h"

#include <sheller/snapshot.h>
#include <sheller/syscallrun.h>

#include "behavior_fact.h"
#include "minimal_pe.h"
#include "pe_headers.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "test_temp.hpp"

namespace {

namespace fs = std::filesystem;
namespace engine = sheller::engine;
namespace capture = sheller::capture;

fs::path synth_dir()
{
    return SYNTH_MODULE_DIR;
}

constexpr std::uint32_t kDataRva = 0x2000;
constexpr std::uint32_t kCallback1Rva = 0x1100;
constexpr std::uint32_t kCallback2Rva = 0x1120;
constexpr std::uint32_t kIatRva = 0x1460;

enum class Variant {
    kTrue,
    kFalse,
    kExit42,
    kNoEntry,        // AddressOfEntryPoint == 0: legal loadable, no init body
    kTlsOutside,     // a TLS callback target outside the module image
    kTlsUnterminated // the callback array runs to the image end without NUL
};

std::vector<std::uint8_t> make_fixture_dll(const Variant variant)
{
    std::vector<std::uint8_t> image(0x4000, std::uint8_t{0});
    auto* const base = image.data();
    const auto at = [&](const std::uint32_t rva) { return base + rva; };
    const auto put32 = [&](const std::uint32_t rva, const std::uint32_t value) {
        for (unsigned i = 0; i < 4; ++i) {
            at(rva)[i] = static_cast<std::uint8_t>(value >> (8 * i));
        }
    };
    const auto put64 = [&](const std::uint32_t rva, const std::uint64_t value) {
        for (unsigned i = 0; i < 8; ++i) {
            at(rva)[i] = static_cast<std::uint8_t>(value >> (8 * i));
        }
    };
    const auto put16 = [&](const std::uint32_t rva, const std::uint16_t value) {
        at(rva)[0] = static_cast<std::uint8_t>(value);
        at(rva)[1] = static_cast<std::uint8_t>(value >> 8);
    };
    const auto put_str = [&](const std::uint32_t rva, const std::string_view text) {
        std::memcpy(at(rva), text.data(), text.size());
        at(rva + static_cast<std::uint32_t>(text.size()))[0] = 0;
    };
    constexpr std::uint64_t kPreferredBase = 0x400000;

    auto& dos = *reinterpret_cast<sheller::capture::DosHeader*>(base);
    dos.e_magic = sheller::capture::kMzSignature;
    dos.e_lfanew = 0x80;
    const std::uint32_t nt = static_cast<std::uint32_t>(dos.e_lfanew);
    put32(nt, sheller::capture::kPeSignature);
    put16(nt + 4, sheller::capture::kMachineAmd64);
    put16(nt + 6, 3); // sections: .text .data .reloc
    put16(nt + 20, sizeof(sheller::capture::OptionalHeader64));
    put16(nt + 22, 0x2002); // EXECUTABLE_IMAGE | IMAGE_FILE_DLL

    const std::uint32_t opt = nt + 24;
    put16(opt, sheller::capture::kPe32PlusMagic);
    put32(opt + 16, variant == Variant::kNoEntry ? 0 : 0x1000); // entry = DllMain
    put32(opt + 20, 0x1000);
    put64(opt + 24, kPreferredBase);
    put32(opt + 32, 0x1000);
    put32(opt + 36, 0x1000);
    put32(opt + 56, 0x4000); // SizeOfImage
    put32(opt + 60, 0x1000);
    put16(opt + 68, 3);
    put32(opt + 108, 16); // NumberOfRvaAndSizes
    const std::uint32_t dirs = opt + 112;
    put32(dirs + 1 * 8, 0x14A0); // import descriptors
    put32(dirs + 1 * 8 + 4, 40);
    put32(dirs + 5 * 8, 0x3000); // basereloc
    put32(dirs + 5 * 8 + 4, 22);
    put32(dirs + 9 * 8, 0x1400); // TLS
    put32(dirs + 9 * 8 + 4, sizeof(sheller::capture::TlsDirectory64));
    put32(dirs + 12 * 8, kIatRva); // IAT (IMAGE_DIRECTORY_ENTRY_IAT = 12; the
    put32(dirs + 12 * 8 + 4, 8);   // delay-import slot 13 stays zero for the
                                   // eager binding's descriptor walk)

    const auto sect = base + opt + sizeof(sheller::capture::OptionalHeader64);
    const auto write_section = [&](const unsigned index, const char* const name,
                                   const std::uint32_t rva, const std::uint32_t characteristics) {
        auto& header = *reinterpret_cast<sheller_test::SectionHeader*>(sect + index * 40);
        header = sheller_test::SectionHeader{
            .name = {static_cast<std::uint8_t>(name[0]), static_cast<std::uint8_t>(name[1]),
                     static_cast<std::uint8_t>(name[2]), static_cast<std::uint8_t>(name[3]),
                     static_cast<std::uint8_t>(name[4]), 0, 0, 0},
            .virtual_size = 0x1000,
            .virtual_address = rva,
            .size_of_raw_data = 0x1000,
            .pointer_to_raw_data = rva,
            .pointer_to_relocations = 0,
            .pointer_to_linenumbers = 0,
            .number_of_relocations = 0,
            .number_of_linenumbers = 0,
            .characteristics = characteristics};
    };
    write_section(0, ".text", 0x1000, 0x60000020);
    write_section(1, ".data", kDataRva, 0xC0000040);
    write_section(2, ".reloc", 0x3000, 0x42000040);

    // --- code: DllMain at 0x1000, callbacks at 0x1100/0x1120 -------------
    {
        // A tiny cursor-tracked x64 emitter: each rip-relative helper knows
        // its own instruction length, so the displacement arithmetic cannot
        // drift from the stream layout.
        std::vector<std::uint8_t> code;
        std::uint32_t cursor = 0x1000; // the RVA the next emitted byte lands at
        const auto emit = [&](const std::initializer_list<std::uint8_t> bytes) {
            for (const std::uint8_t b : bytes) {
                code.push_back(b);
                ++cursor;
            }
        };
        const auto emit32 = [&](const std::uint32_t v) {
            for (unsigned i = 0; i < 4; ++i) {
                code.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
                ++cursor;
            }
        };
        // mov [rip+d], rcx  (48 89 0d disp32 - 7 bytes total)
        const auto store_rcx = [&](const std::uint32_t target) {
            emit({0x48, 0x89, 0x0D});
            emit32(target - cursor - 4); // rip sits past the disp32
        };
        // mov rax, [rsp+0x10]  (5 bytes - the resume slot sits past the
        // fixture's own two pushes)
        const auto load_rax_rsp = [&]() { emit({0x48, 0x8B, 0x44, 0x24, 0x10}); };
        // mov [rip+d], rax  (7 bytes)
        const auto store_rax = [&](const std::uint32_t target) {
            emit({0x48, 0x89, 0x05});
            emit32(target - cursor - 4); // rip sits past the disp32
        };
        // mov dword [rip+d], imm32  (10 bytes)
        const auto store_imm32 = [&](const std::uint32_t target, const std::uint32_t value) {
            emit({0xC7, 0x05});
            emit32(target - (cursor + 8)); // rip sits past disp32 + imm32
            emit32(value);
        };
        // push rbp; push rdi - the entry's contiguous push prefix (extent 16)
        emit({0x55, 0x57});
        store_rcx(kDataRva + 0x08); // the ATTACH base argument
        load_rax_rsp();             // the resume slot the frame pushed
        store_rax(kDataRva + 0x10);
        store_imm32(kDataRva, 0xC0FFEE01); // DllMain entered
        store_imm32(kDataRva + 0x04, 1);   // DLL_PROCESS_ATTACH seen
        // pop rdi; pop rbp - the completed restore (the esp stop's landing read)
        emit({0x5F, 0x5D});
        if (variant == Variant::kExit42) {
            // mov ecx, 42 (5 bytes); call qword [rip+d] (6 bytes) - the
            // IAT-bound ExitProcess
            emit({0xB9});
            emit32(42);
            emit({0xFF, 0x15});
            emit32(kIatRva - cursor - 4);
        }
        // mov eax, 1 (TRUE) / xor eax, eax (FALSE or post-call fall-through)
        if (variant == Variant::kTrue) {
            emit({0xB8});
            emit32(1);
        } else {
            emit({0x31, 0xC0});
        }
        emit({0xC3});
        std::memcpy(at(0x1000), code.data(), code.size());
    }
    {
        const auto emit_callback = [&](const std::uint32_t rva, const std::uint8_t marker,
                                       const std::uint8_t addend, const std::uint32_t marker_slot,
                                       const std::uint32_t order_slot) {
            std::vector<std::uint8_t> cb;
            std::uint32_t cursor = rva;
            const auto emit = [&](const std::initializer_list<std::uint8_t> bytes) {
                for (const std::uint8_t b : bytes) {
                    cb.push_back(b);
                    ++cursor;
                }
            };
            const auto emit32 = [&](const std::uint32_t v) {
                for (unsigned i = 0; i < 4; ++i) {
                    cb.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
                    ++cursor;
                }
            };
            // mov byte [rip+d], imm8 (7 bytes); add byte [rip+d], imm8 (7 bytes)
            emit({0xC6, 0x05});
            emit32(marker_slot - (cursor + 5)); // rip sits past disp32 + imm8
            emit({marker});
            emit({0x80, 0x05});
            emit32(order_slot - (cursor + 5));
            emit({addend});
            emit({0xC3});
            std::memcpy(at(rva), cb.data(), cb.size());
        };
        emit_callback(kCallback1Rva, 0xA1, 1, kDataRva + 0x18, kDataRva + 0x1C);
        emit_callback(kCallback2Rva, 0xA2, 2, kDataRva + 0x19, kDataRva + 0x1C);
    }

    // --- TLS directory, callback array, IAT, import descriptors ----------
    put64(0x1400, kPreferredBase + 0x2F00); // StartRaw
    put64(0x1408, kPreferredBase + 0x2F00); // EndRaw (empty range)
    put64(0x1410, kPreferredBase + 0x2FF8); // Index
    if (variant == Variant::kTlsUnterminated) {
        // The array lives at the image's last two slots: two nonzero entries
        // and no NUL before SizeOfImage - the loader's walk hits the image
        // end with a partial chain.
        put64(0x1418, kPreferredBase + 0x3FF0); // AddressOfCallbacks
        put64(0x3FF0, kPreferredBase + kCallback1Rva);
        put64(0x3FF8, kPreferredBase + kCallback2Rva);
    } else if (variant == Variant::kTlsOutside) {
        put64(0x1418, kPreferredBase + 0x1440);  // AddressOfCallbacks
        put64(0x1440, kPreferredBase + 0x90000); // far outside the image
        // callbacks[1] = NULL stays zeroed: the target check fires first
    } else {
        put64(0x1418, kPreferredBase + 0x1440); // AddressOfCallbacks
        put64(0x1440, kPreferredBase + kCallback1Rva);
        put64(0x1448, kPreferredBase + kCallback2Rva);
        // callbacks[2] = NULL stays zeroed
    }

    // IAT slot pre-link convention: points at the hint/name entry
    put64(kIatRva, 0x1480);
    put16(0x1480, 0); // hint
    put_str(0x1482, "ExitProcess");
    put64(0x1470, 0x1480); // OriginalFirstThunk[0]
    put_str(0x1490, "KERNEL32.dll");
    put32(0x14A0, 0x1470);  // OriginalFirstThunk
    put32(0x14AC, 0x1490);  // Name
    put32(0x14B0, kIatRva); // FirstThunk
    // descriptor terminator + import hint/name terminator stay zeroed

    // --- relocations: DIR64 for the image-absolute pointers --------------
    // TLS dir Start/End/Index/Callbacks (0x1400/0x1408/0x1410/0x1418) and the
    // callback array entries (0x1440/0x1448, or the near-EOF slots); the pad
    // entry stays type 0 - a 0xA-padded entry would be a DIR64 write into
    // the code at page + 0.
    std::vector<std::uint16_t> reloc_offsets = {0x400, 0x408, 0x410, 0x418, 0x440, 0x448};
    if (variant == Variant::kTlsUnterminated) {
        reloc_offsets = {0x400, 0x408, 0x410, 0x418};
    }
    put32(0x3000, 0x1000); // PageRVA
    put32(0x3004, static_cast<std::uint32_t>(8 + 2 * reloc_offsets.size()));
    for (unsigned i = 0; i < reloc_offsets.size(); ++i) {
        const std::uint16_t entry = static_cast<std::uint16_t>(0xA000 | reloc_offsets[i]);
        at(0x3008)[2 * i] = static_cast<std::uint8_t>(entry);
        at(0x3008)[2 * i + 1] = static_cast<std::uint8_t>(entry >> 8);
    }
    if (variant == Variant::kTlsUnterminated) {
        // The callback slots are on page 0x3000, separate from the TLS
        // directory's page. Relocate them too so rejection tests the missing
        // terminator rather than stale callback VAs after rebasing.
        put32(dirs + 5 * 8 + 4, 28);
        put32(0x3010, 0x3000);
        put32(0x3014, 12);
        put16(0x3018, 0xAFF0);
        put16(0x301A, 0xAFF8);
    }
    // pad word 0x0000 (ABSOLUTE, skipped) keeps the block 4-byte aligned
    return image;
}

std::vector<std::uint8_t> craft_fixture(const Variant variant)
{
    const auto dir = sheller_test::temp_path("sheller_dll_fixture");
    fs::create_directories(dir);
    const auto dll_path = dir / "fx.dll";
    const auto bytes = make_fixture_dll(variant);
    std::ofstream out(dll_path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    EXPECT_TRUE(out) << dll_path;
    auto container = engine::craft_sample_container(dll_path, false, synth_dir());
    EXPECT_TRUE(container.has_value()) << (container.has_value() ? "" : container.error().detail);
    return container.has_value() ? *container : std::vector<std::uint8_t>{};
}

engine::SyscallRunOptions base_options()
{
    engine::SyscallRunOptions options;
    options.max_blocks = 6000000;
    options.timeout_ms = 120000;
    options.max_instructions = 0; // bound blocks, not instructions
    options.synthetic_system_modules = true;
    options.synthetic_module_dir = synth_dir();
    return options;
}

std::expected<engine::SyscallRunStats, engine::SyscallRunFailure>
run_container(const std::vector<std::uint8_t>& container, engine::SyscallRunOptions options)
{
    const engine::FactChannel facts;
    return engine::detail::run_snapshot_syscalls_with_facts(container, options, facts);
}

// Runs with an exit-time dump and returns it as {base-hex name -> bytes}.
std::map<std::string, std::vector<std::uint8_t>>
run_with_dump(const std::vector<std::uint8_t>& container, const engine::SyscallRunOptions& options,
              engine::SyscallRunStats& stats)
{
    static std::size_t call = 0;
    const auto dir = sheller_test::temp_path("sheller_dll_fixture_dump_" + std::to_string(++call));
    std::error_code ec;
    fs::remove_all(dir, ec);
    auto with_dump = options;
    with_dump.dump_directory = dir;
    const auto result = run_container(container, with_dump);
    EXPECT_TRUE(result.has_value()) << static_cast<int>(result.error().error);
    if (!result.has_value()) {
        std::printf("DBG run error=%d blocks=%llu\n", static_cast<int>(result.error().error),
                    static_cast<unsigned long long>(result.error().stats.blocks));
    }
    if (result.has_value()) {
        stats = result.value();
    }
    std::map<std::string, std::vector<std::uint8_t>> dump;
    for (const auto& entry : fs::directory_iterator(dir)) {
        std::ifstream in(entry.path(), std::ios::binary);
        dump[entry.path().stem().string()] = {std::istreambuf_iterator<char>(in),
                                              std::istreambuf_iterator<char>()};
    }
    return dump;
}

// Locates the fixture's marker block by the DllMain magic plus the marker
// constellation (base 64KB-aligned, resume slot in the slot page, TLS bytes)
// so a code-section copy of the immediate can never match.
struct FixtureView {
    std::uint64_t region_base{};
    std::size_t magic_offset{};
    const std::vector<std::uint8_t>* bytes{};
};

std::optional<FixtureView>
find_fixture(const std::map<std::string, std::vector<std::uint8_t>>& dump)
{
    for (const auto& [name, bytes] : dump) {
        for (std::size_t off = 0; off + 0x20 <= bytes.size(); ++off) {
            std::uint32_t value = 0;
            std::memcpy(&value, bytes.data() + off, 4);
            if (value != 0xC0FFEE01U) {
                continue;
            }
            std::uint64_t base = 0;
            std::memcpy(&base, bytes.data() + off + 0x08, 8);
            std::uint64_t resume = 0;
            std::memcpy(&resume, bytes.data() + off + 0x10, 8);
            if (base % 0x10000U != 0 || base < 0x10000U) {
                continue;
            }
            if (resume < 0x500000000000ULL || resume >= 0x500000000000ULL + 0x1000) {
                continue;
            }
            if (bytes[off + 0x18] != 0xA1 || bytes[off + 0x19] != 0xA2) {
                continue;
            }
            return FixtureView{std::strtoull(name.c_str(), nullptr, 16), off, &bytes};
        }
    }
    return std::nullopt;
}

} // namespace

// TRUE path: TLS callbacks ran in directory order before DllMain, the ATTACH
// frame carried (rcx=base, rdx=1, [rsp]=resume slot), and the runner's
// ExitProcess finished the run after the module answered LoadLibrary.
TEST(DllFixture, TruePathMarkersProveTheWholeChain)
{
    const auto container = craft_fixture(Variant::kTrue);
    ASSERT_FALSE(container.empty());
    engine::SyscallRunStats stats{};
    const auto dump = run_with_dump(container, base_options(), stats);
    EXPECT_TRUE(stats.terminated);
    EXPECT_EQ(stats.exit_code, 0x5aU);

    const auto fixture = find_fixture(dump);
    ASSERT_TRUE(fixture.has_value()) << "fixture markers not in the dump";
    const auto& bytes = *fixture->bytes;
    const auto at = [&](const std::size_t marker_offset) {
        return bytes.data() + fixture->magic_offset + marker_offset;
    };
    const auto read32 = [&](const std::size_t marker_offset) {
        std::uint32_t v = 0;
        std::memcpy(&v, at(marker_offset), 4);
        return v;
    };
    const auto read64 = [&](const std::size_t marker_offset) {
        std::uint64_t v = 0;
        std::memcpy(&v, at(marker_offset), 8);
        return v;
    };
    // ATTACH frame arguments
    EXPECT_EQ(read32(0x04), 1U); // DLL_PROCESS_ATTACH
    const std::uint64_t base = read64(0x08);
    EXPECT_NE(base, 0U);
    EXPECT_NE(base, 0x400000U); // the preferred base was taken: deterministic rebase
    EXPECT_EQ(base % 0x10000U, 0U);
    // the frame's return address is the engine's continuation slot
    const std::uint64_t resume = read64(0x10);
    EXPECT_GE(resume, 0x500000000000ULL);
    EXPECT_LT(resume, 0x500000000000ULL + 0x1000);
    // TLS callbacks: both ran, in directory order, before DllMain
    EXPECT_EQ(at(0x18)[0], 0xA1);
    EXPECT_EQ(at(0x19)[0], 0xA2);
    EXPECT_EQ(at(0x1C)[0], 3);
}

// FALSE path: DllMain's refusal answers NULL through the continuation slot
// and rolls the module back - the runner still exits its designed way, and
// no fixture image region with markers survives into the dump.
TEST(DllFixture, FalsePathRollsBackWithoutResidue)
{
    const auto container = craft_fixture(Variant::kFalse);
    ASSERT_FALSE(container.empty());
    engine::SyscallRunStats stats{};
    const auto dump = run_with_dump(container, base_options(), stats);
    EXPECT_TRUE(stats.terminated);
    EXPECT_EQ(stats.exit_code, 0x5aU); // the runner's own finish line
    EXPECT_FALSE(find_fixture(dump).has_value()) << "rolled-back module left a residue";
    EXPECT_EQ(stats.sample_module_base, 0U);
}

// IAT callable: the synthetic load bound the fixture's import to the world's
// intercepted ExitProcess, and the fixture's call through it terminated the
// run with the fixture's own code.
TEST(DllFixture, IatBoundExitProcessIsCallable)
{
    const auto container = craft_fixture(Variant::kExit42);
    ASSERT_FALSE(container.empty());
    const auto stats = run_container(container, base_options());
    ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 42U);
}

// esp stop: with a push-prefixed DllMain and TLS frames ahead of
// it, the monitor re-arms at DllMain's own save window and stops inside the
// completed restore read.
TEST(DllFixture, EspStopLandsAtTheDllMainRestore)
{
    const auto container = craft_fixture(Variant::kTrue);
    ASSERT_FALSE(container.empty());
    auto options = base_options();
    options.esp_stop_goal = engine::EspStopGoal::kStopAtRestore;
    const auto stats = run_container(container, options);
    ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
    EXPECT_TRUE(stats->esp_stop);
    EXPECT_FALSE(stats->terminated);
    EXPECT_GT(stats->blocks, 0U);
}

// esp+xfer stop face on this fixture: the arm rides the completed DllMain
// restore, but the fixture has no post-restore sample-territory transfer -
// the ret hands to the engine resume slot and the runner (infrastructure by
// the edge rules), which never counts. The arm is not a stop: the run
// finishes its designed way. (An unpacking payload's post-restore in-sample
// transfer additionally requires the esp arm to confirm at all - on
// UPX-class DllMain stubs it does not, a documented silent miss; xfer=1 is
// the usable stop face there.)
TEST(DllFixture, EspPlusXferArmStaysSilentWithoutASampleTransfer)
{
    const auto container = craft_fixture(Variant::kTrue);
    ASSERT_FALSE(container.empty());
    auto options = base_options();
    options.esp_stop_goal = engine::EspStopGoal::kArmThenNextXfer;
    const auto stats = run_container(container, options);
    ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
    EXPECT_FALSE(stats->esp_stop); // the arm alone never stops
    EXPECT_FALSE(stats->xfer_stop);
    EXPECT_EQ(stats->xfers, 0U);
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x5aU);
}

// Anchors the fixture's marker block by the TLS pair (present in every
// variant whose callbacks ran) instead of the DllMain magic.
std::optional<FixtureView>
find_tls_markers(const std::map<std::string, std::vector<std::uint8_t>>& dump)
{
    for (const auto& [name, bytes] : dump) {
        for (std::size_t off = 0; off + 0x20 <= bytes.size(); ++off) {
            if (bytes[off] != 0xA1 || bytes[off + 1] != 0xA2) {
                continue;
            }
            return FixtureView{std::strtoull(name.c_str(), nullptr, 16), off - 0x18, &bytes};
        }
    }
    return std::nullopt;
}

// AddressOfEntryPoint == 0 is a legal loadable shape. The load completes
// after the TLS chain without entering the image's own headers - the TLS
// markers prove the chain ran, the DllMain magic proves the MZ bytes at the
// image base never executed, and the runner still finishes its way.
TEST(DllFixture, NoEntryPointCompletesAfterTheTlsChain)
{
    const auto container = craft_fixture(Variant::kNoEntry);
    ASSERT_FALSE(container.empty());
    engine::SyscallRunStats stats{};
    const auto dump = run_with_dump(container, base_options(), stats);
    EXPECT_TRUE(stats.terminated);
    EXPECT_EQ(stats.exit_code, 0x5aU);
    EXPECT_NE(stats.sample_module_base, 0U) << "the handle must answer despite no entry";

    const auto fixture = find_tls_markers(dump);
    ASSERT_TRUE(fixture.has_value()) << "TLS chain did not run";
    const auto& bytes = *fixture->bytes;
    std::uint32_t magic = 0;
    std::memcpy(&magic, bytes.data() + fixture->magic_offset, 4);
    EXPECT_NE(magic, 0xC0FFEE01U) << "the image base (MZ bytes) was executed";
    EXPECT_EQ(bytes[fixture->magic_offset + 0x1C], 3); // both callbacks, in order
}

// V3a: a TLS callback target outside the module image rejects the load by
// name - the transaction rolls back, LoadLibrary answers NULL, and the
// runner finishes without any sample residue.
TEST(DllFixture, TlsCallbackOutsideTheModuleIsRejected)
{
    const auto container = craft_fixture(Variant::kTlsOutside);
    ASSERT_FALSE(container.empty());
    engine::SyscallRunStats stats{};
    const auto dump = run_with_dump(container, base_options(), stats);
    EXPECT_TRUE(stats.terminated);
    EXPECT_EQ(stats.exit_code, 0x5aU);
    EXPECT_EQ(stats.sample_module_base, 0U);
    EXPECT_FALSE(find_fixture(dump).has_value()) << "rejected load left a residue";
    EXPECT_FALSE(find_tls_markers(dump).has_value());
}

// V3b: an unterminated callback array (nonzero through the image end) must
// not answer as a completed load with a partially scheduled chain.
TEST(DllFixture, UnterminatedTlsArrayIsRejected)
{
    const auto container = craft_fixture(Variant::kTlsUnterminated);
    ASSERT_FALSE(container.empty());
    engine::SyscallRunStats stats{};
    const auto dump = run_with_dump(container, base_options(), stats);
    EXPECT_TRUE(stats.terminated);
    EXPECT_EQ(stats.exit_code, 0x5aU);
    EXPECT_EQ(stats.sample_module_base, 0U);
    EXPECT_FALSE(find_fixture(dump).has_value()) << "rejected load left a residue";
    EXPECT_FALSE(find_tls_markers(dump).has_value());
}
