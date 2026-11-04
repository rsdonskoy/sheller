// Crafted esp-stop fixtures: the same craft shape as
// snapshot_fixture.h, with entry code that saves registers on the stack and
// restores them, so the esp stop target's window, confirmation set and both
// stop forms have a deterministic corpus. Addresses are the fixture's
// contract: the entry face is kImageBase with rsp = kStackVa (the crafted
// snapshot's registers), so the save window is [kStackVa - extent, kStackVa).
#pragma once

#include "snapshot_fixture.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <sstream>
#include <vector>

namespace sheller_test {

namespace snapshot = sheller::snapshot;

// The terminate tail, shared by every fixture: rcx=-1 / rdx=0x1234 /
// eax=0x1002 / syscall. A run that reaches it died of old age, not of the
// esp stop - syscalls==1 with terminated==1 is the "the esp target never
// fired" face, syscalls==0 the "stopped before the landing" one.
constexpr std::array<std::uint8_t, 21> kEspTerminateTail{
    0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, // mov rcx, -1
    0x48, 0xC7, 0xC2, 0x34, 0x12, 0x00, 0x00, // mov rdx, 0x1234
    0xB8, 0x02, 0x10, 0x00, 0x00,             // mov eax, 0x1002 (NtTerminateProcess)
    0x0F, 0x05};                              // syscall

inline std::vector<std::uint8_t> esp_tail_bytes()
{
    return {kEspTerminateTail.begin(), kEspTerminateTail.end()};
}

// push rbx / push rbp / work / pop rbp / pop rbx / terminate. The window is
// [S-0x10, S); the first pop is an intermediate restore, the second the
// completed one (callback rsp + 8 == S) - the esp form stops inside that
// read, before the terminate tail.
inline std::vector<std::uint8_t> esp_hit_code()
{
    constexpr std::array<std::uint8_t, 14> kHead{
        0x53,                         // push rbx          -> S-8
        0x55,                         // push rbp          -> S-0x10
        0xBB, 0x34, 0x12, 0x00, 0x00, // mov ebx, 0x1234 (the stand-in unpack work)
        0xBD, 0x78, 0x56, 0x00, 0x00, // mov ebp, 0x5678
        0x5D,                         // pop rbp           (intermediate: rsp+8 != S)
        0x5B};                        // pop rbx           (completion: rsp+8 == S)
    auto code = std::vector<std::uint8_t>{kHead.begin(), kHead.end()};
    const auto tail = esp_tail_bytes();
    code.insert(code.end(), tail.begin(), tail.end());
    return code;
}

// The anti-debug shape: a window read whose decode is not a pop. The read
// passes the window gate and the RSP gate (rsp == the slot address) and must
// be rejected by the decode gate alone - the run continues and terminates.
inline std::vector<std::uint8_t> esp_anti_debug_code()
{
    constexpr std::array<std::uint8_t, 15> kHead{
        0x53,                         // push rbx
        0x55,                         // push rbp
        0x48, 0x8B, 0x04, 0x24,       // mov rax, [rsp]  (window read, not a restore)
        0xBB, 0x34, 0x12, 0x00, 0x00, // mov ebx, 0x1234
        0x48, 0x83, 0xC4, 0x10};      // add rsp, 0x10   (discard the frame without pops)
    auto code = std::vector<std::uint8_t>{kHead.begin(), kHead.end()};
    const auto tail = esp_tail_bytes();
    code.insert(code.end(), tail.begin(), tail.end());
    return code;
}

// The VM shape: one register push (the monitor arms on a non-empty window),
// then the stack pointer relocates - the classic VM exit stub that keeps its
// state elsewhere. The window is never read; the run must close on the miss
// path, not stop.
inline std::vector<std::uint8_t> esp_relocated_stack_code()
{
    constexpr std::array<std::uint8_t, 6> kHead{
        0x53,                          // push rbx            (window [S-8, S) armed)
        0xBC, 0x00, 0x0C, 0xF0, 0x07}; // mov esp, 0x07F00C00 (stack base relocated in-page)
    auto code = std::vector<std::uint8_t>{kHead.begin(), kHead.end()};
    const auto tail = esp_tail_bytes();
    code.insert(code.end(), tail.begin(), tail.end());
    return code;
}

// Probe-leg guard corpus: a register saved, a burn loop whose body reads the
// window (thousands of real iterations before the probe triggers, then the
// same reads inside the probe's speculative chunks), the restore after it.
// The loop's reads are decode-rejected (mov, not pop); the probe's
// fast-forward must still admit the loop and the esp stop must land on the
// post-loop restore, not anywhere inside the speculation.
inline std::vector<std::uint8_t> esp_probe_guard_code()
{
    constexpr std::array<std::uint8_t, 14> kHead{
        0x53,                         // push rbx
        0xB9, 0xE0, 0x93, 0x04, 0x00, // mov ecx, 300000
        0x48, 0x8B, 0x04, 0x24,       // loop: mov rax, [rsp]  (window read, rsp == S-8)
        0xFF, 0xC9,                   // dec ecx
        0x75, 0xF9};                  // jnz loop
    constexpr std::array<std::uint8_t, 1> kRestore{0x5B}; // pop rbx (completion)
    auto code = std::vector<std::uint8_t>{kHead.begin(), kHead.end()};
    code.insert(code.end(), kRestore.begin(), kRestore.end());
    const auto tail = esp_tail_bytes();
    code.insert(code.end(), tail.begin(), tail.end());
    return code;
}

// Serializes a single-image-region fixture at kImageBase with the standard
// crafted face (entry kImageBase, rsp kStackVa): the esp fixture's contract.
inline std::vector<std::uint8_t> craft_esp_snapshot(const std::vector<std::uint8_t>& code)
{
    return craft_snapshot(code);
}

// Two-section arm fixture: .text saves and restores, then jumps to text2.
// The jump is the run's only execution transfer, so esp+xfer arms on the
// completed restore and stops before the landing block; the esp form stops
// inside the restore read and the jump never runs.
constexpr std::uint64_t kEspArmTextVa = kImageBase + 0x1000;
constexpr std::uint64_t kEspArmText2Va = kImageBase + 0x2000;

// Shared two-section serializer: `text` lands at 0x1000 (the entry), the
// terminate tail at 0x2000. The jump out of .text is the run's only transfer.
inline std::vector<std::uint8_t> craft_esp_two_section_text(const std::vector<std::uint8_t>& text)
{
    constexpr std::array kSections{PeSection{".text", 0x1000}, PeSection{"text2", 0x2000}};
    auto image = craft_pe_image(kImageBase, kXferImageSize, 0x1000, kSections);

    constexpr std::array<std::uint8_t, 19> kLanding{0x48, 0xC7, 0xC1, 0xFF, 0xFF,
                                                    0xFF, 0xFF,                   // mov rcx, -1
                                                    0xBA, 0x34, 0x12, 0x00, 0x00, // mov edx, 0x1234
                                                    0xB8, 0x02, 0x10, 0x00, 0x00, // mov eax, 0x1002
                                                    0x0F, 0x05};                  // syscall
    std::copy(text.begin(), text.end(), image.begin() + static_cast<std::ptrdiff_t>(0x1000));
    std::copy(kLanding.begin(), kLanding.end(),
              image.begin() + static_cast<std::ptrdiff_t>(0x2000));

    auto metadata = fixture_metadata(kEspArmTextVa);
    std::copy_n(image.begin() + 0x1000, metadata.original_entry_bytes.size(),
                metadata.original_entry_bytes.begin());
    std::vector<std::uint8_t> stack(kRegionSize, std::uint8_t{0x5A});
    std::vector<std::uint8_t> teb(kRegionSize, std::uint8_t{0});

    std::ostringstream out;
    snapshot::Writer writer{out};
    if (!writer.write_header(
            snapshot::Header{.version = snapshot::kVersion, .bitness = snapshot::kBitness64}) ||
        !writer.write_registers(fixture_registers(kEspArmTextVa)) ||
        !writer.write_metadata(metadata) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = kImageBase,
                                                    .size = kXferImageSize,
                                                    .protection = kPageExecuteReadwrite,
                                                    .type = kMemImage,
                                                    .content = snapshot::kContentPresent},
                             image.data()) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = kStackRegionBase,
                                                    .size = kRegionSize,
                                                    .protection = kPageReadwrite,
                                                    .type = kMemPrivate,
                                                    .content = snapshot::kContentPresent},
                             stack.data()) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = 0x07F10000,
                                                    .size = kRegionSize,
                                                    .protection = kPageReadwrite,
                                                    .type = kMemPrivate,
                                                    .content = snapshot::kContentPresent},
                             teb.data()) ||
        !writer.finalize_region_count()) {
        EXPECT_TRUE(false) << "esp two-section snapshot serialization failed";
    }
    const auto str = out.str();
    return {str.begin(), str.end()};
}

inline std::vector<std::uint8_t> craft_esp_arm_snapshot()
{
    constexpr std::array<std::uint8_t, 21> kRestoreAndJump{
        0x53,                         // push rbx
        0x55,                         // push rbp
        0xBB, 0x34, 0x12, 0x00, 0x00, // mov ebx, 0x1234
        0xBD, 0x78, 0x56, 0x00, 0x00, // mov ebp, 0x5678
        0x5D,                         // pop rbp
        0x5B,                         // pop rbx (completion)
        0xB8, 0x00, 0x20, 0x40, 0x00, // mov eax, kEspArmText2Va
        0xFF, 0xE0};                  // jmp rax
    return craft_esp_two_section_text({kRestoreAndJump.begin(), kRestoreAndJump.end()});
}

// The early-transfer corpus: the entry saves registers (the window arms) and
// jumps straight out of the section without ever restoring. The transfer is
// the run's only one, so an explicit xfer ordinal (the public API's
// xfer_number=1) coexisting with `--stop esp+xfer` stops there with the esp
// goal never confirmed - the armed-line false positive's exact shape.
inline std::vector<std::uint8_t> craft_esp_early_xfer_snapshot()
{
    constexpr std::array<std::uint8_t, 19> kJumpOnly{
        0x53,                         // push rbx
        0x55,                         // push rbp
        0xBB, 0x34, 0x12, 0x00, 0x00, // mov ebx, 0x1234
        0xBD, 0x78, 0x56, 0x00, 0x00, // mov ebp, 0x5678
        0xB8, 0x00, 0x20, 0x40, 0x00, // mov eax, kEspArmText2Va
        0xFF, 0xE0};                  // jmp rax (no restore)
    return craft_esp_two_section_text({kJumpOnly.begin(), kJumpOnly.end()});
}

// The stack-pivot corpus: the completion slot's pop writes RSP itself. POP
// RSP passes the window and RSP gates and decodes as a pop, but the retired
// pointer is the popped value - a pivot, not a restore, and the decode gate
// excludes it. The pivot target is a valid in-page stack address so the
// terminate after it runs on a mapped stack.
inline std::vector<std::uint8_t> esp_pop_rsp_code()
{
    constexpr std::uint64_t kPivotRsp = kStackRegionBase + 0x700; // inside the stack page
    std::vector<std::uint8_t> code{0x53, 0x55}; // push rbx; push rbp (the save prefix)
    code.push_back(0x48);
    code.push_back(0xB8); // mov rax, imm64
    for (int byte = 0; byte < 8; ++byte) {
        code.push_back(static_cast<std::uint8_t>(kPivotRsp >> (8 * byte)));
    }
    const std::array<std::uint8_t, 4> kStoreRspSlot{0x48, 0x89, 0x04, 0x24}; // mov [rsp], rax
    code.insert(code.end(), kStoreRspSlot.begin(), kStoreRspSlot.end());
    code.push_back(0x5C); // pop rsp (reads the completion slot S-0x10)
    const auto tail = esp_tail_bytes();
    code.insert(code.end(), tail.begin(), tail.end());
    return code;
}

// The page-end corpus: the restore block sits at the image page's last 8
// bytes, so the completion pop decodes with 7 mapped bytes behind it - all a
// 1-byte pop needs, and what the short-read decode has to accept.
inline std::vector<std::uint8_t> craft_esp_page_end_restore_snapshot()
{
    std::vector<std::uint8_t> page(kRegionSize, std::uint8_t{0});
    constexpr std::array<std::uint8_t, 17> kEntry{
        0x53,                          // push rbx
        0x55,                          // push rbp
        0xBB, 0x34, 0x12, 0x00, 0x00,  // mov ebx, 0x1234
        0xBD, 0x78, 0x56, 0x00, 0x00,  // mov ebp, 0x5678
        0xE9, 0xE7, 0x0F, 0x00, 0x00}; // jmp rel32 -> image+0xFF8
    std::copy(kEntry.begin(), kEntry.end(), page.begin());
    constexpr std::array<std::uint8_t, 7> kRestore{0x5D, // pop rbp (reads S-0x10, intermediate)
                                                   0x5B, // pop rbx (reads S-8: the completion)
                                                   0xE9, 0x01, 0xF1,
                                                   0xFF, 0xFF}; // jmp rel32 -> image+0x100
    std::copy(kRestore.begin(), kRestore.end(), page.begin() + 0xFF8);
    const auto tail = esp_tail_bytes();
    std::copy(tail.begin(), tail.end(), page.begin() + 0x100);
    return craft_snapshot(page);
}

} // namespace sheller_test
