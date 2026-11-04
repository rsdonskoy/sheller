// Syscall number resolution tests: a synthetic ntdll built
// in guest memory (minimal PE header + export directory + stubs) exercises
// the export walk and the stub-immediate decode; the semantic dispatch tests
// prove the policy table honors by-name registered numbers. Portable: uc
// works on every platform.

#include "syscall_number_map.h"

#include "fake_ntdll.hpp"
#include "syscall_policy.h"

#include <unicorn/unicorn.h>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

namespace syscalls = sheller::syscalls;

using sheller_test::build_fake_ntdll;
using sheller_test::kNtdllBase;
using sheller_test::kNtdllImageSize;

class SyscallNumberMap : public testing::Test {
  protected:
    void SetUp() override
    {
        ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &uc_), UC_ERR_OK);
        ASSERT_EQ(uc_mem_map(uc_, kNtdllBase, kNtdllImageSize, UC_PROT_ALL), UC_ERR_OK);
        const auto image = build_fake_ntdll();
        ASSERT_EQ(uc_mem_write(uc_, kNtdllBase, image.data(), image.size()), UC_ERR_OK);
    }

    void TearDown() override
    {
        if (uc_ != nullptr) {
            uc_close(uc_);
        }
    }

    uc_engine* uc_ = nullptr;
};

TEST_F(SyscallNumberMap, DiagnosticFixtureWalk)
{
    // Temp: mirrors the enumerate walk step by step to expose the mismatch.
    const auto read_u32_at = [this](std::uint64_t a) {
        std::uint32_t v = 0;
        uc_mem_read(uc_, a, &v, sizeof v);
        return v;
    };
    EXPECT_EQ(read_u32_at(kNtdllBase + 0x3C), 0x40U);
    EXPECT_EQ(read_u32_at(kNtdllBase + 0x40), 0x4550U);
    EXPECT_EQ(read_u32_at(kNtdllBase + 0x58), 0x20BU);
    EXPECT_EQ(read_u32_at(kNtdllBase + 0xC8), 0x2000U);
    EXPECT_EQ(read_u32_at(kNtdllBase + 0x2014), 3U);
    EXPECT_EQ(read_u32_at(kNtdllBase + 0x201C), 0x150U);
    EXPECT_EQ(read_u32_at(kNtdllBase + 0x2020), 0x160U);
    EXPECT_EQ(read_u32_at(kNtdllBase + 0x2024), 0x170U);
    EXPECT_EQ(read_u32_at(kNtdllBase + 0x160), 0x180U);

    std::uint8_t name_bytes[20] = {};
    uc_mem_read(uc_, kNtdllBase + 0x180, name_bytes, sizeof name_bytes);
    EXPECT_EQ(std::memcmp(name_bytes, "NtTerminateProcess", 18), 0);

    std::uint8_t stub_bytes[8] = {};
    uc_mem_read(uc_, kNtdllBase + 0x3000, stub_bytes, sizeof stub_bytes);
    EXPECT_EQ(stub_bytes[0], 0x4C);
    EXPECT_EQ(stub_bytes[3], 0xB8);
}

TEST_F(SyscallNumberMap, DecodesNtStubNumbers)
{
    const auto entries = syscalls::enumerate_ntdll_syscalls(uc_, kNtdllBase);
    ASSERT_EQ(entries.size(), 2U);
    EXPECT_EQ(entries[0].number, 0x1234U);
    EXPECT_STREQ(entries[0].name.data(), "NtTerminateProcess");
    EXPECT_EQ(entries[1].number, 0x5678U);
    EXPECT_STREQ(entries[1].name.data(), "NtProtectVirtualMemory");
}

TEST(PolicySemanticDispatch, ByNameRegisteredNumberHonorsSemantics)
{
    // A policy registered on an arbitrary "real" number honors the builtin
    // semantics - number keys are pure data (design: semantic dispatch).
    syscalls::PolicyTable table;
    table.set_builtin(0x1234, syscalls::BuiltinHandler::kTerminateProcess);

    syscalls::SyscallFrame frame{};
    frame.number = 0x1234;
    frame.rdx = 0x5678;
    frame.rcx = ~std::uint64_t{0}; // explicit current-process handle
    const syscalls::WriteSink null_sink{};
    const auto outcome = syscalls::dispatch_syscall(table, nullptr, frame, null_sink);
    EXPECT_TRUE(outcome.terminate);
    EXPECT_EQ(outcome.exit_code, 0x5678U);
}

TEST(PolicySemanticDispatch, TerminateProcessNullHandleReturnsPending)
{
    // NtTerminateProcess(NULL) marks the process terminating and returns
    // STATUS_PENDING to the surviving caller - the DLL detach walk (and the
    // CRT's stdio flush) continues on the native exit path.
    syscalls::PolicyTable table;
    table.set_builtin(0x1234, syscalls::BuiltinHandler::kTerminateProcess);

    syscalls::SyscallFrame frame{};
    frame.number = 0x1234;
    frame.rcx = 0; // NULL = current process, pending semantics
    frame.rdx = 0x5678;
    const syscalls::WriteSink null_sink{};
    const auto outcome = syscalls::dispatch_syscall(table, nullptr, frame, null_sink);
    EXPECT_FALSE(outcome.terminate);
    EXPECT_EQ(outcome.status, syscalls::kStatusPending);
}

TEST(PolicySemanticDispatch, UnregisteredNumberDefaultsToDeny)
{
    syscalls::PolicyTable table;
    syscalls::SyscallFrame frame{};
    frame.number = 0x9999;
    const syscalls::WriteSink null_sink{};
    const auto outcome = syscalls::dispatch_syscall(table, nullptr, frame, null_sink);
    EXPECT_TRUE(outcome.rejected);
    EXPECT_EQ(outcome.status, syscalls::kStatusAccessDenied);
}

// NtMapViewOfSection's *ViewSize (argument 7) rides
// the stack-arg window as a POINTER - the real loader passes
// &LdrEntry->ViewSize, and answering anywhere but the pointed-at variable
// leaves the loader's LDR size field at zero: the post-map
// RtlImageNtHeaderEx(base, 0) deep validation then fails the load with
// STATUS_INVALID_IMAGE_FORMAT. The outcome must carry the dereferenced
// pointer, not the stack-slot address.
TEST_F(SyscallNumberMap, MapViewAnswersCallersViewSizePointer)
{
    ASSERT_EQ(uc_mem_map(uc_, 0x7FF900000000, 0x10000, UC_PROT_ALL), UC_ERR_OK);
    constexpr std::uint64_t kStackBase = 0x7FF900000000;
    constexpr std::uint64_t kViewSizePtr = kStackBase + 0x800;
    constexpr std::uint64_t kRsp = kStackBase + 0x1000;
    const std::uint64_t slot_value = kViewSizePtr;
    ASSERT_EQ(uc_mem_write(uc_, kRsp + 0x38, &slot_value, sizeof slot_value), UC_ERR_OK);

    syscalls::PolicyTable table;
    table.set_builtin(0x1234, syscalls::BuiltinHandler::kMapViewOfSection);
    syscalls::SyscallFrame frame{};
    frame.number = 0x1234;
    frame.rcx = 0x5EC70001; // section handle (parse-only here)
    frame.r8 = kStackBase + 0x900;
    frame.rsp = kRsp;
    const syscalls::WriteSink null_sink{};
    const auto outcome = syscalls::dispatch_syscall(table, uc_, frame, null_sink);
    ASSERT_TRUE(outcome.map_view);
    EXPECT_EQ(outcome.map_view_base_ptr, kStackBase + 0x900);
    EXPECT_EQ(outcome.map_view_size_ptr, kViewSizePtr);
}

// Fail-soft: an unreadable argument stack answers the base only - no size
// answer, no fault.
TEST_F(SyscallNumberMap, MapViewUnreadableStackKeepsBaseAnswer)
{
    syscalls::PolicyTable table;
    table.set_builtin(0x1234, syscalls::BuiltinHandler::kMapViewOfSection);
    syscalls::SyscallFrame frame{};
    frame.number = 0x1234;
    frame.rcx = 0x5EC70001;
    frame.r8 = 0x7FF900000900;
    frame.rsp = 0x5000; // unmapped
    const syscalls::WriteSink null_sink{};
    const auto outcome = syscalls::dispatch_syscall(table, uc_, frame, null_sink);
    ASSERT_TRUE(outcome.map_view);
    EXPECT_EQ(outcome.map_view_base_ptr, 0x7FF900000900U);
    EXPECT_EQ(outcome.map_view_size_ptr, 0U);
}

// kQueryZero's ReturnLength reports the bytes actually written - the real
// kernel always fills it in, and strict callers treat a zero as a failed
// query.
TEST_F(SyscallNumberMap, QueryZeroReportsWrittenLength)
{
    ASSERT_EQ(uc_mem_map(uc_, 0x7FF900000000, 0x10000, UC_PROT_ALL), UC_ERR_OK);
    constexpr std::uint64_t kStackBase = 0x7FF900000000;
    constexpr std::uint64_t kRetLenPtr = kStackBase + 0x800;
    constexpr std::uint64_t kRsp = kStackBase + 0x1000;
    const std::uint64_t slot_value = kRetLenPtr;
    ASSERT_EQ(uc_mem_write(uc_, kRsp + 0x28, &slot_value, sizeof slot_value), UC_ERR_OK);
    constexpr std::uint64_t kZero = 0;
    ASSERT_EQ(uc_mem_write(uc_, kRetLenPtr, &kZero, sizeof kZero), UC_ERR_OK);

    syscalls::PolicyTable table;
    table.set_builtin(0x1234, syscalls::BuiltinHandler::kQueryZero);
    syscalls::SyscallFrame frame{};
    frame.number = 0x1234;
    frame.r8 = kStackBase + 0x900; // info buffer
    frame.r9 = 48;                 // requested length
    frame.rsp = kRsp;
    const syscalls::WriteSink null_sink{};
    const auto outcome = syscalls::dispatch_syscall(table, uc_, frame, null_sink);
    EXPECT_EQ(outcome.status, syscalls::kStatusSuccess);
    std::uint64_t reported = 0;
    ASSERT_EQ(uc_mem_read(uc_, kRetLenPtr, &reported, sizeof reported), UC_ERR_OK);
    EXPECT_EQ(reported, 48U);
}

// NtOpenEvent of the loader's post-map notification event: a deterministic
// constant handle nothing dereferences - the denial was fatal to the load.
TEST_F(SyscallNumberMap, OpenEventAnswersDeterministicHandle)
{
    ASSERT_EQ(uc_mem_map(uc_, 0x7FF900000000, 0x10000, UC_PROT_ALL), UC_ERR_OK);
    constexpr std::uint64_t kHandlePtr = 0x7FF900000800;
    syscalls::PolicyTable table;
    table.set_builtin(0x1234, syscalls::BuiltinHandler::kOpenEvent);
    syscalls::SyscallFrame frame{};
    frame.number = 0x1234;
    frame.rcx = kHandlePtr;
    const syscalls::WriteSink null_sink{};
    const auto outcome = syscalls::dispatch_syscall(table, uc_, frame, null_sink);
    EXPECT_EQ(outcome.status, syscalls::kStatusSuccess);
    std::uint64_t handle = 0;
    ASSERT_EQ(uc_mem_read(uc_, kHandlePtr, &handle, sizeof handle), UC_ERR_OK);
    EXPECT_EQ(handle, 0x5ECB0001U);
}

// NtQueryPerformanceCounter answers deterministic
// zeros into both out-parameters (the replay's clock never advances) and
// stays fail-soft on an unwritable counter pointer.
TEST_F(SyscallNumberMap, QueryPerformanceCounterAnswersDeterministicZeros)
{
    ASSERT_EQ(uc_mem_map(uc_, 0x7FF900000000, 0x10000, UC_PROT_ALL), UC_ERR_OK);
    constexpr std::uint64_t kCounterPtr = 0x7FF900000800;
    constexpr std::uint64_t kFreqPtr = 0x7FF900000810;
    syscalls::PolicyTable table;
    table.set_builtin(0x1234, syscalls::BuiltinHandler::kQueryPerformanceCounter);
    syscalls::SyscallFrame frame{};
    frame.number = 0x1234;
    frame.rcx = kCounterPtr;
    frame.rdx = kFreqPtr;
    const syscalls::WriteSink null_sink{};
    const auto outcome = syscalls::dispatch_syscall(table, uc_, frame, null_sink);
    EXPECT_EQ(outcome.status, syscalls::kStatusSuccess);
    std::uint64_t value = 0;
    ASSERT_EQ(uc_mem_read(uc_, kCounterPtr, &value, sizeof value), UC_ERR_OK);
    EXPECT_EQ(value, 0U);
    ASSERT_EQ(uc_mem_read(uc_, kFreqPtr, &value, sizeof value), UC_ERR_OK);
    EXPECT_EQ(value, 0U);
}

TEST_F(SyscallNumberMap, QueryPerformanceCounterFailSoftOnUnwritableCounter)
{
    syscalls::PolicyTable table;
    table.set_builtin(0x1234, syscalls::BuiltinHandler::kQueryPerformanceCounter);
    syscalls::SyscallFrame frame{};
    frame.number = 0x1234;
    frame.rcx = 0x7FF800000000; // mapped but the stub area read-only? UC_PROT_ALL
                                // here: use an unmapped page instead
    frame.rcx = 0x5FF900000000; // unmapped
    frame.rdx = 0;
    const syscalls::WriteSink null_sink{};
    const auto outcome = syscalls::dispatch_syscall(table, uc_, frame, null_sink);
    EXPECT_EQ(outcome.status, syscalls::kStatusAccessViolation);
}

// The AppPolicy preamble's thread-token open: the desktop answer for a plain
// main thread is STATUS_NO_TOKEN (not the old default-denial ACCESS_DENIED -
// the real denial sent the replayed loader down an error branch native never
// walks).
TEST(PolicySemanticDispatch, OpenThreadTokenRejectsWithNativeNoToken)
{
    syscalls::PolicyTable table;
    table.set_entry(0x1234, syscalls::PolicyEntry{.kind = syscalls::EntryKind::kReject,
                                                  .reject_status = syscalls::kStatusNoToken,
                                                  .builtin = syscalls::BuiltinHandler::kNone});
    syscalls::SyscallFrame frame{};
    frame.number = 0x1234;
    const syscalls::WriteSink null_sink{};
    const auto outcome = syscalls::dispatch_syscall(table, nullptr, frame, null_sink);
    EXPECT_TRUE(outcome.rejected);
    EXPECT_EQ(outcome.status, syscalls::kStatusNoToken);
    EXPECT_EQ(syscalls::kStatusNoToken, 0xC000007CU);
}

} // namespace
