// Behavior ledger tests: ring order and capacity-drop semantics, per-type
// counters, truncation of oversized payloads, TLV output round-tripped
// through the contract reader, and the deterministic JSON render - the last
// one through the CLI render library's full-level events section, the only
// shipped entry that spells window entries. Pure standard library - runs on
// both platforms.

#include "event_ledger.h"

#include <sheller/events.h>

#include <gtest/gtest.h>

#include "render_test_util.hpp"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <vector>

namespace {

namespace ev = sheller;
namespace behavior = sheller::behavior;
namespace fs = std::filesystem;

sheller::EventPreamble fixture_preamble(const std::uint64_t pc)
{
    // The stream tee owns whole-run numbering; tests that assert the seq spell
    // it explicitly, the rest pass 0 (the ledger never renumbers).
    return sheller::EventPreamble{.seq = 0, .tid = 7, .pc = pc};
}

sheller::EventPreamble fixture_preamble(const std::uint64_t seq, const std::uint64_t pc)
{
    return sheller::EventPreamble{.seq = seq, .tid = 7, .pc = pc};
}

std::vector<std::uint8_t> u64_fields(const std::uint64_t value)
{
    std::vector<std::uint8_t> bytes(sizeof(std::uint64_t));
    ev::le::store_le64(bytes.data(), value);
    return bytes;
}

std::vector<std::uint8_t> u32_fields(const std::uint32_t value)
{
    std::vector<std::uint8_t> bytes(sizeof(std::uint32_t));
    ev::le::store_le32(bytes.data(), value);
    return bytes;
}

// Function-form syscall payload:
// {number u32, flags u8, status u32, caller u64}, no parameter records.
std::vector<std::uint8_t> syscall_head_fields(const std::uint32_t number,
                                              const std::uint8_t flags = 0,
                                              const std::uint32_t status = 0,
                                              const std::uint64_t caller = 0x140001000)
{
    std::vector<std::uint8_t> bytes(ev::kSyscallFixedBytes);
    ev::le::store_le32(bytes.data() + ev::kSyscallNumberOffset, number);
    bytes[ev::kSyscallFlagsOffset] = flags;
    ev::le::store_le32(bytes.data() + ev::kSyscallStatusOffset, status);
    ev::le::store_le64(bytes.data() + ev::kSyscallCallerOffset, caller);
    return bytes;
}

std::string read_file(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

fs::path scratch_path(const char* name)
{
    const auto dir = fs::temp_directory_path() / "sheller_ledger_test";
    fs::create_directories(dir);
    return dir / name;
}

TEST(EventLedgerRing, KeepsOrderAndDropsOldestWhenFull)
{
    behavior::EventLedger ledger{4};
    for (std::uint64_t i = 1; i <= 6; ++i) {
        ledger.record(ev::EventTypeId::kBlockExec, fixture_preamble(i, i * 0x100),
                      u64_fields(i * 0x100));
    }

    // Capacity 4 with 6 records: the two oldest are evicted, order preserved.
    EXPECT_EQ(ledger.size(), 4U);
    EXPECT_EQ(ledger.dropped(), 2U);
    for (std::size_t i = 0; i < ledger.size(); ++i) {
        const auto entry = ledger.entry(i);
        EXPECT_EQ(entry.type, ev::EventTypeId::kBlockExec);
        EXPECT_EQ(entry.preamble.pc, (i + 3) * 0x100);
        EXPECT_EQ(entry.preamble.seq, i + 3); // caller-owned, kept verbatim
        EXPECT_EQ(entry.preamble.tid, 7U);
    }
}

TEST(EventLedgerRing, CountsPerTypeSurviveEviction)
{
    behavior::EventLedger ledger{2}; // tiny ring: everything evicts, counts stay
    ledger.record(ev::EventTypeId::kBlockExec, fixture_preamble(0x100), u64_fields(0x100));
    ledger.record(ev::EventTypeId::kSyscall, fixture_preamble(0x110), u32_fields(0x1000));
    ledger.record(ev::EventTypeId::kBlockExec, fixture_preamble(0x120), u64_fields(0x120));
    ledger.record(ev::EventTypeId::kSyscall, fixture_preamble(0x130), u32_fields(0x1001));

    EXPECT_EQ(ledger.count_of(ev::EventTypeId::kBlockExec), 2U);
    EXPECT_EQ(ledger.count_of(ev::EventTypeId::kSyscall), 2U);
    EXPECT_EQ(ledger.count_of(ev::EventTypeId::kMemRead), 0U);
    EXPECT_EQ(ledger.count_of(static_cast<ev::EventTypeId>(0x7FFF)),
              0U); // outside the known id space
    EXPECT_EQ(ledger.dropped(), 2U);
}

TEST(EventLedgerRing, OversizedFieldsAreTruncatedAndCounted)
{
    behavior::EventLedger ledger;
    const std::vector<std::uint8_t> oversized(behavior::kMaxEventFields + 8, 0xAB);
    ledger.record(ev::EventTypeId::kMemRead, fixture_preamble(0x100), oversized);

    ASSERT_EQ(ledger.size(), 1U);
    const auto entry = ledger.entry(0);
    EXPECT_EQ(entry.type_fields.size(), behavior::kMaxEventFields);
    EXPECT_EQ(entry.type_fields.front(), 0xAB);
    EXPECT_EQ(entry.type_fields.back(), 0xAB);
    EXPECT_EQ(ledger.truncated(), 1U);
    EXPECT_EQ(ledger.dropped(), 0U);
}

TEST(EventLedgerTlv, RoundTripsThroughContractReader)
{
    behavior::EventLedger ledger;
    ledger.record(ev::EventTypeId::kBlockExec, fixture_preamble(0x140001000),
                  u64_fields(0x140001000));
    ledger.record(ev::EventTypeId::kSyscall, fixture_preamble(0x140001010),
                  syscall_head_fields(0x1000));
    ledger.record(ev::EventTypeId::kCpuid, fixture_preamble(0x140001020), {}); // preamble-only

    const auto path = scratch_path("roundtrip.tlv");
    const auto written = ledger.write_tlv(path);
    ASSERT_TRUE(written.has_value()) << behavior::ledger_error_message(written.error());
    EXPECT_EQ(*written, 3 * (ev::kEventHeaderSize + ev::kEventPreambleSize) +
                            sizeof(std::uint64_t) + ev::kSyscallFixedBytes);

    const auto bytes = read_file(path);
    ASSERT_EQ(bytes.size(), *written);
    const std::span<const std::uint8_t> in(reinterpret_cast<const std::uint8_t*>(bytes.data()),
                                           bytes.size());

    std::size_t seen = 0;
    auto cursor = in;
    while (!cursor.empty()) {
        const auto view = ev::read_event(cursor);
        ASSERT_TRUE(view.has_value()) << ev::event_codec_error_message(view.error());
        const auto entry = ledger.entry(seen++);
        EXPECT_EQ(view->type, entry.type);
        const auto preamble = ev::read_preamble(view->payload);
        ASSERT_TRUE(preamble.has_value());
        EXPECT_EQ(preamble->seq, entry.preamble.seq);
        EXPECT_EQ(preamble->tid, entry.preamble.tid);
        EXPECT_EQ(preamble->pc, entry.preamble.pc);
        ASSERT_EQ(view->payload.size(), ev::kEventPreambleSize + entry.type_fields.size());
        if (!entry.type_fields.empty()) {
            EXPECT_EQ(0, std::memcmp(view->payload.data() + ev::kEventPreambleSize,
                                     entry.type_fields.data(), entry.type_fields.size()));
        }
        cursor = cursor.subspan(view->total_size);
    }
    EXPECT_EQ(seen, ledger.size());
}

TEST(EventLedgerTlv, JudgmentPayloadRoundTripsThroughContractReader)
{
    const ev::JudgmentFields fields{
        .address = 0x140001234,
        .aux = 96,
        .subtype = static_cast<std::uint32_t>(ev::AntiDebugSubtype::kProbeApiCall),
        .api = "kernel32!IsDebuggerPresent"};
    std::array<std::uint8_t, 256> payload{};
    const auto encoded = ev::encode_judgment(payload, fields);
    ASSERT_TRUE(encoded.has_value());

    behavior::EventLedger ledger;
    ledger.record(ev::EventTypeId::kAntiDebug, fixture_preamble(1, 0x140001234),
                  std::span(payload.data(), *encoded));
    const auto path = scratch_path("judgment.tlv");
    ASSERT_TRUE(ledger.write_tlv(path).has_value());

    const auto bytes = read_file(path);
    const std::span<const std::uint8_t> in(reinterpret_cast<const std::uint8_t*>(bytes.data()),
                                           bytes.size());
    const auto view = ev::read_event(in);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->type, ev::EventTypeId::kAntiDebug);
    const auto preamble = ev::read_preamble(view->payload);
    ASSERT_TRUE(preamble.has_value());
    EXPECT_EQ(preamble->seq, 1U);
    EXPECT_EQ(preamble->pc, 0x140001234U);
    const auto decoded = ev::read_judgment(view->payload.subspan(ev::kEventPreambleSize));
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->fields.address, fields.address);
    EXPECT_EQ(decoded->fields.aux, fields.aux);
    EXPECT_EQ(decoded->fields.subtype, fields.subtype);
    EXPECT_EQ(decoded->fields.api, fields.api);
}

TEST(EventLedgerTlv, EmptyLedgerWritesEmptyFile)
{
    const behavior::EventLedger ledger;
    const auto path = scratch_path("empty.tlv");
    const auto written = ledger.write_tlv(path);
    ASSERT_TRUE(written.has_value());
    EXPECT_EQ(*written, 0U);
    EXPECT_TRUE(read_file(path).empty());
}

TEST(EventLedgerJson, EmptyLedgerRendersEmptyArray)
{
    const behavior::EventLedger ledger;
    const auto path = scratch_path("empty.json");
    const auto written = ledger.write_json(path);
    ASSERT_TRUE(written.has_value());
    EXPECT_EQ(*written, 2U);
    EXPECT_EQ(read_file(path), "[]");
}

TEST(EventLedgerJson, DeterministicExactShape)
{
    const auto render = [] {
        behavior::EventLedger ledger;
        ledger.record(ev::EventTypeId::kBlockExec, fixture_preamble(1, 0x140001000),
                      u64_fields(0x140001000));
        ledger.record(ev::EventTypeId::kSyscall, fixture_preamble(2, 0x140001010),
                      syscall_head_fields(0x1000));
        const auto path = scratch_path("shape.json");
        EXPECT_TRUE(ledger.write_json(path).has_value());
        return read_file(path);
    };

    // Fixed key order, fixed lowercase names, 0x hex addresses, compact. The
    // whole-ledger JSON keeps the minimal payload fields (syscall: number only);
    // the full function-form decode lives in the CLI's full-level stream.
    const std::string expected =
        "[{\"type\":\"block-exec\",\"seq\":1,\"tid\":7,\"pc\":\"0x140001000\","
        "\"addr\":\"0x140001000\"},{\"type\":\"syscall\",\"seq\":2,\"tid\":7,"
        "\"pc\":\"0x140001010\",\"num\":\"0x1000\"}]";
    EXPECT_EQ(render(), expected);
    EXPECT_EQ(render(), render()); // same records -> byte-identical
}

TEST(EventLedgerJson, UnknownTypeRendersAsUnknownPreambleOnly)
{
    behavior::EventLedger ledger;
    ledger.record(static_cast<ev::EventTypeId>(0x7FFF), fixture_preamble(1, 0x1000), {});

    const auto path = scratch_path("unknown.json");
    ASSERT_TRUE(ledger.write_json(path).has_value());
    EXPECT_EQ(read_file(path), "[{\"type\":\"unknown\",\"seq\":1,\"tid\":7,\"pc\":\"0x1000\"}]");
}

TEST(EventLedgerJson, ExceptionRendersCode)
{
    behavior::EventLedger ledger;
    ledger.record(ev::EventTypeId::kException, fixture_preamble(1, 0x140002000),
                  u32_fields(0xC0000005));

    const auto path = scratch_path("exception.json");
    ASSERT_TRUE(ledger.write_json(path).has_value());
    // Fixed key order: type, seq, tid, pc, then the payload code.
    EXPECT_EQ(read_file(path),
              "[{\"type\":\"exception\",\"seq\":1,\"tid\":7,\"pc\":\"0x140002000\","
              "\"code\":\"0xc0000005\"}]");
}

// --- full-level stream: flat linear, decoded payloads, attribution ---

TEST(EventLedgerTimeline, FullTypeDecodeWithAttribution)
{
    behavior::EventLedger ledger;
    sheller::EventPreamble pre{.seq = 0, .tid = 3, .pc = 0x401000};

    // xfer: from sample .text to runtime
    const std::uint16_t from_mod = 0, from_sec = 1; // .text rides the wire-grid index 1
    const std::uint16_t to_mod = sheller::TimelineNameTable::kRuntimeIndex;
    const std::uint16_t to_sec = sheller::TimelineNameTable::kRuntimeIndex;
    std::array<std::uint8_t, 8> xfer{};
    xfer[0] = static_cast<std::uint8_t>(from_mod);
    xfer[1] = static_cast<std::uint8_t>(from_mod >> 8);
    xfer[2] = static_cast<std::uint8_t>(from_sec);
    xfer[3] = static_cast<std::uint8_t>(from_sec >> 8);
    xfer[4] = static_cast<std::uint8_t>(to_mod);
    xfer[5] = static_cast<std::uint8_t>(to_mod >> 8);
    xfer[6] = static_cast<std::uint8_t>(to_sec);
    xfer[7] = static_cast<std::uint8_t>(to_sec >> 8);
    ledger.record(sheller::EventTypeId::kXfer, pre, xfer);

    // syscall with a known mnemonic (function-form head)
    ledger.record(sheller::EventTypeId::kSyscall, pre, syscall_head_fields(0x1002));

    // thread-create: tid + start
    const std::uint32_t new_tid = 1;
    const std::uint64_t start = 0x401047;
    std::array<std::uint8_t, 12> create{};
    std::memcpy(create.data(), &new_tid, 4);
    std::memcpy(create.data() + 4, &start, 8);
    ledger.record(sheller::EventTypeId::kThreadCreate, pre, create);

    sheller::TimelineNameTable names;
    names.modules = {"sample.exe", "ntdll.dll"};
    // wire-grid convention: index 0 = headers pseudo-section, real sections
    // from index 1
    names.sections = {{"headers", ".text"}, {"headers", ".text", ".data"}};
    names.syscalls.emplace(0x1002, "NtTerminateProcess");

    const auto json = render_full_events(ledger, names);
    EXPECT_NE(json.find("\"type\":\"xfer\""), std::string::npos);
    EXPECT_NE(json.find("\"from\":\"sample.exe!.text\""), std::string::npos);
    EXPECT_NE(json.find("\"to\":\"runtime\""), std::string::npos);
    EXPECT_NE(json.find("\"num\":\"0x1002\""), std::string::npos);
    EXPECT_NE(json.find("\"api\":\"NtTerminateProcess\""), std::string::npos);
    EXPECT_NE(json.find("\"type\":\"thread-create\""), std::string::npos);
    EXPECT_NE(json.find("\"new_tid\":1"), std::string::npos);
    EXPECT_NE(json.find("\"start\":\"0x401047\""), std::string::npos);

    // determinism: same input, byte-identical output
    const auto again = render_full_events(ledger, names);
    EXPECT_EQ(json, again);
}

TEST(EventLedgerTimeline, OutOfRangeIndexesRenderRuntime)
{
    behavior::EventLedger ledger;
    sheller::EventPreamble pre{.seq = 0, .tid = 0, .pc = 0x77000000};
    const std::uint16_t big = 0x7FFF; // beyond any name table
    std::array<std::uint8_t, 8> xfer{};
    xfer[0] = static_cast<std::uint8_t>(big);
    xfer[4] = static_cast<std::uint8_t>(big);
    ledger.record(sheller::EventTypeId::kXfer, pre, xfer);

    sheller::TimelineNameTable names;
    names.modules = {"sample.exe"};
    names.sections = {{"headers", ".text"}};
    const auto json = render_full_events(ledger, names);
    EXPECT_NE(json.find("\"from\":\"runtime\""), std::string::npos);
    EXPECT_NE(json.find("\"to\":\"runtime\""), std::string::npos);
}

TEST(EventLedgerTimeline, XferAttributionMatchesThePublicResolver)
{
    // One-implementation guard: the timeline's endpoint spelling must be
    // exactly what the public resolver produces for the same indexes. A
    // private copy inside the render layer would drift from the artifacts the
    // library fills, and the report and the timeline would name the same event
    // differently - which the behavior-rules report requirement forbids.
    behavior::EventLedger ledger;
    sheller::EventPreamble pre{.seq = 0, .tid = 0, .pc = 0x77000000};
    std::array<std::uint8_t, 8> xfer{};
    const auto put = [&xfer](const std::size_t offset, const std::uint16_t value) {
        xfer[offset] = static_cast<std::uint8_t>(value & 0xFFu);
        xfer[offset + 1] = static_cast<std::uint8_t>(value >> 8);
    };
    put(0, 0);      // from module: sample.exe
    put(2, 1);      // from section: .text
    put(4, 0xFF01); // to module: the private-exec region sentinel
    put(6, 0xFFFF); // to section: unclassified
    ledger.record(sheller::EventTypeId::kXfer, pre, xfer);

    sheller::TimelineNameTable names;
    names.modules = {"sample.exe"};
    names.sections = {{"headers", ".text"}};
    const auto json = render_full_events(ledger, names);
    EXPECT_NE(json.find("\"from\":\"" + sheller::section_name_of(names, 0, 1) + "\""),
              std::string::npos)
        << json;
    EXPECT_NE(json.find("\"to\":\"" + sheller::section_name_of(names, 0xFF01, 0xFFFF) + "\""),
              std::string::npos)
        << json;
    // The spellings themselves, so a resolver change that carries both sides
    // with it still shows up here.
    EXPECT_NE(json.find("\"from\":\"sample.exe!.text\""), std::string::npos) << json;
    EXPECT_NE(json.find("\"to\":\"private-exec\""), std::string::npos) << json;
}

TEST(EventLedgerTimeline, SentinelXferPayloadRendersClass)
{
    // Wire path: an xfer whose to-slot carries the runtime private-exec
    // sentinel renders "private-exec" in the timeline - the same string the
    // report's events section produces from the shared helper.
    behavior::EventLedger ledger;
    sheller::EventPreamble pre{.seq = 0, .tid = 0, .pc = 0x7F0000001000};
    std::array<std::uint8_t, 8> xfer{};
    const std::uint16_t from_module = 0, from_section = 1; // sample .text (wire-grid index 1)
    const std::uint16_t to_module = 0xFF11, to_section = 0xFFFF;
    xfer[0] = static_cast<std::uint8_t>(from_module);
    xfer[1] = static_cast<std::uint8_t>(from_module >> 8);
    xfer[2] = static_cast<std::uint8_t>(from_section);
    xfer[3] = static_cast<std::uint8_t>(from_section >> 8);
    xfer[4] = static_cast<std::uint8_t>(to_module);
    xfer[5] = static_cast<std::uint8_t>(to_module >> 8);
    xfer[6] = static_cast<std::uint8_t>(to_section);
    xfer[7] = static_cast<std::uint8_t>(to_section >> 8);
    ledger.record(sheller::EventTypeId::kXfer, pre, xfer);

    sheller::TimelineNameTable names;
    names.modules = {"sample.exe"};
    names.sections = {{"headers", ".text"}};
    const auto json = render_full_events(ledger, names);
    EXPECT_NE(json.find("\"from\":\"sample.exe!.text\""), std::string::npos);
    EXPECT_NE(json.find("\"to\":\"private-exec\""), std::string::npos);
}

// --- Function-form renders, stub table, truncation

namespace {

// Builds a complete kApiCall type-field payload: head + one strA record.
std::vector<std::uint8_t> apicall_fields_stra(const std::string_view name,
                                              const std::uint16_t module, const std::uint8_t flags,
                                              const std::string_view arg)
{
    std::vector<std::uint8_t> payload(ev::kApiCallFixedBytes + name.size() + 3 + arg.size());
    const ev::ApiCallFields fields{.name = name,
                                   .module = module,
                                   .flags = flags,
                                   .retval = 0x7FF800000000,
                                   .caller_retaddr = 0x1400012F4};
    const auto head = ev::encode_api_call_head(payload, fields);
    if (!head.has_value()) {
        return {};
    }
    std::size_t cursor = *head;
    const auto rec =
        ev::append_param_record(payload, cursor, ev::ParamKind::kStrA,
                                {reinterpret_cast<const std::uint8_t*>(arg.data()), arg.size()});
    if (!rec.appended) {
        return {};
    }
    payload.resize(cursor);
    return payload;
}

} // namespace

TEST(EventLedgerTimeline, ApiCallRenderJoinsNames)
{
    behavior::EventLedger ledger;
    ledger.record(ev::EventTypeId::kApiCall, fixture_preamble(0x7FF9000012A0),
                  apicall_fields_stra("LoadLibraryA", 1, ev::kEventFlagSuccess, "ntdll.dll"));

    sheller::TimelineNameTable names;
    names.modules = {"sample.exe", "kernel32"};
    names.apicall_params.emplace("kernel32!LoadLibraryA", std::vector<std::string>{"lpFileName"});

    const auto json = render_full_events(ledger, names);
    EXPECT_NE(json.find("\"type\":\"apicall\""), std::string::npos);
    EXPECT_NE(json.find("\"api\":\"LoadLibraryA\""), std::string::npos);
    EXPECT_NE(json.find("\"module\":\"kernel32\""), std::string::npos);
    EXPECT_NE(json.find("\"status\":true"), std::string::npos);
    EXPECT_NE(json.find("\"return\":\"0x7ff800000000\""), std::string::npos);
    EXPECT_NE(json.find("\"caller\":\"0x1400012f4\""), std::string::npos);
    EXPECT_NE(json.find("\"name\":\"lpFileName\",\"value\":\"ntdll.dll\""), std::string::npos);

    // Without the description entry the same event renders positional names.
    sheller::TimelineNameTable bare;
    bare.modules = names.modules;
    const auto fallback = render_full_events(ledger, bare);
    EXPECT_NE(fallback.find("\"name\":\"arg1\",\"value\":\"ntdll.dll\""), std::string::npos);
}

TEST(EventLedgerTimeline, RawSyscallRendersRawFlagAndPositionalArgs)
{
    behavior::EventLedger ledger;
    std::vector<std::uint8_t> payload(ev::kSyscallFixedBytes + 4 * 11);
    const ev::SyscallFields fields{.number = 0x1A3,
                                   .flags = ev::kEventFlagRaw,
                                   .status = 0xC0000002,
                                   .caller_retaddr = 0x14000195C};
    ASSERT_TRUE(ev::encode_syscall_head(payload, fields).has_value());
    std::size_t cursor = ev::kSyscallFixedBytes;
    for (const std::uint64_t reg : {0x10ULL, 0x20ULL, 0x30ULL, 0x40ULL}) {
        std::vector<std::uint8_t> value(8);
        ev::le::store_le64(value.data(), reg);
        ASSERT_TRUE(ev::append_param_record(payload, cursor, ev::ParamKind::kU64, value).appended);
    }
    payload.resize(cursor);
    ledger.record(ev::EventTypeId::kSyscall, fixture_preamble(0x14000195C), payload);

    const auto json = render_full_events(ledger, sheller::TimelineNameTable{});
    EXPECT_NE(json.find("\"num\":\"0x1a3\""), std::string::npos);
    EXPECT_NE(json.find("\"raw\":true"), std::string::npos);
    EXPECT_NE(json.find("\"status\":\"0xc0000002\""), std::string::npos);
    EXPECT_NE(json.find("\"name\":\"arg1\",\"value\":\"0x10\""), std::string::npos);
    EXPECT_NE(json.find("\"name\":\"arg4\",\"value\":\"0x40\""), std::string::npos);
}

TEST(EventLedgerStub, CountsRenderDeterministically)
{
    behavior::EventLedger ledger;
    ledger.record_stub_call(1, "malloc");
    ledger.record_stub_call(1, "malloc");
    ledger.record_stub_call(1, "memcpy");
    ledger.record_stub_call(4, "?_Src@?1??_Getffldx");
    EXPECT_EQ(ledger.stub_counts().at({1, "malloc"}), 2U);

    const auto json = render_stub_calls_section(ledger);
    // Map order: module index first, then name ("malloc" < "memcpy") - and
    // the side table lands under the report's own stub_calls key.
    EXPECT_EQ(json, "{\"counts\":{},\"detail\":[],\"stub_calls\":{\"1!malloc\":2,\"1!memcpy\":1,"
                    "\"4!?_Src@?1??_Getffldx\":1},"
                    "\"module_sources\":[],"
                    "\"loss\":{\"dropped\":null,\"truncated\":null}}");
    EXPECT_EQ(json, render_stub_calls_section(ledger));
}

TEST(EventLedgerStub, CountsSurviveRingEviction)
{
    behavior::EventLedger ledger{4}; // tiny ring
    ledger.record_stub_call(1, "malloc");
    for (int i = 0; i < 10; ++i) {
        ledger.record(ev::EventTypeId::kBlockExec, fixture_preamble(0x1000), u64_fields(0x1000));
    }
    EXPECT_EQ(ledger.dropped(), 6U); // 10 events in a 4-slot ring; the stub
                                     // side table does not occupy slots
    EXPECT_EQ(ledger.stub_counts().at({1, "malloc"}), 1U);
}

TEST(EventLedgerTimeline, StackSlotsRenderOwnArrayNotArguments)
{
    behavior::EventLedger ledger;
    std::vector<std::uint8_t> payload(ev::kApiCallFixedBytes + 16 + 11 + 2 * 11);
    const ev::ApiCallFields fields{.name = "VirtualAlloc",
                                   .module = 1,
                                   .flags = ev::kEventFlagSuccess,
                                   .retval = 0x1D000000,
                                   .caller_retaddr = 0x14000130C};
    const auto head = ev::encode_api_call_head(payload, fields);
    ASSERT_TRUE(head.has_value());
    std::size_t cursor = *head;
    const std::vector<std::uint8_t> one(8, 0x11);
    ASSERT_TRUE(ev::append_param_record(payload, cursor, ev::ParamKind::kU64, one).appended);
    for (const std::uint64_t slot : {0x140001000ULL, 0x140002000ULL}) {
        std::vector<std::uint8_t> v(8);
        ev::le::store_le64(v.data(), slot);
        ASSERT_TRUE(
            ev::append_param_record(payload, cursor, ev::ParamKind::kStackSlot, v).appended);
    }
    payload.resize(cursor);
    ledger.record(ev::EventTypeId::kApiCall, fixture_preamble(0x7FF9000015E8), payload);

    sheller::TimelineNameTable names;
    names.modules = {"sample.exe", "kernel32"};
    names.apicall_params.emplace(
        "kernel32!VirtualAlloc",
        std::vector<std::string>{"lpAddress", "dwSize", "flAllocationType", "flProtect"});
    const auto json = render_full_events(ledger, names);
    EXPECT_NE(json.find("\"stack\":[\"0x140001000\",\"0x140002000\"]"), std::string::npos);
    EXPECT_EQ(json.find("\"name\":\"arg3\""), std::string::npos);

    behavior::EventLedger bare;
    std::vector<std::uint8_t> plain =
        apicall_fields_stra("LoadLibraryA", 1, ev::kEventFlagSuccess, "ntdll.dll");
    bare.record(ev::EventTypeId::kApiCall, fixture_preamble(0x1000), plain);
    const auto bare_json = render_full_events(bare, names);
    EXPECT_EQ(bare_json.find("\"stack\""), std::string::npos);
}

TEST(EventLedgerTruncation, EventFlagAggregatesIntoCounter)
{
    behavior::EventLedger ledger;
    // syscall head carrying the truncated flag (bit2)
    ledger.record(ev::EventTypeId::kSyscall, fixture_preamble(0x1000),
                  syscall_head_fields(0x55, ev::kEventFlagTruncated));
    // apicall with the flag: flags byte sits past name_len + name + module
    ledger.record(
        ev::EventTypeId::kApiCall, fixture_preamble(0x2000),
        apicall_fields_stra("WriteFile", 1, ev::kEventFlagSuccess | ev::kEventFlagTruncated, "x"));
    // and one clean event: no change
    ledger.record(ev::EventTypeId::kSyscall, fixture_preamble(0x3000), syscall_head_fields(0x56));
    EXPECT_EQ(ledger.truncated(), 2U);
}

} // namespace
