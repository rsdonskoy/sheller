// Report events section tests: the unified seq-ordered detail list over the
// facade's semantic events (all types interleaved, names resolved
// in-library, no grouping, no count cap), the exact counts header, the
// stub-call snapshot, and byte-exact determinism. Pure standard library -
// runs on both platforms. The low-volume event-detail scenarios
// pin here.
//
// The full-level detail is the merged stream over the semantic tier and the
// ledger's TLV window: an ordinal both tiers carry renders once and the
// semantic entry wins it, instruction-level entries interleave by the
// whole-run ordinal, the loss counters carry both fields even at zero, and a
// malformed window tail stops the walk without fabricating an entry.

#include "report_events.h"

#include "../src/cli/render.h"

#include <sheller/analysis.h>
#include <sheller/events.h>

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace ev = sheller;
namespace behavior = sheller::behavior;

ev::EventPreamble fixture_preamble(const std::uint64_t pc)
{
    return ev::EventPreamble{.seq = 0, .tid = 7, .pc = pc};
}

// A semantic event with the common fields; type-specific fields are set by
// the builders below.
ev::SemanticEvent base_event(const ev::EventTypeId type, const std::uint64_t seq,
                             const std::uint64_t pc)
{
    ev::SemanticEvent event;
    event.type = type;
    event.seq = seq;
    event.wire_seq = seq;
    event.tid = 7;
    event.pc = pc;
    return event;
}

ev::SemanticEvent syscall_event(const std::uint64_t seq, const std::uint32_t number,
                                const std::string& name, const std::uint32_t status,
                                const std::uint64_t caller)
{
    auto event = base_event(ev::EventTypeId::kSyscall, seq, 0x140001000);
    event.syscall_number = number;
    event.syscall_name = name;
    event.status = status;
    event.success = true;
    event.caller_retaddr = caller;
    return event;
}

ev::SemanticEvent rdtsc_event(const std::uint64_t seq, const std::uint64_t pc)
{
    return base_event(ev::EventTypeId::kRdtsc, seq, pc);
}

sheller::AnalysisArtifacts fixture_artifacts()
{
    sheller::AnalysisArtifacts artifacts;
    artifacts.instrumented = true;
    artifacts.event_counts[static_cast<std::size_t>(ev::EventTypeId::kBlockExec)] = 3;
    artifacts.event_counts[static_cast<std::size_t>(ev::EventTypeId::kXfer)] = 1;
    artifacts.event_counts[static_cast<std::size_t>(ev::EventTypeId::kSyscall)] = 1;
    artifacts.event_counts[static_cast<std::size_t>(ev::EventTypeId::kRdtsc)] = 1;
    return artifacts;
}

TEST(EventTallyCounts, ExactPerTypeWholeRunCounts)
{
    behavior::EventTally tally;
    tally.on_event(ev::EventTypeId::kBlockExec, fixture_preamble(0x100), {});
    tally.on_event(ev::EventTypeId::kBlockExec, fixture_preamble(0x110), {});
    tally.on_event(ev::EventTypeId::kXfer, fixture_preamble(0x120), {});
    tally.on_event(ev::EventTypeId::kSyscall, fixture_preamble(0x130), {});
    tally.on_event(ev::EventTypeId::kBlockExec, fixture_preamble(0x140), {});
    tally.on_event(ev::EventTypeId::kRdtsc, fixture_preamble(0x150), {});

    EXPECT_EQ(tally.count_of(ev::EventTypeId::kBlockExec), 3U);
    EXPECT_EQ(tally.count_of(ev::EventTypeId::kXfer), 1U);
    EXPECT_EQ(tally.count_of(ev::EventTypeId::kSyscall), 1U);
    EXPECT_EQ(tally.count_of(ev::EventTypeId::kRdtsc), 1U);
    EXPECT_EQ(tally.count_of(ev::EventTypeId::kMemRead), 0U);
    EXPECT_EQ(tally.count_of(ev::EventTypeId::kApiCall), 0U);
    // outside the known id space: ignored, nothing to name
    tally.on_event(static_cast<ev::EventTypeId>(0x7FFF), fixture_preamble(0x160), {});
    EXPECT_EQ(tally.count_of(static_cast<ev::EventTypeId>(0x7FFF)), 0U);
}

TEST(EventsDetail, SeqOrderedUnifiedListAcrossTypes)
{
    // 明细时间序: the timing probe lands before every syscall, and the
    // unified list interleaves the types in arrival order.
    auto artifacts = fixture_artifacts();
    artifacts.semantic_events.push_back(rdtsc_event(1, 0x7ff6e8a115ec));
    artifacts.semantic_events.push_back(syscall_event(2, 0x1000, "NtWriteFile", 0, 0x140001010));
    artifacts.semantic_events.push_back(
        syscall_event(3, 0x1002, "NtTerminateProcess", 0, 0x140001014));

    const auto json = sheller::cli::render_events_section(artifacts);
    const auto rdtsc_pos = json.find("\"type\":\"rdtsc\"");
    const auto syscall_pos = json.find("\"type\":\"syscall\"");
    ASSERT_NE(rdtsc_pos, std::string::npos);
    ASSERT_NE(syscall_pos, std::string::npos);
    EXPECT_LT(rdtsc_pos, syscall_pos);
    // counts header stays intact ahead of the unified detail list
    EXPECT_NE(json.find("\"counts\":{\"block-exec\":3,\"xfer\":1,\"syscall\":1,\"rdtsc\":1}"),
              std::string::npos);
    EXPECT_NE(json.find("\"detail\":["), std::string::npos);
    // no grouping, no omitted counters
    EXPECT_EQ(json.find("\"omitted\""), std::string::npos);
    EXPECT_EQ(json.find("\"items\""), std::string::npos);
}

TEST(EventsDetail, SyscallFieldsWithResolvedName)
{
    auto artifacts = fixture_artifacts();
    artifacts.semantic_events.push_back(
        syscall_event(1, 0x1002, "NtTerminateProcess", 0xC0000022, 0x140001234));
    // unresolvable number: num/status/caller stay, api is omitted
    auto unresolved = syscall_event(2, 0xBEEF, "", 0, 0x140001234);
    unresolved.syscall_name.clear();
    artifacts.semantic_events.push_back(std::move(unresolved));

    const auto json = sheller::cli::render_events_section(artifacts);
    EXPECT_NE(json.find("\"num\":\"0x1002\",\"api\":\"NtTerminateProcess\",\"status\":"
                        "\"0xc0000022\",\"caller\":\"0x140001234\""),
              std::string::npos);
    EXPECT_NE(json.find("\"num\":\"0xbeef\",\"status\""), std::string::npos);
}

TEST(EventsDetail, XferEndpointsAndSentinelClasses)
{
    auto artifacts = fixture_artifacts();
    // module!section landing (module 0 / section 1 = sample.exe!.text)
    auto landed = base_event(ev::EventTypeId::kXfer, 1, 0x140001000);
    landed.from_module = "sample.exe";
    landed.from_section = ".text";
    landed.to_module = "kernel32";
    landed.to_section = ".text";
    artifacts.semantic_events.push_back(std::move(landed));
    // runtime allocation landing: the private-exec sentinel renders bare
    auto alloc = base_event(ev::EventTypeId::kXfer, 2, 0x140002000);
    alloc.from_module = "sample.exe";
    alloc.from_section = ".text";
    alloc.to_module = "private-exec";
    artifacts.semantic_events.push_back(std::move(alloc));

    const auto json = sheller::cli::render_events_section(artifacts);
    EXPECT_NE(json.find("\"from\":\"sample.exe!.text\",\"to\":\"kernel32!.text\""),
              std::string::npos);
    EXPECT_NE(json.find("\"to\":\"private-exec\""), std::string::npos);
}

TEST(EventsDetail, FullTypeCoverageIncludingTruncationFlag)
{
    auto artifacts = fixture_artifacts();
    auto exception = base_event(ev::EventTypeId::kException, 1, 0x140001000);
    exception.exception_code = 0xC0000005;
    artifacts.semantic_events.push_back(std::move(exception));
    auto thread = base_event(ev::EventTypeId::kThreadCreate, 2, 0x140001000);
    thread.new_tid = 42;
    thread.start_routine = 0x7FF600001000;
    artifacts.semantic_events.push_back(std::move(thread));
    auto cpuid = base_event(ev::EventTypeId::kCpuid, 3, 0x140001004);
    artifacts.semantic_events.push_back(std::move(cpuid));
    auto truncated = syscall_event(4, 0x1000, "NtWriteFile", 0, 0x140001000);
    truncated.truncated = true;
    artifacts.semantic_events.push_back(std::move(truncated));

    const auto json = sheller::cli::render_events_section(artifacts);
    EXPECT_NE(json.find("\"type\":\"exception\",\"seq\":1,\"code\":\"0xc0000005\""),
              std::string::npos);
    EXPECT_NE(json.find("\"type\":\"thread-create\",\"seq\":2,\"new_tid\":42,\"start\":"
                        "\"0x7ff600001000\""),
              std::string::npos);
    EXPECT_NE(json.find("\"type\":\"cpuid\",\"seq\":3,\"pc\":\"0x140001004\""), std::string::npos);
    // a cut payload keeps its entry and carries the flag
    EXPECT_NE(json.find("\"truncated\":true"), std::string::npos);
}

std::size_t occurrences(const std::string& text, const std::string_view needle)
{
    std::size_t count = 0;
    for (auto pos = text.find(needle); pos != std::string::npos;
         pos = text.find(needle, pos + needle.size())) {
        ++count;
    }
    return count;
}

// The rendered section split at its newlines: the detail layout is one entry
// per line, so the line boundaries are what the layout cases pin.
std::vector<std::string_view> lines_of(const std::string& text)
{
    std::vector<std::string_view> lines;
    std::string_view view{text};
    while (!view.empty()) {
        const auto break_at = view.find('\n');
        if (break_at == std::string_view::npos) {
            lines.push_back(view);
            break;
        }
        lines.push_back(view.substr(0, break_at));
        view.remove_prefix(break_at + 1);
    }
    return lines;
}

TEST(EventsDetail, DetailRendersOneEntryPerLine)
{
    // The file is read as lines: the header opens the array, every event takes
    // exactly one line, and the closing bracket opens the tail line.
    auto artifacts = fixture_artifacts();
    artifacts.semantic_events.push_back(rdtsc_event(1, 0x140001014));
    artifacts.semantic_events.push_back(syscall_event(2, 0x1000, "NtWriteFile", 0, 0x140001010));

    const auto json = sheller::cli::render_events_section(artifacts);
    const auto lines = lines_of(json);
    ASSERT_EQ(lines.size(), 4U);
    EXPECT_TRUE(lines[0].ends_with("\"detail\":[")) << lines[0];
    EXPECT_TRUE(lines[1].starts_with("{\"type\":\"rdtsc\"")) << lines[1];
    EXPECT_TRUE(lines[1].ends_with("},")) << lines[1]; // entry, then the separator
    EXPECT_TRUE(lines[2].starts_with("{\"type\":\"syscall\"")) << lines[2];
    EXPECT_TRUE(lines[2].ends_with('}')) << lines[2];
    EXPECT_TRUE(lines[3].starts_with("],\"stub_calls\":")) << lines[3];
}

TEST(EventsDetail, IdenticalEntriesMergeWithCountAndFirstEightSeqs)
{
    // Same rendered fields apart from seq: one line, first occurrence keeps
    // seq, and the group carries the total count plus the first 8 seqs.
    sheller::AnalysisArtifacts artifacts;
    for (std::uint64_t i = 1; i <= 20; ++i) {
        artifacts.semantic_events.push_back(rdtsc_event(i, 0x140001014));
    }
    artifacts.semantic_events.push_back(rdtsc_event(21, 0x140001018));

    const auto json = sheller::cli::render_events_section(artifacts);
    EXPECT_EQ(occurrences(json, "\"type\":\"rdtsc\""), 2U) << json;
    EXPECT_NE(json.find("{\"type\":\"rdtsc\",\"seq\":1,\"pc\":\"0x140001014\",\"count\":20,"
                        "\"seqs\":[1,2,3,4,5,6,7,8]}"),
              std::string::npos)
        << json;
    EXPECT_NE(json.find("{\"type\":\"rdtsc\",\"seq\":21,\"pc\":\"0x140001018\"}"),
              std::string::npos)
        << json;
}

TEST(EventsDetail, SecondaryAuxDoesNotSplitKusdGroups)
{
    // kusd-access's aux is a secondary key: the first value stays in the
    // entry and aux_last appears when the group saw another value.
    sheller::AnalysisArtifacts artifacts;
    for (std::uint64_t i = 0; i < 4; ++i) {
        auto event = base_event(sheller::EventTypeId::kKusdAccess, i + 1, 0x1400032EA);
        event.address = 0x7FFE0004;
        event.aux = 0x100 + i;
        artifacts.semantic_events.push_back(std::move(event));
    }

    const auto json = sheller::cli::render_events_section(artifacts);
    EXPECT_EQ(occurrences(json, "\"type\":\"kusd-access\""), 1U) << json;
    EXPECT_NE(json.find("{\"type\":\"kusd-access\",\"seq\":1,\"pc\":\"0x1400032ea\","
                        "\"address\":\"0x7ffe0004\",\"aux\":\"0x100\",\"subtype\":\"\","
                        "\"api\":\"\",\"aux_last\":\"0x103\",\"count\":4,"
                        "\"seqs\":[1,2,3,4]}"),
              std::string::npos)
        << json;
}

TEST(EventsDetail, JudgmentAndForwardedEntriesCarryTheirFields)
{
    auto artifacts = fixture_artifacts();
    auto anti = base_event(ev::EventTypeId::kAntiDebug, 1, 0x140001000);
    anti.address = 0x140002000;
    anti.aux = 0x1234;
    anti.subtype = static_cast<std::uint32_t>(ev::AntiDebugSubtype::kRdtscBurst);
    artifacts.semantic_events.push_back(std::move(anti));

    auto memread = base_event(ev::EventTypeId::kMemRead, 2, 0x140001010);
    memread.address = 0x7FFE0324;
    memread.access_size = 4;
    memread.value = 0x1234;
    artifacts.semantic_events.push_back(std::move(memread));

    auto memwrite = base_event(ev::EventTypeId::kMemWrite, 3, 0x140001020);
    memwrite.address = 0x3000;
    memwrite.access_size = 8;
    artifacts.semantic_events.push_back(std::move(memwrite));

    const auto json = sheller::cli::render_events_section(artifacts);
    EXPECT_NE(json.find("\"type\":\"anti-debug\",\"seq\":1,\"pc\":\"0x140001000\","
                        "\"address\":\"0x140002000\",\"aux\":\"0x1234\","
                        "\"subtype\":\"rdtsc-burst\",\"api\":\"\""),
              std::string::npos)
        << json;
    EXPECT_NE(json.find("\"type\":\"mem-read\",\"seq\":2,\"pc\":\"0x140001010\","
                        "\"addr\":\"0x7ffe0324\",\"size\":4,\"value\":\"0x1234\""),
              std::string::npos)
        << json;
    EXPECT_NE(json.find("\"type\":\"mem-write\",\"seq\":3,\"pc\":\"0x140001020\","
                        "\"addr\":\"0x3000\",\"size\":8}"),
              std::string::npos)
        << json;
}

TEST(EventsDetail, SemanticSeqIsTheWholeRunOrdinalToo)
{
    // The retired two-space spelling used the arrival ordinal at semantic
    // level; both levels now carry the whole-run seq.
    sheller::AnalysisArtifacts artifacts;
    auto event = syscall_event(1, 0x1000, "NtWriteFile", 0, 0x140001000);
    event.wire_seq = 7;
    artifacts.semantic_events.push_back(std::move(event));
    const auto json = sheller::cli::render_events_section(artifacts);
    EXPECT_NE(json.find("\"type\":\"syscall\",\"seq\":7"), std::string::npos) << json;
    EXPECT_EQ(json.find("\"type\":\"syscall\",\"seq\":1"), std::string::npos) << json;
}

TEST(EventsDetail, RawExceptionAndDispositionAreDistinctNames)
{
    // The old name collision: the raw exception event and the exception
    // judgment both spelled "exception". The judgment is now
    // exception-disposition, and no tier discriminator is needed.
    auto artifacts = fixture_artifacts();
    auto raw = base_event(ev::EventTypeId::kException, 1, 0x140001000);
    raw.exception_code = 0xC0000005;
    artifacts.semantic_events.push_back(std::move(raw));
    auto disposition = base_event(ev::EventTypeId::kExceptionDisposition, 2, 0x140001004);
    disposition.subtype = static_cast<std::uint32_t>(ev::ExceptionDisposition::kUnhandled);
    disposition.aux = 0xC0000005;
    artifacts.semantic_events.push_back(std::move(disposition));

    const auto json = sheller::cli::render_events_section(artifacts);
    EXPECT_NE(json.find("\"type\":\"exception\",\"seq\":1"), std::string::npos) << json;
    EXPECT_NE(json.find("\"type\":\"exception-disposition\",\"seq\":2"), std::string::npos) << json;
    EXPECT_EQ(json.find("\"tier\""), std::string::npos) << json;
    EXPECT_EQ(occurrences(json, "\"type\":\"exception\""), 1U) << json;
}

TEST(EventsDetail, NoCountCapOnTheDetailList)
{
    auto artifacts = fixture_artifacts();
    for (std::uint64_t i = 0; i < 200; ++i) {
        artifacts.semantic_events.push_back(
            syscall_event(i + 1, static_cast<std::uint32_t>(i), "", 0, 0x140001000));
    }
    const auto json = sheller::cli::render_events_section(artifacts);
    // every entry survives: first and last both render, no omission counters
    EXPECT_NE(json.find("\"num\":\"0x0\""), std::string::npos);
    EXPECT_NE(json.find("\"num\":\"0xc7\""), std::string::npos); // 199
    EXPECT_EQ(json.find("\"num\":\"0xc8\""), std::string::npos); // 200 would be past the end
    EXPECT_EQ(json.find("\"omitted\""), std::string::npos);
}

TEST(EventsDetail, EmptyArtifactsRenderFiveKeys)
{
    const sheller::AnalysisArtifacts artifacts;
    EXPECT_EQ(sheller::cli::render_events_section(artifacts),
              "{\"counts\":{},\"detail\":[],\"stub_calls\":{},"
              "\"module_sources\":[],\"loss\":{\"dropped\":null,\"truncated\":null}}");
}

TEST(EventsDetail, CountsLevelEmitsNoDetailEntries)
{
    // The counts level is the compact report: the counts header and side
    // tables stay, detail is empty, and no ledger exists (null loss).
    auto artifacts = fixture_artifacts();
    artifacts.semantic_events.push_back(rdtsc_event(1, 0x140001014));
    artifacts.stub_calls.push_back({1, "kernel32", "malloc", 1});

    const auto json =
        sheller::cli::render_events_section(artifacts, sheller::cli::EventLevel::Counts);
    EXPECT_EQ(json, "{\"counts\":{\"block-exec\":3,\"xfer\":1,\"syscall\":1,\"rdtsc\":1},"
                    "\"detail\":[],\"stub_calls\":{\"kernel32!malloc\":1},"
                    "\"module_sources\":[],\"loss\":{\"dropped\":null,\"truncated\":null}}");
}

TEST(EventsStub, SideTableSnapshotResolvedNamesBeforeLoss)
{
    auto artifacts = fixture_artifacts();
    artifacts.stub_calls.push_back({0, "sample.exe", "ExitProcess", 1});
    artifacts.stub_calls.push_back({1, "ucrtbase", "malloc", 2});
    artifacts.stub_calls.push_back({1, "ucrtbase", "memcpy", 1});

    const auto json = sheller::cli::render_events_section(artifacts);
    // (module, name) order, resolved through the artifact's module names; the
    // side table sits before the always-present loss key.
    EXPECT_NE(json.find(",\"stub_calls\":{\"sample.exe!ExitProcess\":1,"
                        "\"ucrtbase!malloc\":2,\"ucrtbase!memcpy\":1},"
                        "\"module_sources\":[],\"loss\":{\"dropped\":null,\"truncated\":null}}"),
              std::string::npos)
        << json;
    EXPECT_TRUE(
        json.ends_with("\"ucrtbase!memcpy\":1},"
                       "\"module_sources\":[],\"loss\":{\"dropped\":null,\"truncated\":null}}"))
        << json;
}

TEST(EventsStub, SentinelAndOutOfRangeModulesKeepNameShapedKeys)
{
    // The facade resolves every stub module index through the run's name
    // table: a region sentinel spells its class and an out-of-range index
    // spells "runtime" (never an empty name), so the report's keys stay
    // "module!name" shaped instead of degrading to the raw index.
    auto artifacts = fixture_artifacts();
    artifacts.stub_calls.push_back({0xFF01, "private-exec", "malloc", 1});
    artifacts.stub_calls.push_back({0xFFFF, "runtime", "memcpy", 2});

    const auto json = sheller::cli::render_events_section(artifacts);
    EXPECT_NE(json.find("\"private-exec!malloc\":1"), std::string::npos) << json;
    EXPECT_NE(json.find("\"runtime!memcpy\":2"), std::string::npos) << json;
    EXPECT_EQ(json.find("\"65281!"), std::string::npos) << json;
    EXPECT_EQ(json.find("\"65535!"), std::string::npos) << json;
}

TEST(BehaviorReportRender, JudgmentApiNamesAreJsonEscaped)
{
    // api rides in from guest-controlled export names: quotes/backslashes
    // must not break the JSON envelope. Byte-exact on purpose - a substring
    // check passes even when the envelope carries a stray quote, which is how
    // a malformed report once reached the tree.
    sheller::AnalysisArtifacts artifacts;
    auto judgment = base_event(ev::EventTypeId::kExportWalk, 1, 0x140001000);
    judgment.address = 0x600001100;
    judgment.aux = 0;
    judgment.subtype = 0;
    judgment.judgment_api = "ba\"d\\x";
    artifacts.semantic_events.push_back(std::move(judgment));
    const auto json = sheller::cli::render_events_section(artifacts);
    const std::string expected =
        "{\"counts\":{},\"detail\":[\n{\"type\":\"export-walk\",\"seq\":1,"
        "\"pc\":\"0x140001000\",\"address\":\"0x600001100\",\"aux\":\"0x0\",\"subtype\":\"\","
        "\"api\":\"ba\\\"d\\\\x\"}\n],\"stub_calls\":{},"
        "\"module_sources\":[],\"loss\":{\"dropped\":null,\"truncated\":null}}";
    EXPECT_EQ(json, expected);
}

TEST(EventsRender, ByteExactShapeAcrossAllClasses)
{
    auto artifacts = fixture_artifacts();
    artifacts.semantic_events.push_back(rdtsc_event(1, 0x140001014));
    auto landed = base_event(ev::EventTypeId::kXfer, 2, 0x140001000);
    landed.from_module = "sample.exe";
    landed.from_section = ".text";
    landed.to_module = "runtime";
    artifacts.semantic_events.push_back(std::move(landed));
    artifacts.semantic_events.push_back(
        syscall_event(3, 0x1002, "NtTerminateProcess", 0, 0x140001000));
    auto apicall = base_event(ev::EventTypeId::kApiCall, 4, 0x7FF9000012A0);
    apicall.api_name = "LoadLibraryA";
    apicall.api_module = "kernel32";
    apicall.retval = 0x7FF800000000;
    apicall.caller_retaddr = 0x1400012F4;
    apicall.success = true;
    artifacts.semantic_events.push_back(std::move(apicall));
    artifacts.stub_calls.push_back({1, "kernel32", "malloc", 1});

    const auto json = sheller::cli::render_events_section(artifacts);
    const std::string expected =
        "{\"counts\":{\"block-exec\":3,\"xfer\":1,\"syscall\":1,\"rdtsc\":1},"
        "\"detail\":[\n"
        "{\"type\":\"rdtsc\",\"seq\":1,\"pc\":\"0x140001014\"},\n"
        "{\"type\":\"xfer\",\"seq\":2,\"from\":\"sample.exe!.text\",\"to\":\"runtime\"},\n"
        "{\"type\":\"syscall\",\"seq\":3,\"num\":\"0x1002\",\"api\":\"NtTerminateProcess\","
        "\"status\":\"0x0\",\"caller\":\"0x140001000\"},\n"
        "{\"type\":\"apicall\",\"seq\":4,\"api\":\"kernel32!LoadLibraryA\","
        "\"retval\":\"0x7ff800000000\",\"caller\":\"0x1400012f4\"}\n],"
        "\"stub_calls\":{\"kernel32!malloc\":1},"
        "\"module_sources\":[],\"loss\":{\"dropped\":null,\"truncated\":null}}";
    EXPECT_EQ(json, expected);
    EXPECT_EQ(json, sheller::cli::render_events_section(artifacts)); // byte-identical
}

// --- The full-level unified stream ---------------------------------------
//
// Fixtures for the merge: the semantic tier's join key is wire_seq (the
// whole-run ordinal), the ledger window is the facade's own TLV bytes built
// with the public codec, preamble.seq in that same ordinal space.

ev::EventPreamble tlv_preamble(const std::uint64_t seq, const std::uint64_t pc)
{
    return ev::EventPreamble{.seq = seq, .tid = 7, .pc = pc};
}

std::vector<std::uint8_t> u64_fields(const std::uint64_t value)
{
    std::vector<std::uint8_t> bytes(sizeof(std::uint64_t));
    ev::le::store_le64(bytes.data(), value);
    return bytes;
}

// A function-form syscall payload with no parameter records - the wire twin of
// a semantic syscall carries no resolved name, which is what tells the two
// spellings apart in these cases.
std::vector<std::uint8_t> tlv_syscall_fields(const std::uint32_t number)
{
    std::vector<std::uint8_t> payload(ev::kSyscallFixedBytes);
    const auto written = ev::encode_syscall_head(
        payload, ev::SyscallFields{
                     .number = number, .flags = 0, .status = 0, .caller_retaddr = 0x140001010});
    EXPECT_TRUE(written.has_value());
    return payload;
}

void append_tlv_event(std::vector<std::uint8_t>& out, const ev::EventTypeId type,
                      const ev::EventPreamble& preamble, const std::vector<std::uint8_t>& fields)
{
    std::vector<std::uint8_t> buffer(ev::kEventHeaderSize + ev::kEventPreambleSize + fields.size());
    const auto written = ev::encode_event(buffer, type, preamble, fields);
    ASSERT_TRUE(written.has_value());
    out.insert(out.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*written));
}

auto render_full(const sheller::AnalysisArtifacts& artifacts)
{
    return sheller::cli::render_events_section(artifacts, sheller::cli::EventLevel::Full);
}

TEST(EventsDetailFullLevel, DetailRendersOneEntryPerLine)
{
    // The merged path writes through its own cursor; it owns the same line
    // layout as the semantic path.
    sheller::AnalysisArtifacts artifacts;
    append_tlv_event(artifacts.timeline_tlv, ev::EventTypeId::kBlockExec,
                     tlv_preamble(1, 0x140001000), u64_fields(0x140001000));
    append_tlv_event(artifacts.timeline_tlv, ev::EventTypeId::kMemWrite,
                     tlv_preamble(2, 0x140001010), {});

    const auto json = render_full(artifacts);
    const auto lines = lines_of(json);
    ASSERT_EQ(lines.size(), 4U);
    EXPECT_TRUE(lines[0].ends_with("\"detail\":[")) << lines[0];
    EXPECT_TRUE(lines[1].starts_with("{\"type\":\"block-exec\"")) << lines[1];
    EXPECT_TRUE(lines[2].starts_with("{\"type\":\"mem-write\"")) << lines[2];
    EXPECT_TRUE(lines[3].starts_with("],\"stub_calls\":")) << lines[3];
}

TEST(EventsDetailFullLevel, SemanticEntryWinsTheSharedOrdinal)
{
    // One underlying event on both tiers: the stream holds it exactly once, in
    // the semantic spelling (the resolved name only that tier carries).
    sheller::AnalysisArtifacts artifacts;
    auto syscall = syscall_event(1, 0x1002, "NtTerminateProcess", 0, 0x140001010);
    syscall.wire_seq = 2;
    artifacts.semantic_events.push_back(std::move(syscall));
    append_tlv_event(artifacts.timeline_tlv, ev::EventTypeId::kSyscall,
                     tlv_preamble(2, 0x140001010), tlv_syscall_fields(0x1002));

    const auto json = render_full(artifacts);
    EXPECT_EQ(occurrences(json, "\"type\":\"syscall\""), 1U) << json;
    EXPECT_NE(json.find("\"api\":\"NtTerminateProcess\""), std::string::npos) << json;
    EXPECT_EQ(json.find("\"raw\""), std::string::npos) << json;
}

TEST(EventsDetailFullLevel, SemanticTypeMissingFromTheTierStillRendersFromTheWindow)
{
    // A semantic-type event the semantic tier dropped (payload decode failure)
    // owns no ordinal in the dedup set, so its window entry surfaces - the
    // merge adds to what the semantic level shows, never takes away.
    sheller::AnalysisArtifacts artifacts;
    auto syscall = syscall_event(1, 0x1002, "NtTerminateProcess", 0, 0x140001010);
    syscall.wire_seq = 1;
    artifacts.semantic_events.push_back(std::move(syscall));
    append_tlv_event(artifacts.timeline_tlv, ev::EventTypeId::kSyscall,
                     tlv_preamble(1, 0x140001010), tlv_syscall_fields(0x1002));
    append_tlv_event(artifacts.timeline_tlv, ev::EventTypeId::kSyscall,
                     tlv_preamble(2, 0x140001020), tlv_syscall_fields(0x1000));

    const auto json = render_full(artifacts);
    EXPECT_EQ(occurrences(json, "\"type\":\"syscall\""), 2U) << json;
    EXPECT_NE(json.find("\"seq\":2,\"tid\":7,\"pc\":\"0x140001020\",\"num\":\"0x1000\""),
              std::string::npos)
        << json;
}

TEST(EventsDetailFullLevel, UnifiedStreamIsByteExactInWireOrder)
{
    // Instruction-level entries and semantic entries interleave by the
    // whole-run ordinal, and the arrival order the semantic level sorts by is
    // not what the full level spells as seq.
    sheller::AnalysisArtifacts artifacts;
    auto syscall = syscall_event(1, 0x1002, "NtTerminateProcess", 0, 0x140001010);
    syscall.wire_seq = 2; // arrival 1, whole-run ordinal 2
    artifacts.semantic_events.push_back(std::move(syscall));
    auto timing = rdtsc_event(2, 0x140002000);
    timing.wire_seq = 4; // arrival 2, whole-run ordinal 4
    artifacts.semantic_events.push_back(timing);

    append_tlv_event(artifacts.timeline_tlv, ev::EventTypeId::kBlockExec,
                     tlv_preamble(1, 0x140001000), u64_fields(0x140001000));
    append_tlv_event(artifacts.timeline_tlv, ev::EventTypeId::kSyscall,
                     tlv_preamble(2, 0x140001010), tlv_syscall_fields(0x1002));
    append_tlv_event(artifacts.timeline_tlv, ev::EventTypeId::kMemRead,
                     tlv_preamble(3, 0x140001020), {});
    append_tlv_event(artifacts.timeline_tlv, ev::EventTypeId::kRdtsc, tlv_preamble(4, 0x140002000),
                     {});
    append_tlv_event(artifacts.timeline_tlv, ev::EventTypeId::kBlockExec,
                     tlv_preamble(5, 0x140003000), u64_fields(0x140003000));

    const auto json = render_full(artifacts);
    const std::string expected =
        "{\"counts\":{},\"detail\":[\n"
        "{\"type\":\"block-exec\",\"seq\":1,\"tid\":7,\"pc\":\"0x140001000\","
        "\"addr\":\"0x140001000\"},\n"
        "{\"type\":\"syscall\",\"seq\":2,\"tid\":7,\"pc\":\"0x140001000\",\"num\":\"0x1002\","
        "\"api\":\"NtTerminateProcess\",\"status\":\"0x0\",\"caller\":\"0x140001010\"},\n"
        "{\"type\":\"mem-read\",\"seq\":3,\"tid\":7,\"pc\":\"0x140001020\"},\n"
        "{\"type\":\"rdtsc\",\"seq\":4,\"tid\":7,\"pc\":\"0x140002000\"},\n"
        "{\"type\":\"block-exec\",\"seq\":5,\"tid\":7,\"pc\":\"0x140003000\","
        "\"addr\":\"0x140003000\"}\n],"
        "\"stub_calls\":{},"
        "\"module_sources\":[],\"loss\":{\"dropped\":0,\"truncated\":0}}";
    EXPECT_EQ(json, expected);
    EXPECT_EQ(json, render_full(artifacts));
}

TEST(EventsDetailFullLevel, SemanticHeadCarriesTidAndPcOnce)
{
    auto artifacts = fixture_artifacts();
    artifacts.semantic_events.push_back(
        syscall_event(1, 0x1002, "NtTerminateProcess", 0, 0x140001234));
    artifacts.semantic_events.push_back(base_event(ev::EventTypeId::kCpuid, 2, 0x140001004));

    // The semantic level spells neither tid nor a head pc - and cpuid/rdtsc
    // carry pc in their payload.
    const auto semantic = sheller::cli::render_events_section(artifacts);
    EXPECT_EQ(semantic.find("\"tid\":"), std::string::npos) << semantic;
    EXPECT_NE(semantic.find("\"type\":\"cpuid\",\"seq\":2,\"pc\":\"0x140001004\""),
              std::string::npos)
        << semantic;

    // At full level the head carries both, so the payload stops spelling pc a
    // second time: one entry, one pc key.
    const auto full = render_full(artifacts);
    EXPECT_NE(full.find("\"type\":\"syscall\",\"seq\":1,\"tid\":7,\"pc\":\"0x140001000\""),
              std::string::npos)
        << full;
    EXPECT_NE(full.find("{\"type\":\"cpuid\",\"seq\":2,\"tid\":7,\"pc\":\"0x140001004\"}"),
              std::string::npos)
        << full;
    EXPECT_EQ(occurrences(full, "\"pc\":"), 2U) << full;
}

TEST(EventsDetailFullLevel, LossNullAtSemanticAndCountersAtFull)
{
    auto artifacts = fixture_artifacts();
    artifacts.semantic_events.push_back(rdtsc_event(1, 0x140001014));

    const auto semantic = sheller::cli::render_events_section(artifacts);
    // No ledger at semantic level: null says "not observable", 0 would lie.
    EXPECT_NE(semantic.find("\"module_sources\":[],\"loss\":{\"dropped\":null,\"truncated\":null}"),
              std::string::npos)
        << semantic;

    // Zero still renders both fields - the presence is the contract.
    const auto clean = render_full(artifacts);
    EXPECT_NE(clean.find("\"module_sources\":[],\"loss\":{\"dropped\":0,\"truncated\":0}"),
              std::string::npos)
        << clean;

    artifacts.timeline_dropped = 7;
    artifacts.timeline_truncated = 2;
    const auto lossy = render_full(artifacts);
    EXPECT_NE(lossy.find("\"loss\":{\"dropped\":7,\"truncated\":2}"), std::string::npos) << lossy;
    // The default-column types are not the window's: their entries stand
    // whatever the ledger dropped.
    EXPECT_NE(lossy.find("\"type\":\"rdtsc\""), std::string::npos) << lossy;
}

TEST(EventsDetailFullLevel, MalformedTailStopsTheWalkWithoutAFakeEntry)
{
    std::vector<std::uint8_t> clean;
    append_tlv_event(clean, ev::EventTypeId::kBlockExec, tlv_preamble(1, 0x140001000),
                     u64_fields(0x140001000));
    append_tlv_event(clean, ev::EventTypeId::kMemWrite, tlv_preamble(2, 0x140001010), {});
    ASSERT_FALSE(sheller::cli::tlv_window_has_malformed_tail(clean));

    // A header cut mid-event: the walk stops at it, and that is what the CLI
    // warns about - the predicate has to say so for this stream and not for
    // the intact one.
    auto torn = clean;
    torn.push_back(static_cast<std::uint8_t>(0xAB));
    torn.push_back(static_cast<std::uint8_t>(0x00));
    ASSERT_TRUE(sheller::cli::tlv_window_has_malformed_tail(torn));

    sheller::AnalysisArtifacts artifacts;
    artifacts.timeline_tlv = torn;
    const auto json = render_full(artifacts);
    EXPECT_NE(json.find("{\"type\":\"mem-write\",\"seq\":2,\"tid\":7,\"pc\":\"0x140001010\"}"),
              std::string::npos)
        << json;
    EXPECT_EQ(occurrences(json, "\"type\":"), 2U) << json;
    EXPECT_EQ(json.find("unknown"), std::string::npos) << json;
    EXPECT_EQ(json, render_full(artifacts));
}

} // namespace
