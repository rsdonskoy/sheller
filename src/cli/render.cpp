#include "render.h"

#include <sheller/events.h>

#include <array>
#include <format>
#include <map>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sheller::cli {
namespace {

// Lowercase 0x-prefixed hex without leading zeros (0 -> "0x0"): the one
// address spelling of the JSON renders.
void append_hex(std::string& out, const std::uint64_t value)
{
    static constexpr char kDigits[] = "0123456789abcdef";
    out.push_back('0');
    out.push_back('x');
    auto started = false;
    for (auto shift = 60; shift >= 0; shift -= 4) {
        const auto nibble = (value >> shift) & 0xFu;
        if (nibble == 0 && !started && shift != 0) {
            continue;
        }
        out.push_back(kDigits[nibble]);
        started = true;
    }
}

// Minimal JSON string escaping: quotes, backslash, control chars as \u00XX.
// Everything else passes through (payload names are already UTF-8).
void append_json_string(std::string& out, const std::string_view value)
{
    out.push_back('"');
    for (const char c : value) {
        const auto uc = static_cast<unsigned char>(c);
        if (c == '"' || c == '\\') {
            out.push_back('\\');
            out.push_back(c);
        } else if (uc < 0x20) {
            out += "\\u00";
            out += std::format("{:02x}", uc);
        } else {
            out.push_back(c);
        }
    }
    out.push_back('"');
}

// Walks the TLV stream: one decoded event per call, oldest first. A
// malformed tail stops the walk deterministically (never a fabricated
// event). The returned cursor is where the walk stopped, so a caller holding
// the stream size can tell a clean end from a truncated one.
template <typename Fn> std::size_t for_each_tlv_event(std::span<const std::uint8_t> tlv, Fn&& fn)
{
    std::size_t cursor = 0;
    while (cursor < tlv.size()) {
        const auto view = sheller::read_event(tlv.subspan(cursor));
        if (!view.has_value()) {
            break;
        }
        const auto preamble = sheller::read_preamble(view->payload);
        if (!preamble.has_value()) {
            break;
        }
        fn(view->type, *preamble, view->payload.subspan(sheller::kEventPreambleSize));
        cursor += view->total_size;
    }
    return cursor;
}

// One decoded TLV entry, kept as a view over the artifact's own bytes. The
// merge walk needs the window indexed alongside the semantic records; decode
// order is stream order, so the vector is already ascending by preamble.seq.
struct TlvEntry {
    sheller::EventTypeId type{};
    sheller::EventPreamble preamble{};
    std::span<const std::uint8_t> fields{};
};

std::vector<TlvEntry> collect_tlv_entries(std::span<const std::uint8_t> tlv)
{
    std::vector<TlvEntry> entries;
    static_cast<void>(for_each_tlv_event(tlv, [&](const sheller::EventTypeId type,
                                                  const sheller::EventPreamble& preamble,
                                                  const std::span<const std::uint8_t> fields) {
        entries.push_back(TlvEntry{.type = type, .preamble = preamble, .fields = fields});
    }));
    return entries;
}

// One parameter record as {"name":..,"value":..[,"truncated":true]}. The
// value spelling per kind: numbers/pointers hex, bool literal, strings as
// JSON strings, buffers as hex byte strings, unreadable as null.
void append_param_json(std::string& out, const sheller::SemanticParam& param)
{
    out += "{\"name\":";
    append_json_string(out, param.name);
    out += ",\"value\":";
    switch (param.kind) {
    case ParamKind::kU32:
        out.push_back('"');
        append_hex(out, param.integer);
        out.push_back('"');
        break;
    case ParamKind::kU64:
    case ParamKind::kPtr:
        out.push_back('"');
        append_hex(out, param.integer);
        out.push_back('"');
        break;
    case ParamKind::kBool:
        out += param.integer != 0 ? "true" : "false";
        break;
    case ParamKind::kStrA:
    case ParamKind::kStrW:
        append_json_string(out, param.text);
        break;
    case ParamKind::kBuf:
        out.push_back('"');
        out += "0x";
        for (const auto b : param.bytes) {
            out += std::format("{:02x}", b);
        }
        out.push_back('"');
        break;
    case ParamKind::kUnreadable:
    default:
        out += "null";
        break;
    }
    if (param.truncated) {
        out += ",\"truncated\":true";
    }
    out.push_back('}');
}

// Parameter records (stack slots excluded - they render as the separate
// "stack" array, raw values above the caller's return address).
void append_arguments_json(std::string& out, const sheller::SemanticEvent& event)
{
    bool has_params = false;
    for (const auto& param : event.params) {
        if (param.kind != ParamKind::kStackSlot) {
            has_params = true;
            break;
        }
    }
    if (has_params) {
        out += ",\"arguments\":[";
        bool first = true;
        for (const auto& param : event.params) {
            if (param.kind == ParamKind::kStackSlot) {
                continue;
            }
            if (!first) {
                out.push_back(',');
            }
            first = false;
            append_param_json(out, param);
        }
        out.push_back(']');
    }
    bool has_slots = false;
    for (const auto& param : event.params) {
        if (param.kind == ParamKind::kStackSlot) {
            has_slots = true;
            break;
        }
    }
    if (has_slots) {
        out += ",\"stack\":[";
        bool first = true;
        for (const auto& param : event.params) {
            if (param.kind != ParamKind::kStackSlot) {
                continue;
            }
            if (!first) {
                out.push_back(',');
            }
            first = false;
            out.push_back('"');
            append_hex(out, param.integer);
            out.push_back('"');
        }
        out.push_back(']');
    }
}

// One wire parameter record as {"name":..,"value":..[,"truncated":true]}.
// The value spelling per kind: numbers/pointers hex, bool literal, strings
// as JSON strings, buffers as hex byte strings, unreadable as null. A kind
// whose byte length does not match its nominal size renders as a raw hex
// dump - deterministic, never a malformed object.
void append_wire_param_json(std::string& out, const ParamRecordView& record,
                            const std::string& name)
{
    out += "{\"name\":";
    append_json_string(out, name);
    out += ",\"value\":";
    const auto bytes = record.bytes;
    switch (record.kind) {
    case ParamKind::kU32:
        if (bytes.size() == 4) {
            out.push_back('"');
            append_hex(out, le::load_le32(bytes.data()));
            out.push_back('"');
        } else {
            out += "null";
        }
        break;
    case ParamKind::kU64:
    case ParamKind::kPtr:
        if (bytes.size() == 8) {
            out.push_back('"');
            append_hex(out, le::load_le64(bytes.data()));
            out.push_back('"');
        } else {
            out += "null";
        }
        break;
    case ParamKind::kBool:
        out += bytes.size() == 1 && bytes[0] != 0 ? "true" : "false";
        break;
    case ParamKind::kStrA:
    case ParamKind::kStrW:
        append_json_string(out, {reinterpret_cast<const char*>(bytes.data()), bytes.size()});
        break;
    case ParamKind::kBuf:
        out.push_back('"');
        out += "0x";
        for (const auto b : bytes) {
            out += std::format("{:02x}", b);
        }
        out.push_back('"');
        break;
    case ParamKind::kUnreadable:
    default:
        out += "null";
        break;
    }
    if (record.truncated) {
        out += ",\"truncated\":true";
    }
    out.push_back('}');
}

// Wire parameter-record stream as a JSON array; names come from the
// description table, positional argN past its end. Stack slots render as
// the separate "stack" array - attribution-only, never form parameters.
void append_wire_arguments_json(std::string& out, const std::span<const std::uint8_t> records,
                                const std::vector<std::string>* param_names)
{
    bool has_params = false;
    {
        std::size_t scan = 0;
        while (scan < records.size()) {
            const auto record = sheller::read_param_record(records, scan);
            if (!record.has_value()) {
                break;
            }
            if (record->kind != ParamKind::kStackSlot) {
                has_params = true;
                break;
            }
        }
    }
    if (has_params) {
        out += ",\"arguments\":[";
        std::size_t cursor = 0;
        std::size_t index = 0;
        bool first = true;
        while (cursor < records.size()) {
            const auto record = sheller::read_param_record(records, cursor);
            if (!record.has_value()) {
                break;
            }
            if (record->kind == ParamKind::kStackSlot) {
                continue;
            }
            if (!first) {
                out.push_back(',');
            }
            first = false;
            std::string name;
            if (param_names != nullptr && index < param_names->size()) {
                name = (*param_names)[index];
            } else {
                name = "arg" + std::to_string(index + 1);
            }
            append_wire_param_json(out, *record, name);
            ++index;
        }
        out.push_back(']');
    }
    bool has_slots = false;
    {
        std::size_t scan = 0;
        while (scan < records.size()) {
            const auto record = sheller::read_param_record(records, scan);
            if (!record.has_value()) {
                break;
            }
            if (record->kind == ParamKind::kStackSlot) {
                has_slots = true;
                break;
            }
        }
    }
    if (has_slots) {
        out += ",\"stack\":[";
        std::size_t cursor = 0;
        bool first = true;
        while (cursor < records.size()) {
            const auto record = sheller::read_param_record(records, cursor);
            if (!record.has_value()) {
                break;
            }
            if (record->kind != ParamKind::kStackSlot) {
                continue;
            }
            if (!first) {
                out.push_back(',');
            }
            first = false;
            if (record->bytes.size() == 8) {
                out.push_back('"');
                append_hex(out, le::load_le64(record->bytes.data()));
                out.push_back('"');
            } else {
                out += "null";
            }
        }
        out.push_back(']');
    }
}

// One TLV entry as {"type":..,"seq":..,"tid":..,"pc":..,<payload fields>}:
// seq is the ledger ordinal from the preamble, and the payload decodes from
// the wire (block address, xfer module!section attribution, syscall function
// form, apicall fields, exception code, thread-create tid/start). The single
// builder of instruction-level entries in the full-level unified stream.
void append_tlv_entry_json(std::string& out, const TlvEntry& entry, const TimelineNameTable& names)
{
    const auto type = entry.type;
    const auto fields = entry.fields;
    out += "{\"type\":\"";
    out += sheller::event_type_name(type);
    out += "\",\"seq\":";
    out += std::to_string(entry.preamble.seq);
    out += ",\"tid\":";
    out += std::to_string(entry.preamble.tid);
    out += ",\"pc\":\"";
    append_hex(out, entry.preamble.pc);
    out.push_back('"');
    switch (type) {
    case sheller::EventTypeId::kBlockExec:
        if (fields.size() >= sizeof(std::uint64_t)) {
            out += ",\"addr\":\"";
            append_hex(out, le::load_le64(fields.data()));
            out.push_back('"');
        }
        break;
    case sheller::EventTypeId::kXfer:
        if (fields.size() >= 8) {
            const auto from_module = le::load_le16(fields.data());
            const auto from_section = le::load_le16(fields.data() + 2);
            const auto to_module = le::load_le16(fields.data() + 4);
            const auto to_section = le::load_le16(fields.data() + 6);
            out += ",\"from\":\"";
            out += section_name_of(names, from_module, from_section);
            out += "\",\"to\":\"";
            out += section_name_of(names, to_module, to_section);
            out.push_back('"');
        }
        break;
    case sheller::EventTypeId::kSyscall: {
        const auto call = sheller::read_syscall(fields);
        if (!call.has_value()) {
            break;
        }
        out += ",\"num\":\"";
        append_hex(out, call->fields.number);
        out.push_back('"');
        std::string api_name;
        const auto it = names.syscalls.find(call->fields.number);
        if (it != names.syscalls.end()) {
            api_name = it->second;
            out += ",\"api\":";
            append_json_string(out, api_name);
        }
        if ((call->fields.flags & sheller::kEventFlagRaw) != 0) {
            out += ",\"raw\":true";
        }
        if ((call->fields.flags & sheller::kEventFlagSynthetic) != 0) {
            out += ",\"synthetic\":true";
        }
        out += ",\"status\":\"";
        append_hex(out, call->fields.status);
        out += "\",\"caller\":\"";
        append_hex(out, call->fields.caller_retaddr);
        out.push_back('"');
        const auto param_names = names.apicall_params.find(api_name);
        // Parameter records over the wire: names join from the table,
        // positional argN past its end.
        append_wire_arguments_json(out, call->records,
                                   param_names != names.apicall_params.end() ? &param_names->second
                                                                             : nullptr);
        break;
    }
    case sheller::EventTypeId::kApiCall: {
        const auto call = sheller::read_api_call(fields);
        if (!call.has_value()) {
            break;
        }
        out += ",\"api\":";
        append_json_string(out, call->fields.name);
        out += ",\"module\":\"";
        out += module_name_of(names, call->fields.module);
        out.push_back('"');
        if ((call->fields.flags & sheller::kEventFlagRaw) != 0) {
            out += ",\"raw\":true";
        }
        out += ",\"status\":";
        out += (call->fields.flags & sheller::kEventFlagSuccess) != 0 ? "true" : "false";
        out += ",\"return\":\"";
        append_hex(out, call->fields.retval);
        out += "\",\"caller\":\"";
        append_hex(out, call->fields.caller_retaddr);
        out.push_back('"');
        const auto key =
            module_name_of(names, call->fields.module) + "!" + std::string{call->fields.name};
        const auto param_names = names.apicall_params.find(key);
        append_wire_arguments_json(out, call->records,
                                   param_names != names.apicall_params.end() ? &param_names->second
                                                                             : nullptr);
        break;
    }
    case sheller::EventTypeId::kException:
        if (fields.size() >= sizeof(std::uint32_t)) {
            out += ",\"code\":\"";
            append_hex(out, le::load_le32(fields.data()));
            out.push_back('"');
        }
        break;
    case sheller::EventTypeId::kThreadCreate:
        if (fields.size() >= 12) {
            out += ",\"new_tid\":";
            out += std::to_string(le::load_le32(fields.data()));
            out += ",\"start\":\"";
            append_hex(out, le::load_le64(fields.data() + 4));
            out.push_back('"');
        }
        break;
    case sheller::EventTypeId::kMemRead:
    case sheller::EventTypeId::kMemWrite: {
        const auto access = read_mem_access(fields);
        if (!access.has_value()) {
            break;
        }
        out += ",\"addr\":\"";
        append_hex(out, access->address);
        out += "\",\"size\":";
        out += std::to_string(access->size);
        if (type == sheller::EventTypeId::kMemRead) {
            out += ",\"value\":\"";
            append_hex(out, access->value);
            out.push_back('"');
        }
        break;
    }
    case sheller::EventTypeId::kSampleCode: {
        const auto code = read_sample_code(fields);
        if (!code.has_value()) {
            break;
        }
        out += ",\"length\":";
        out += std::to_string(code->length);
        out += ",\"bytes\":\"0x";
        for (const auto byte : code->bytes) {
            out += std::format("{:02x}", byte);
        }
        out.push_back('"');
        break;
    }
    default:
        // Judgment events: the rule fields, with the subtype spelled for the
        // two kinds that carry one.
        if (is_judgment_event(type)) {
            const auto judgment = read_judgment(fields);
            if (!judgment.has_value()) {
                break;
            }
            out += ",\"address\":\"";
            append_hex(out, judgment->fields.address);
            out += "\",\"aux\":\"";
            append_hex(out, judgment->fields.aux);
            out += "\",\"subtype\":\"";
            out += type == sheller::EventTypeId::kAntiDebug
                       ? anti_debug_subtype_name(judgment->fields.subtype)
                   : type == sheller::EventTypeId::kExceptionDisposition
                       ? exception_disposition_name(judgment->fields.subtype)
                       : std::string_view{};
            out += "\",\"api\":";
            append_json_string(out, judgment->fields.api);
        }
        break;
    }
    out.push_back('}');
}

// One semantic entry: {"type":..,"seq":..,<payload fields>} at semantic level
// and {"type":..,"seq":..,"tid":..,"pc":..,<payload fields>[,"truncated":true]}
// at full level. seq is always the whole-run event ordinal - the report has
// one numbering at both levels. cpuid and rdtsc spell pc in the payload only
// when the head does not already carry it; forwarded facts and judgments
// carry their own pc at semantic level because it is part of the finding.
void append_semantic_entry_json(std::string& out, const sheller::SemanticEvent& event,
                                const EventLevel level)
{
    out += "{\"type\":\"";
    out += sheller::event_type_name(event.type);
    out += "\",\"seq\":";
    out += std::to_string(event.wire_seq);
    if (level == EventLevel::Full) {
        out += ",\"tid\":";
        out += std::to_string(event.tid);
        out += ",\"pc\":\"";
        append_hex(out, event.pc);
        out.push_back('"');
    }
    if (event.truncated && level == EventLevel::Semantic) {
        out += ",\"truncated\":true";
    }
    switch (event.type) {
    case sheller::EventTypeId::kXfer: {
        const auto endpoint = [](const std::string& module, const std::string& section) {
            return section.empty() ? module : module + "!" + section;
        };
        out += ",\"from\":";
        append_json_string(out, endpoint(event.from_module, event.from_section));
        out += ",\"to\":";
        append_json_string(out, endpoint(event.to_module, event.to_section));
        break;
    }
    case sheller::EventTypeId::kSyscall: {
        out += ",\"num\":\"";
        append_hex(out, event.syscall_number);
        out.push_back('"');
        if (!event.syscall_name.empty()) {
            out += ",\"api\":";
            append_json_string(out, event.syscall_name);
        }
        out += ",\"status\":\"";
        append_hex(out, event.status);
        out += "\",\"caller\":\"";
        append_hex(out, event.caller_retaddr);
        out.push_back('"');
        append_arguments_json(out, event);
        break;
    }
    case sheller::EventTypeId::kApiCall: {
        out += ",\"api\":";
        append_json_string(out, event.api_module.empty() ? event.api_name
                                                         : event.api_module + "!" + event.api_name);
        out += ",\"retval\":\"";
        append_hex(out, event.retval);
        out += "\",\"caller\":\"";
        append_hex(out, event.caller_retaddr);
        out.push_back('"');
        append_arguments_json(out, event);
        break;
    }
    case sheller::EventTypeId::kRdtsc:
    case sheller::EventTypeId::kCpuid:
    case sheller::EventTypeId::kStackRestore:
        if (level == EventLevel::Semantic) {
            out += ",\"pc\":\"";
            append_hex(out, event.pc);
            out.push_back('"');
        }
        break;
    case sheller::EventTypeId::kException:
        out += ",\"code\":\"";
        append_hex(out, event.exception_code);
        out.push_back('"');
        break;
    case sheller::EventTypeId::kThreadCreate:
        out += ",\"new_tid\":";
        out += std::to_string(event.new_tid);
        out += ",\"start\":\"";
        append_hex(out, event.start_routine);
        out.push_back('"');
        break;
    case sheller::EventTypeId::kMemRead:
    case sheller::EventTypeId::kMemWrite:
        if (level == EventLevel::Semantic) {
            out += ",\"pc\":\"";
            append_hex(out, event.pc);
            out.push_back('"');
        }
        out += ",\"addr\":\"";
        append_hex(out, event.address);
        out += "\",\"size\":";
        out += std::to_string(event.access_size);
        if (event.type == sheller::EventTypeId::kMemRead) {
            out += ",\"value\":\"";
            append_hex(out, event.value);
            out.push_back('"');
        }
        break;
    default:
        // Judgment types: the rule fields, subtype spelled for the two kinds
        // that carry one (anti-debug, exception-disposition).
        if (is_judgment_event(event.type)) {
            if (level == EventLevel::Semantic) {
                out += ",\"pc\":\"";
                append_hex(out, event.pc);
                out.push_back('"');
            }
            out += ",\"address\":\"";
            append_hex(out, event.address);
            out += "\",\"aux\":\"";
            append_hex(out, event.aux);
            out += "\",\"subtype\":\"";
            out += event.type == sheller::EventTypeId::kAntiDebug
                       ? anti_debug_subtype_name(event.subtype)
                   : event.type == sheller::EventTypeId::kExceptionDisposition
                       ? exception_disposition_name(event.subtype)
                       : std::string_view{};
            out += "\",\"api\":";
            append_json_string(out, event.judgment_api);
        }
        break;
    }
    if (event.truncated && level == EventLevel::Full) {
        out += ",\"truncated\":true";
    }
    out.push_back('}');
}

// Semantic detail grouping: entries whose rendered fields are identical apart
// from seq are one group. The first occurrence keeps the "seq" key (the list
// order), and a repeated group carries the total "count" plus the first 16
// occurrence seqs. This keeps clock-fed runs from writing thousands of
// identical lines without losing the exact per-type counts.
// Per-type secondary detail keys: fields excluded from the grouping identity
// and summarized on the merged entry (the first value stays, and
// <field>_last is added when the group saw another value). Every other
// rendered field apart from seq is the primary key. Only scalar fields are
// supported here; add a type to this table when its variation is noise
// rather than identity.
std::span<const std::string_view> secondary_detail_fields(const sheller::EventTypeId type)
{
    static constexpr std::string_view kAux[] = {"aux"};
    if (type == sheller::EventTypeId::kKusdAccess) {
        return kAux;
    }
    return {};
}

// Removes ,"name":<scalar token> from text and returns the token as rendered
// (a JSON string keeps its quotes). Arrays/objects are not secondary keys.
bool take_json_field(std::string& text, const std::string_view name, std::string& value)
{
    const auto key = std::format(",\"{}\":", name);
    const auto at = text.find(key);
    if (at == std::string::npos) {
        return false;
    }
    const auto value_begin = at + key.size();
    auto value_end = value_begin;
    if (value_begin < text.size() && text[value_begin] == '"') {
        value_end = value_begin + 1;
        while (value_end < text.size()) {
            if (text[value_end] == '\\') {
                value_end += 2;
                continue;
            }
            if (text[value_end] == '"') {
                ++value_end;
                break;
            }
            ++value_end;
        }
    } else {
        while (value_end < text.size() && text[value_end] != ',' && text[value_end] != '}') {
            ++value_end;
        }
    }
    value = text.substr(value_begin, value_end - value_begin);
    text.erase(at, value_end - at);
    return true;
}

struct SemanticGroup {
    std::string entry; // first occurrence, including its seq
    std::uint64_t count{};
    std::array<std::uint64_t, 8> seqs{};
    std::size_t seq_count{};
    struct Secondary {
        std::string_view name;
        std::string last;
        bool changed{};
    };
    std::vector<Secondary> secondary;
};

bool append_semantic_detail_json(std::string& out, const AnalysisArtifacts& artifacts)
{
    std::vector<SemanticGroup> groups;
    std::map<std::string, std::size_t> index;
    for (const auto& event : artifacts.semantic_events) {
        std::string entry;
        append_semantic_entry_json(entry, event, EventLevel::Semantic);

        // Primary key: the rendered entry without seq and without the type's
        // secondary fields.
        std::string key = entry;
        std::vector<std::pair<std::string_view, std::string>> secondary;
        for (const auto name : secondary_detail_fields(event.type)) {
            std::string value;
            if (take_json_field(key, name, value)) {
                secondary.emplace_back(name, std::move(value));
            }
        }
        const auto seq_at = key.find(",\"seq\":");
        const auto value_at = seq_at + 7; // ,"seq":
        auto value_end = value_at;
        while (value_end < key.size() && key[value_end] >= '0' && key[value_end] <= '9') {
            ++value_end;
        }
        key.erase(seq_at, value_end - seq_at);

        const auto [it, inserted] = index.try_emplace(std::move(key), groups.size());
        if (inserted) {
            SemanticGroup group;
            group.entry = entry;
            group.count = 1;
            group.seqs[0] = event.wire_seq;
            group.seq_count = 1;
            for (const auto& [name, value] : secondary) {
                group.secondary.push_back({name, value, false});
            }
            groups.push_back(std::move(group));
        } else {
            auto& group = groups[it->second];
            ++group.count;
            if (group.seq_count < group.seqs.size()) {
                group.seqs[group.seq_count++] = event.wire_seq;
            }
            for (std::size_t i = 0; i < secondary.size() && i < group.secondary.size(); ++i) {
                if (group.secondary[i].last != secondary[i].second) {
                    group.secondary[i].last = std::move(secondary[i].second);
                    group.secondary[i].changed = true;
                }
            }
        }
    }
    for (std::size_t i = 0; i < groups.size(); ++i) {
        const auto& group = groups[i];
        if (i != 0) {
            out.push_back(',');
        }
        out.push_back('\n');
        if (group.count == 1) {
            out += group.entry;
            continue;
        }
        out += group.entry.substr(0, group.entry.size() - 1); // drop the closing }
        for (const auto& secondary : group.secondary) {
            if (secondary.changed) {
                out += std::format(",\"{}_last\":{}", secondary.name, secondary.last);
            }
        }
        out += std::format(",\"count\":{},\"seqs\":[", group.count);
        for (std::size_t s = 0; s < group.seq_count; ++s) {
            if (s != 0) {
                out.push_back(',');
            }
            out += std::to_string(group.seqs[s]);
        }
        out.push_back(']');
        out.push_back('}');
    }
    return !groups.empty();
}

// The full-level detail list: the semantic tier and the ledger window as one
// stream. Both sides ascend in the whole-run event ordinal (semantic records
// arrive in wire order, the ring keeps it), so two cursors over them sort the
// merge with no extra structure. An ordinal both tiers carry is one and the
// same underlying event: the semantic entry renders (never evicted, names
// already resolved) and the TLV twin is skipped - which is also why a
// semantic record whose payload failed to decode still shows up, through the
// TLV side. Returns whether any entry rendered; the caller owns the array
// brackets and the closing line.
bool append_merged_detail_json(std::string& out, const AnalysisArtifacts& artifacts)
{
    const auto entries = collect_tlv_entries(artifacts.timeline_tlv);
    std::set<std::uint64_t> semantic_ordinals;
    for (const auto& event : artifacts.semantic_events) {
        semantic_ordinals.insert(event.wire_seq);
    }
    std::size_t semantic_index = 0;
    std::size_t tlv_index = 0;
    bool first_item = true;
    const auto open_entry = [&]() {
        if (!first_item) {
            out.push_back(',');
        }
        out.push_back('\n');
        first_item = false;
    };
    while (semantic_index < artifacts.semantic_events.size() || tlv_index < entries.size()) {
        const auto more_semantic = semantic_index < artifacts.semantic_events.size();
        const auto more_tlv = tlv_index < entries.size();
        const auto semantic_next =
            more_semantic && (!more_tlv || artifacts.semantic_events[semantic_index].wire_seq <=
                                               entries[tlv_index].preamble.seq);
        if (semantic_next) {
            open_entry();
            append_semantic_entry_json(out, artifacts.semantic_events[semantic_index],
                                       EventLevel::Full);
            ++semantic_index;
            continue;
        }
        const auto& entry = entries[tlv_index];
        ++tlv_index;
        if (semantic_ordinals.contains(entry.preamble.seq)) {
            continue; // the semantic tier already rendered this event
        }
        open_entry();
        append_tlv_entry_json(out, entry, artifacts.timeline_names);
    }
    return !first_item;
}

} // namespace

std::string render_events_section(const AnalysisArtifacts& artifacts, const EventLevel level)
{
    std::string out;
    // Counts: every type, id order, zero-count types omitted.
    out += "{\"counts\":{";
    bool first = true;
    for (std::size_t i = 0; i < artifacts.event_counts.size(); ++i) {
        const auto count = artifacts.event_counts[i];
        if (count == 0) {
            continue;
        }
        if (!first) {
            out.push_back(',');
        }
        first = false;
        out.push_back('"');
        out += sheller::kEventTypeNames[i]; // fixed lowercase names: no escaping needed
        out += "\":";
        out += std::to_string(count);
    }
    out.push_back('}');

    // Detail: counts level emits no entries (the counts header and the side
    // tables are the whole report); semantic level is the semantic tier
    // alone, one first-seq-ordered unified list (all types interleaved, names
    // resolved in-library, no type grouping, no cap, truncated payloads
    // carrying their flag on the entry; entries identical apart from seq are
    // one line with count and the first 16 seqs); full level merges that tier
    // with the ledger's
    // TLV window over the whole-run ordinal - see append_merged_detail_json.
    // Every entry occupies exactly one line; an empty list stays "[]", so a
    // counts-only or empty report remains one line.
    out += ",\"detail\":[";
    bool any_entries = false;
    if (level == EventLevel::Full) {
        any_entries = append_merged_detail_json(out, artifacts);
    } else if (level == EventLevel::Semantic) {
        any_entries = append_semantic_detail_json(out, artifacts);
    }
    if (any_entries) {
        out.push_back('\n');
    }
    out.push_back(']');

    // Stub-call side-table snapshot: key always present, {} when nothing
    // called.
    out += ",\"stub_calls\":{";
    first = true;
    for (const auto& stub : artifacts.stub_calls) {
        if (!first) {
            out.push_back(',');
        }
        first = false;
        append_json_string(out, stub.module_name.empty()
                                    ? std::to_string(stub.module) + "!" + stub.name
                                    : stub.module_name + "!" + stub.name);
        out.push_back(':');
        out += std::to_string(stub.count);
    }
    out.push_back('}');

    // Module source table (change real-dll-module-dir): key always present,
    // [] on routes that never build a loader world. One row per resident
    // system module - name plus the provenance class the loader marked.
    out += ",\"module_sources\":[";
    first = true;
    for (const auto& row : artifacts.module_sources) {
        if (!first) {
            out.push_back(',');
        }
        first = false;
        out += "{\"module\":";
        append_json_string(out, row.module);
        out += ",\"source\":";
        append_json_string(out, row.source);
        out.push_back('}');
    }
    out.push_back(']');

    // Loss: key always present. No ledger (default level) means the window
    // was never built - null says "not observable", which 0 cannot. A built
    // ledger spells its counters, zero included.
    if (level == EventLevel::Full) {
        out += ",\"loss\":{\"dropped\":";
        out += std::to_string(artifacts.timeline_dropped);
        out += ",\"truncated\":";
        out += std::to_string(artifacts.timeline_truncated);
        out.push_back('}');
    } else {
        out += ",\"loss\":{\"dropped\":null,\"truncated\":null}";
    }

    out.push_back('}');
    return out;
}

// Whether the TLV walk stops before the end of the window: a malformed tail
// means the full-level render carried fewer entries than the bytes on hand
// could hold. One walk implementation - the same break conditions the merge
// uses - so the console warning cannot disagree with the rendered file.
bool tlv_window_has_malformed_tail(std::span<const std::uint8_t> tlv)
{
    const auto stop =
        for_each_tlv_event(tlv, [](sheller::EventTypeId, const sheller::EventPreamble&,
                                   std::span<const std::uint8_t>) {});
    return stop != tlv.size();
}

} // namespace sheller::cli
