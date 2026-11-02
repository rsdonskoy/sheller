#include "boundary_derive.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <map>
#include <utility>

namespace sheller::loader {
namespace {

// Source-side layout facts. Offsets mirror winnt.h (same minimum as
// loader.cpp); the export-directory field positions are shared by both
// optional-header magics.
constexpr std::uint32_t kELfanewOffset = 0x3C;
constexpr std::uint32_t kOptionalHeaderOffset = 24;
constexpr std::uint32_t kDataDirectoryOffset64 = 112; // PE32+ optional+0x70
constexpr std::uint32_t kDataDirectoryOffset32 = 96;  // PE32  optional+0x60
constexpr std::uint16_t kMachineAmd64 = 0x8664;

// Derived-image layout: one code section carrying the body slots, the
// rebuilt export directory and the data slots (the engine maps resident
// modules RWX anyway; a second section would only duplicate that decision).
// ntdll keeps the engine's weld-slot parity with the synthetic generator:
// .text padded to 0x40000, .data at 0x41000.
constexpr std::uint32_t kDeriveSectionRva = 0x1000;
constexpr std::uint32_t kDeriveHeadersBytes = 0x1000;
constexpr std::uint32_t kDeriveStubStride = 16;
constexpr std::uint32_t kNtdllWeldDataSize = 0x200;
constexpr std::uint32_t kNtdllSizeOfImage =
    kBoundaryNtdllWeldDataRva + 0x1000; // 0x42000, matching the generator

// Bounded walks over untrusted directory files (same discipline as
// imports.cpp's caps).
constexpr std::uint32_t kMaxFunctions = 16384;
constexpr std::uint32_t kMaxNames = 8192;
constexpr std::uint32_t kMaxNameBytes = 255;
constexpr std::uint32_t kMaxDataSlotBytes = 0x10000;

std::uint16_t read16(std::span<const std::uint8_t> bytes, const std::size_t offset)
{
    if (offset + 2 > bytes.size()) {
        return 0;
    }
    return static_cast<std::uint16_t>(bytes[offset] |
                                      (static_cast<std::uint16_t>(bytes[offset + 1]) << 8));
}

std::uint32_t read32(std::span<const std::uint8_t> bytes, const std::size_t offset)
{
    if (offset + 4 > bytes.size()) {
        return 0;
    }
    std::uint32_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof value);
    return value;
}

// NUL-terminated ASCII string at a file offset, bounded (export names and
// forwarder strings are short). Empty when unterminated within the bound.
std::string read_c_string(std::span<const std::uint8_t> bytes, const std::size_t offset)
{
    if (offset >= bytes.size()) {
        return {};
    }
    const auto end = std::min(bytes.size(), offset + static_cast<std::size_t>(kMaxNameBytes) + 1);
    std::string out;
    for (auto i = offset; i < end; ++i) {
        if (bytes[i] == 0) {
            return out;
        }
        out.push_back(static_cast<char>(bytes[i]));
    }
    return {};
}

// RVA -> file offset over the parsed source section table (span = the
// larger of virtual and raw size, the PE convention for BSS-tailed
// sections). Header-resident RVAs map 1:1 at the file start. nullopt when
// the RVA does not name file-backed bytes.
std::optional<std::size_t> rva_to_file_offset(const ImageInfo& info,
                                              std::span<const std::uint8_t> file,
                                              const std::uint32_t rva)
{
    if (info.sections.empty() || rva < info.sections.front().virtual_address) {
        if (rva < kDeriveHeadersBytes && rva < file.size()) {
            return static_cast<std::size_t>(rva);
        }
        return std::nullopt;
    }
    for (const auto& section : info.sections) {
        const auto span = std::max(section.virtual_size, section.raw_size);
        if (rva >= section.virtual_address && rva < section.virtual_address + span) {
            const auto offset =
                static_cast<std::size_t>(rva - section.virtual_address) + section.raw_pointer;
            if (offset < file.size()) {
                return offset;
            }
            return std::nullopt;
        }
    }
    return std::nullopt;
}

// The u32 at an RVA, when the four bytes are file-backed.
std::optional<std::uint32_t> read_rva32(const ImageInfo& info, std::span<const std::uint8_t> file,
                                        const std::uint32_t rva)
{
    const auto offset = rva_to_file_offset(info, file, rva);
    if (!offset.has_value() || *offset + 4 > file.size()) {
        return std::nullopt;
    }
    return read32(file, *offset);
}

BoundaryDeriveFailure fail(const BoundaryDeriveError code, std::string detail)
{
    return BoundaryDeriveFailure{code, std::move(detail)};
}

// One source EAT slot: the function RVA plus every name that resolves to it
// (in source name-array order - the alias spelling the derived image keeps).
struct SourceExport {
    std::uint32_t function_rva{};
    std::vector<std::string> names;
};

struct SourceExports {
    std::uint32_t export_base{};
    std::uint32_t directory_rva{};
    std::uint32_t directory_size{};
    std::vector<SourceExport> functions; // EAT index order
    // (EAT index, name position) in the source names-array walking order -
    // the derived names array preserves this exact order.
    std::vector<std::pair<std::uint32_t, std::size_t>> name_order;
};

std::expected<SourceExports, BoundaryDeriveFailure>
walk_source_exports(std::span<const std::uint8_t> file, const ImageInfo& info)
{
    const auto pe = read32(file, kELfanewOffset);
    if (pe == 0 || pe + 4 + 20 + 128 > file.size() || read32(file, pe) != 0x00004550) {
        return std::unexpected(fail(BoundaryDeriveError::kBadSource, "broken PE headers"));
    }
    const auto optional = pe + kOptionalHeaderOffset;
    const auto dirs =
        read16(file, optional) == 0x010B ? kDataDirectoryOffset32 : kDataDirectoryOffset64;
    SourceExports out;
    out.directory_rva = read32(file, optional + dirs);
    out.directory_size = read32(file, optional + dirs + 4);
    if (out.directory_rva == 0 || out.directory_size == 0) {
        return std::unexpected(
            fail(BoundaryDeriveError::kNoExportDirectory, "boundary module exports nothing"));
    }
    const auto dir_offset = rva_to_file_offset(info, file, out.directory_rva);
    if (!dir_offset.has_value() || *dir_offset + 40 > file.size()) {
        return std::unexpected(
            fail(BoundaryDeriveError::kBadSource,
                 std::format("export directory RVA 0x{:x} not file-backed", out.directory_rva)));
    }
    out.export_base = read32(file, *dir_offset + 0x10);
    const auto number_of_functions = read32(file, *dir_offset + 0x14);
    const auto number_of_names = read32(file, *dir_offset + 0x18);
    const auto functions_rva = read32(file, *dir_offset + 0x1C);
    const auto names_rva = read32(file, *dir_offset + 0x20);
    const auto ordinals_rva = read32(file, *dir_offset + 0x24);
    if (number_of_functions == 0 || number_of_functions > kMaxFunctions ||
        number_of_names > kMaxNames) {
        return std::unexpected(
            fail(BoundaryDeriveError::kBadSource,
                 std::format("export table span {} functions / {} names exceeds the bounded walk",
                             number_of_functions, number_of_names)));
    }
    out.functions.assign(number_of_functions, {});
    for (std::uint32_t i = 0; i < number_of_functions; ++i) {
        const auto entry_rva = functions_rva + 4 * i;
        auto function_rva = read_rva32(info, file, entry_rva);
        if (!function_rva.has_value()) {
            return std::unexpected(
                fail(BoundaryDeriveError::kBadSource,
                     std::format("EAT entry {} at RVA 0x{:x} not file-backed", i, entry_rva)));
        }
        out.functions[i].function_rva = *function_rva;
    }
    for (std::uint32_t i = 0; i < number_of_names; ++i) {
        const auto name_rva_slot = names_rva + 4 * i;
        auto name_rva = read_rva32(info, file, name_rva_slot);
        if (!name_rva.has_value()) {
            return std::unexpected(
                fail(BoundaryDeriveError::kBadSource,
                     std::format("names array entry {} at RVA 0x{:x} not file-backed", i,
                                 name_rva_slot)));
        }
        const auto ordinal_slot = ordinals_rva + 2 * i;
        auto ordinal_offset = rva_to_file_offset(info, file, ordinal_slot);
        if (!ordinal_offset.has_value() || *ordinal_offset + 2 > file.size()) {
            return std::unexpected(
                fail(BoundaryDeriveError::kBadSource,
                     std::format("ordinals array entry {} at RVA 0x{:x} not file-backed", i,
                                 ordinal_slot)));
        }
        const auto ordinal_index = read16(file, *ordinal_offset);
        if (ordinal_index >= number_of_functions) {
            return std::unexpected(
                fail(BoundaryDeriveError::kBadSource,
                     std::format("name ordinal {} out of the EAT range", ordinal_index)));
        }
        auto name_offset = rva_to_file_offset(info, file, *name_rva);
        if (!name_offset.has_value()) {
            return std::unexpected(
                fail(BoundaryDeriveError::kBadSource,
                     std::format("export name RVA 0x{:x} not file-backed", *name_rva)));
        }
        auto name = read_c_string(file, *name_offset);
        if (name.empty()) {
            return std::unexpected(
                fail(BoundaryDeriveError::kBadSource,
                     std::format("export name at RVA 0x{:x} is empty or unterminated", *name_rva)));
        }
        out.functions[ordinal_index].names.push_back(std::move(name));
        out.name_order.emplace_back(ordinal_index, out.functions[ordinal_index].names.size() - 1);
    }
    return out;
}

bool is_forwarder_rva(const SourceExports& source, const std::uint32_t function_rva)
{
    return function_rva >= source.directory_rva &&
           function_rva < source.directory_rva + source.directory_size;
}

// The body recipe each derived kind emits (all fit the 16-byte stride;
// bytes only - the engine's intercept/registration layers key on the VA).
std::vector<std::uint8_t> stub_body(const BoundaryKind kind, const std::uint32_t syscall_number,
                                    const std::uint64_t compat_return)
{
    switch (kind) {
    case BoundaryKind::kSyscallStub: {
        // canonical Win10+ x64 shape: mov r10, rcx; mov eax, imm32; syscall; ret
        std::vector<std::uint8_t> body{0x4C, 0x8B, 0xD1, 0xB8};
        for (unsigned i = 0; i < 4; ++i) {
            body.push_back(static_cast<std::uint8_t>(syscall_number >> (8 * i)));
        }
        body.push_back(0x0F);
        body.push_back(0x05);
        body.push_back(0xC3);
        return body;
    }
    case BoundaryKind::kTrap:
        // ud2: the registered terminator owns the stop; the bytes are the
        // catch-all that never answers a caller
        return {0x0F, 0x0B};
    case BoundaryKind::kCompat: {
        // mov eax/rax, imm; ret - the manifest's per-function answer, with
        // no family-wide default anywhere near it.
        std::vector<std::uint8_t> body;
        if (compat_return <= 0xFFFFFFFFULL) {
            body.push_back(0xB8);
            for (unsigned i = 0; i < 4; ++i) {
                body.push_back(static_cast<std::uint8_t>(compat_return >> (8 * i)));
            }
        } else {
            body.push_back(0x48);
            body.push_back(0xB8);
            for (unsigned i = 0; i < 8; ++i) {
                body.push_back(static_cast<std::uint8_t>(compat_return >> (8 * i)));
            }
        }
        body.push_back(0xC3);
        return body;
    }
    case BoundaryKind::kIntercept:
    default:
        // the entry is replaced wholesale by the engine implementation; the
        // body only has to be a deterministic, self-contained return
        return {0x31, 0xC0, 0xC3}; // xor eax, eax; ret
    }
}

constexpr std::uint32_t align_up(const std::uint32_t value, const std::uint32_t alignment)
{
    return (value + alignment - 1) / alignment * alignment;
}

} // namespace

std::string_view boundary_derive_error_message(const BoundaryDeriveError error)
{
    switch (error) {
    case BoundaryDeriveError::kNone:
        return "ok";
    case BoundaryDeriveError::kBadSource:
        return "boundary source file is not a walkable PE";
    case BoundaryDeriveError::kUnsupportedMachine:
        return "boundary derivation accepts AMD64 images only";
    case BoundaryDeriveError::kNoExportDirectory:
        return "boundary module has no export directory";
    case BoundaryDeriveError::kUnknownExport:
        return "export outside the boundary manifest rule set";
    case BoundaryDeriveError::kManifestMismatch:
        return "boundary manifest rule disagrees with the source image";
    case BoundaryDeriveError::kBadRule:
        return "boundary manifest rule payload invalid for its kind";
    }
    return "unknown boundary derivation error";
}

std::optional<std::uint32_t> syscall_stub_number_from_bytes(std::span<const std::uint8_t> body)
{
    // Canonical Win10+ x64 ntdll stub: mov r10, rcx; mov eax, imm32. The
    // prefix is the whole verdict - the engine's syscall_number_map reads
    // the same eight bytes, and no `Nt`/`Zw` spelling takes part.
    static constexpr std::array<std::uint8_t, 4> kStubPrefix{0x4C, 0x8B, 0xD1, 0xB8};
    if (body.size() < 8) {
        return std::nullopt;
    }
    if (body[0] == kStubPrefix[0] && body[1] == kStubPrefix[1] && body[2] == kStubPrefix[2] &&
        body[3] == kStubPrefix[3]) {
        return static_cast<std::uint32_t>(body[4]) | (static_cast<std::uint32_t>(body[5]) << 8) |
               (static_cast<std::uint32_t>(body[6]) << 16) |
               (static_cast<std::uint32_t>(body[7]) << 24);
    }
    return std::nullopt;
}

std::expected<DerivedBoundary, BoundaryDeriveFailure>
derive_boundary_image(std::span<const std::uint8_t> file, const std::string_view module_name,
                      const std::vector<BoundaryRule>& rules)
{
    const auto info = parse_pe(file);
    if (!info.has_value()) {
        return std::unexpected(fail(
            BoundaryDeriveError::kBadSource,
            std::format("{}: source rejected: {}", module_name, load_error_message(info.error()))));
    }
    // Phase 1 derives the x64 boundary pair only (design Non-Goals: no x86
    // directory mode; the manifest schema reserves the x86 ABI field).
    if (info->bitness != kBitness64) {
        return std::unexpected(
            fail(BoundaryDeriveError::kUnsupportedMachine,
                 std::format("{}: i386 boundary images are not derived", module_name)));
    }
    const auto source = walk_source_exports(file, *info);
    if (!source.has_value()) {
        return std::unexpected(source.error());
    }

    // Rule lookup: exact name spelling first, true-ordinal fallback for
    // unnamed exports. Duplicate rules are a manifest defect, not a tie.
    std::map<std::string, std::size_t> rules_by_name;
    std::map<std::uint32_t, std::size_t> rules_by_ordinal;
    for (std::size_t i = 0; i < rules.size(); ++i) {
        const auto& rule = rules[i];
        const bool inserted = rule.name.empty() ? rules_by_ordinal.emplace(rule.ordinal, i).second
                                                : rules_by_name.emplace(rule.name, i).second;
        if (!inserted) {
            return std::unexpected(
                fail(BoundaryDeriveError::kBadRule,
                     std::format("{}: duplicate rule for '{}'", module_name, rule.name)));
        }
    }

    // Classification pass over the source exports, EAT order. Aliases
    // produce one disposition per name, all sharing the ordinal's body.
    struct Classified {
        DerivedBoundaryExport record;
        std::uint32_t source_index{}; // EAT index the disposition belongs to
        const BoundaryRule* rule{};
        bool has_body{};
        std::vector<std::uint8_t> data_bytes;
        std::uint32_t data_align{};
    };
    std::vector<Classified> classified;
    const auto classify =
        [&](const std::string& name, const std::uint32_t source_index,
            const SourceExport& slot) -> std::expected<void, BoundaryDeriveFailure> {
        const auto true_ordinal = source->export_base + source_index;
        const BoundaryRule* rule = nullptr;
        if (name.empty()) {
            if (const auto it = rules_by_ordinal.find(true_ordinal); it != rules_by_ordinal.end()) {
                rule = &rules[it->second];
            }
        } else {
            if (const auto it = rules_by_name.find(name); it != rules_by_name.end()) {
                rule = &rules[it->second];
            }
        }
        Classified item;
        item.record.name = name;
        item.record.ordinal = true_ordinal;
        item.source_index = source_index;
        if (slot.function_rva == 0) {
            // EAT hole: preserved as an empty entry; no rule can give it a
            // body.
            if (rule != nullptr) {
                return std::unexpected(
                    fail(BoundaryDeriveError::kManifestMismatch,
                         std::format("{}!{}: rule targets an empty EAT entry", module_name, name)));
            }
            item.record.kind = BoundaryKind::kEmpty;
            classified.push_back(std::move(item));
            return {};
        }
        if (is_forwarder_rva(*source, slot.function_rva)) {
            // Forwarder relation: preserved verbatim, classified along the
            // chain at bind time. A rule here means the manifest and the
            // source disagree about what this name is.
            auto target_offset = rva_to_file_offset(*info, file, slot.function_rva);
            if (!target_offset.has_value()) {
                return std::unexpected(
                    fail(BoundaryDeriveError::kBadSource,
                         std::format("{}!{}: forwarder string at RVA 0x{:x} not file-backed",
                                     module_name, name, slot.function_rva)));
            }
            auto target = read_c_string(file, *target_offset);
            if (target.empty()) {
                return std::unexpected(fail(BoundaryDeriveError::kBadSource,
                                            std::format("{}!{}: forwarder string is empty or "
                                                        "unterminated",
                                                        module_name, name)));
            }
            if (rule != nullptr) {
                return std::unexpected(fail(BoundaryDeriveError::kManifestMismatch,
                                            std::format("{}!{}: rule targets a forwarder to '{}'",
                                                        module_name, name, target)));
            }
            item.record.kind = BoundaryKind::kForwarder;
            item.record.forwarded = true;
            item.record.forwarder_target = std::move(target);
            classified.push_back(std::move(item));
            return {};
        }
        if (rule == nullptr) {
            return std::unexpected(
                fail(BoundaryDeriveError::kUnknownExport,
                     std::format("{}!{}: no boundary manifest rule covers this export", module_name,
                                 name.empty() ? std::format("<ordinal {}>", true_ordinal) : name)));
        }
        item.rule = rule;
        item.record.kind = rule->kind;
        switch (rule->kind) {
        case BoundaryKind::kSyscallStub: {
            const auto body_offset = rva_to_file_offset(*info, file, slot.function_rva);
            const auto body =
                body_offset.has_value()
                    ? file.subspan(*body_offset,
                                   std::min<std::size_t>(16, file.size() - *body_offset))
                    : std::span<const std::uint8_t>{};
            const auto number = syscall_stub_number_from_bytes(body);
            if (!number.has_value()) {
                // Shape validation is the whole syscall verdict: a rule
                // cannot promote a non-stub body, and an `Nt` prefix never
                // substitutes for the bytes.
                return std::unexpected(fail(BoundaryDeriveError::kManifestMismatch,
                                            std::format("{}!{}: syscallstub rule but the body "
                                                        "fails stub-shape validation",
                                                        module_name, name)));
            }
            item.record.syscall_number = *number;
            item.has_body = true;
            break;
        }
        case BoundaryKind::kIntercept:
        case BoundaryKind::kTrap:
        case BoundaryKind::kCompat:
            item.has_body = true;
            break;
        case BoundaryKind::kData: {
            if (rule->data_size == 0 || rule->data_size > kMaxDataSlotBytes ||
                rule->data_bytes.size() != rule->data_size || rule->data_align == 0 ||
                (rule->data_align & (rule->data_align - 1)) != 0) {
                return std::unexpected(
                    fail(BoundaryDeriveError::kBadRule,
                         std::format("{}!{}: data rule layout invalid (size {}, {} bytes, "
                                     "align {})",
                                     module_name, name, rule->data_size, rule->data_bytes.size(),
                                     rule->data_align)));
            }
            item.data_bytes = rule->data_bytes;
            item.data_align = std::max(rule->data_align, 8u);
            break;
        }
        case BoundaryKind::kForwarder:
        case BoundaryKind::kEmpty:
            return std::unexpected(fail(BoundaryDeriveError::kBadRule,
                                        std::format("{}!{}: the kind is disposition-only and "
                                                    "cannot be a manifest rule",
                                                    module_name, name)));
        }
        classified.push_back(std::move(item));
        return {};
    };
    for (std::uint32_t index = 0; index < source->functions.size(); ++index) {
        const auto& slot = source->functions[index];
        if (slot.names.empty()) {
            if (const auto ok = classify({}, index, slot); !ok) {
                return std::unexpected(ok.error());
            }
            continue;
        }
        for (const auto& name : slot.names) {
            if (const auto ok = classify(name, index, slot); !ok) {
                return std::unexpected(ok.error());
            }
        }
    }

    // Alias integrity: names sharing one EAT index share the target's body
    // and therefore its disposition - a manifest that assigns them different
    // kinds (or different compat answers) disagrees with its own aliases.
    for (std::size_t i = 1; i < classified.size(); ++i) {
        const auto& item = classified[i];
        if (item.record.kind == BoundaryKind::kForwarder ||
            item.record.kind == BoundaryKind::kEmpty) {
            continue;
        }
        for (std::size_t j = 0; j < i; ++j) {
            const auto& other = classified[j];
            if (other.source_index != item.source_index ||
                other.record.kind == BoundaryKind::kForwarder ||
                other.record.kind == BoundaryKind::kEmpty) {
                continue;
            }
            const bool same = other.record.kind == item.record.kind &&
                              (item.record.kind != BoundaryKind::kCompat ||
                               other.rule->compat_return == item.rule->compat_return);
            if (!same) {
                return std::unexpected(
                    fail(BoundaryDeriveError::kManifestMismatch,
                         std::format("{}!{}: alias of {} but carries a different disposition",
                                     module_name, item.record.name, other.record.name)));
            }
        }
    }

    // Layout pass. Code slots first (source ordinal order; aliases share the
    // ordinal's one slot), then the rebuilt export directory, then the
    // preserved forwarder strings, then the data slots at their per-rule
    // alignments. Per-ordinal RVAs live in one map so the EAT emission and
    // the dispositions read the same addresses.
    const bool is_ntdll = module_name == "ntdll.dll";
    std::map<std::uint32_t, std::uint32_t> rva_by_ordinal;
    std::uint32_t cursor = kDeriveSectionRva;
    for (const auto& item : classified) {
        if (!item.has_body) {
            continue;
        }
        if (rva_by_ordinal.emplace(item.source_index, cursor).second) {
            cursor += kDeriveStubStride;
        }
    }
    const auto export_dir_rva = align_up(cursor, 16);
    cursor = export_dir_rva + 40; // IMAGE_EXPORT_DIRECTORY
    const auto eat_rva = cursor;
    cursor += 4 * static_cast<std::uint32_t>(source->functions.size());
    const auto names_array_rva = cursor;
    const auto named_count = source->name_order.size();
    cursor += 4 * static_cast<std::uint32_t>(named_count);
    const auto ordinals_array_rva = cursor;
    cursor += 2 * static_cast<std::uint32_t>(named_count);
    const auto module_name_rva = cursor;
    cursor += static_cast<std::uint32_t>(module_name.size()) + 1;
    // name strings in source name-array order
    std::vector<std::uint32_t> name_string_rvas(named_count, 0);
    for (std::size_t i = 0; i < named_count; ++i) {
        const auto& name =
            source->functions[source->name_order[i].first].names[source->name_order[i].second];
        name_string_rvas[i] = cursor;
        cursor += static_cast<std::uint32_t>(name.size()) + 1;
    }
    // forwarder strings, one per forwarded ordinal (aliases share the slot)
    for (const auto& item : classified) {
        if (!item.record.forwarded) {
            continue;
        }
        if (rva_by_ordinal.emplace(item.source_index, cursor).second) {
            cursor += static_cast<std::uint32_t>(item.record.forwarder_target.size()) + 1;
        }
    }
    // data slots: per-rule alignment, disposition order
    for (const auto& item : classified) {
        if (item.record.kind != BoundaryKind::kData) {
            continue;
        }
        if (rva_by_ordinal.emplace(item.source_index, align_up(cursor, item.data_align)).second) {
            cursor = align_up(cursor, item.data_align) +
                     static_cast<std::uint32_t>(item.data_bytes.size());
        }
    }
    auto content_end = cursor;
    std::uint32_t size_of_image = align_up(content_end, kDeriveSectionRva);
    if (is_ntdll) {
        // weld-slot parity: .text spans the fixed 0x40000, .data follows
        if (content_end > kBoundaryNtdllTextSpan) {
            return std::unexpected(
                fail(BoundaryDeriveError::kBadSource,
                     std::format("{}: derived content 0x{:x} overflows the "
                                 "weld-slot .text span 0x{:x}",
                                 module_name, content_end, kBoundaryNtdllTextSpan)));
        }
        content_end = kBoundaryNtdllTextSpan;
        size_of_image = kNtdllSizeOfImage;
    }
    // every disposition now carries its final RVA
    for (auto& item : classified) {
        const auto rva = rva_by_ordinal.find(item.source_index);
        item.record.body_rva =
            rva != rva_by_ordinal.end() ? static_cast<std::uint64_t>(rva->second) : 0;
    }

    // Emission.
    std::vector<std::uint8_t> image(kDeriveHeadersBytes, 0);
    // DOS header: MZ and e_lfanew only - every other field, including the
    // reserved e_res2 marker slot at 0x28..0x3B, stays zero.
    image[0] = 'M';
    image[1] = 'Z';
    constexpr std::size_t kPeOffset = 0x7C;
    image[kELfanewOffset] = static_cast<std::uint8_t>(kPeOffset);
    // PE signature + COFF: AMD64, PE32+ optional header
    image.resize(kPeOffset + 4, 0);
    std::memcpy(image.data() + kPeOffset, "PE\0\0", 4);
    const std::size_t section_count = is_ntdll ? 2 : 1;
    {
        std::vector<std::uint8_t> file_header;
        const auto put16 = [&file_header](const std::uint16_t v) {
            file_header.push_back(static_cast<std::uint8_t>(v));
            file_header.push_back(static_cast<std::uint8_t>(v >> 8));
        };
        const auto put32 = [&file_header](const std::uint32_t v) {
            for (unsigned i = 0; i < 4; ++i) {
                file_header.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
            }
        };
        put16(kMachineAmd64);
        put16(static_cast<std::uint16_t>(section_count));
        put32(0);    // time date stamp
        put32(0);    // symbol table RVA
        put32(0);    // symbol count
        put16(0xF0); // size of optional header (PE32+)
        put16(0x2022);
        image.insert(image.end(), file_header.begin(), file_header.end());
    }
    {
        std::vector<std::uint8_t> opt(0xF0, 0);
        const auto put = [&opt](const std::size_t at, const std::uint32_t v) {
            for (unsigned i = 0; i < 4; ++i) {
                opt[at + i] = static_cast<std::uint8_t>(v >> (8 * i));
            }
        };
        opt[0] = 0x0B;
        opt[1] = 0x02; // PE32+ magic
        std::size_t code_bytes = 0;
        for (const auto& item : classified) {
            if (item.has_body) {
                code_bytes += kDeriveStubStride;
            }
        }
        put(4, static_cast<std::uint32_t>(code_bytes));
        // AddressOfEntryPoint: the first code slot (derived modules never
        // run an entry; the field keeps the image shape conventional)
        const auto entry = std::find_if(classified.begin(), classified.end(),
                                        [](const Classified& c) { return c.has_body; });
        put(16, entry == classified.end() ? 0 : static_cast<std::uint32_t>(entry->record.body_rva));
        put(20, kDeriveSectionRva); // BaseOfCode
        put(24, 0x400000);          // ImageBase (PE32+; high dword stays zero)
        put(32, kDeriveSectionRva); // SectionAlignment
        put(36, kDeriveSectionRva); // FileAlignment
        put(56, size_of_image);
        put(60, kDeriveHeadersBytes); // SizeOfHeaders
        opt[68] = 3;                  // SubSystem console
        put(108, 16);                 // NumberOfRvaAndSizes
        // DataDirectory[0]: the rebuilt export directory
        put(112, export_dir_rva);
        std::uint32_t directory_size = 40;
        directory_size += 4 * static_cast<std::uint32_t>(source->functions.size());
        directory_size += 4 * static_cast<std::uint32_t>(named_count);
        directory_size += 2 * static_cast<std::uint32_t>(named_count);
        directory_size += static_cast<std::uint32_t>(module_name.size()) + 1;
        for (std::size_t i = 0; i < named_count; ++i) {
            const auto& name =
                source->functions[source->name_order[i].first].names[source->name_order[i].second];
            directory_size += static_cast<std::uint32_t>(name.size()) + 1;
        }
        for (const auto& item : classified) {
            if (item.record.forwarded) {
                directory_size +=
                    static_cast<std::uint32_t>(item.record.forwarder_target.size()) + 1;
            }
        }
        put(116, directory_size);
        image.insert(image.end(), opt.begin(), opt.end());
    }
    // Section table: .text (bodies + directory + data) plus the ntdll weld
    // .data. Raw pointers keep RVA == file offset inside the section.
    std::vector<std::uint8_t> sections(section_count * 40, 0);
    const auto fill_section = [&](const std::size_t index, const char* name,
                                  const std::uint32_t virtual_size, const std::uint32_t rva,
                                  const std::uint32_t raw_size, const std::uint32_t raw_pointer,
                                  const std::uint32_t characteristics) {
        auto* at = sections.data() + index * 40;
        std::memcpy(at, name, std::min<std::size_t>(std::strlen(name), 8));
        const auto put = [at](const std::size_t field, const std::uint32_t v) {
            for (unsigned i = 0; i < 4; ++i) {
                at[field + i] = static_cast<std::uint8_t>(v >> (8 * i));
            }
        };
        put(8, virtual_size);
        put(12, rva);
        put(16, raw_size);
        put(20, raw_pointer);
        put(36, characteristics);
    };
    const auto text_raw = is_ntdll ? kBoundaryNtdllTextSpan : content_end - kDeriveSectionRva;
    fill_section(0, ".text", content_end - kDeriveSectionRva, kDeriveSectionRva, text_raw,
                 kDeriveHeadersBytes, 0x60000020);
    if (is_ntdll) {
        fill_section(1, ".data", kNtdllWeldDataSize, kBoundaryNtdllWeldDataRva, kNtdllWeldDataSize,
                     kDeriveHeadersBytes + text_raw, 0xC0000040);
    }
    image.insert(image.end(), sections.begin(), sections.end());
    image.resize(static_cast<std::size_t>(kDeriveHeadersBytes) + text_raw, 0);

    // .text payload
    const auto put_at = [&image](const std::uint32_t rva, const std::uint32_t value) {
        const auto at = static_cast<std::size_t>(rva);
        for (unsigned i = 0; i < 4; ++i) {
            image[at + i] = static_cast<std::uint8_t>(value >> (8 * i));
        }
    };
    const auto put_string = [&image](const std::uint32_t rva, const std::string_view text) {
        const auto at = static_cast<std::size_t>(rva);
        std::memcpy(image.data() + at, text.data(), text.size());
        image[at + text.size()] = 0;
    };
    for (const auto& item : classified) {
        if (!item.has_body) {
            continue;
        }
        const auto body = stub_body(item.record.kind, item.record.syscall_number,
                                    item.rule != nullptr ? item.rule->compat_return : 0);
        std::memcpy(image.data() + item.record.body_rva, body.data(), body.size());
    }
    // export directory struct
    put_at(export_dir_rva + 0x0C, module_name_rva);
    put_at(export_dir_rva + 0x10, source->export_base); // Base
    put_at(export_dir_rva + 0x14, static_cast<std::uint32_t>(source->functions.size()));
    put_at(export_dir_rva + 0x18, static_cast<std::uint32_t>(named_count));
    put_at(export_dir_rva + 0x1C, eat_rva);
    put_at(export_dir_rva + 0x20, names_array_rva);
    put_at(export_dir_rva + 0x24, ordinals_array_rva);
    put_string(module_name_rva, module_name);
    // EAT: rebuilt addresses only - forwarders point at the preserved
    // strings inside this image, holes stay empty, and no entry ever keeps a
    // source RVA.
    for (std::size_t index = 0; index < source->functions.size(); ++index) {
        const auto rva = rva_by_ordinal.find(static_cast<std::uint32_t>(index));
        if (rva != rva_by_ordinal.end()) {
            put_at(eat_rva + 4 * static_cast<std::uint32_t>(index), rva->second);
        }
    }
    for (std::size_t i = 0; i < named_count; ++i) {
        const auto [index, name_index] = source->name_order[i];
        put_at(names_array_rva + 4 * static_cast<std::uint32_t>(i), name_string_rvas[i]);
        put_string(name_string_rvas[i], source->functions[index].names[name_index]);
        const auto at = static_cast<std::size_t>(ordinals_array_rva) + 2 * i;
        image[at] = static_cast<std::uint8_t>(index);
        image[at + 1] = static_cast<std::uint8_t>(index >> 8);
    }
    for (const auto& item : classified) {
        if (item.record.forwarded) {
            put_string(static_cast<std::uint32_t>(item.record.body_rva),
                       item.record.forwarder_target);
        }
    }
    for (const auto& item : classified) {
        if (item.record.kind == BoundaryKind::kData) {
            std::memcpy(image.data() + item.record.body_rva, item.data_bytes.data(),
                        item.data_bytes.size());
        }
    }
    if (is_ntdll) {
        // weld .data: zero-initialized engine slots at the fixed RVA
        image.resize(image.size() + kNtdllWeldDataSize, 0);
    }

    DerivedBoundary out;
    out.image = std::move(image);
    out.weld_data_rva = is_ntdll ? kBoundaryNtdllWeldDataRva : 0;
    out.exports.reserve(classified.size());
    for (auto& item : classified) {
        out.exports.push_back(std::move(item.record));
    }
    return out;
}

} // namespace sheller::loader
