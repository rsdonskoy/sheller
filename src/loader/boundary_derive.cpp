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
    constexpr std::uint32_t kHeadersBytes = 0x1000;
    if (info.sections.empty() || rva < info.sections.front().virtual_address) {
        if (rva < kHeadersBytes && rva < file.size()) {
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
// (in source name-array order - the disposition records keep the spelling).
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
    // the disposition records preserve this exact order.
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

// The image bytes over [rva, rva+bytes). The folded image maps RVA ==
// offset inside the header block and every section's virtual span, so the
// range check plus the section walk settles mapped-ness. A whitelist write
// or read lands only when the WHOLE span sits inside one mapped region - a
// span straddling a section end into an inter-section gap is not mapped.
bool rva_span_mapped(const ImageInfo& info, const std::uint64_t image_size, const std::uint32_t rva,
                     const std::uint64_t bytes)
{
    if (rva >= image_size || bytes > image_size - rva) {
        return false;
    }
    const auto header_end = std::min<std::uint64_t>(
        image_size,
        std::max<std::uint64_t>(0x400, std::max(info.size_of_headers, info.table_end_rva)));
    if (rva < header_end && bytes <= header_end - rva) {
        return true;
    }
    for (const auto& section : info.sections) {
        const auto span = std::max(section.virtual_size, section.raw_size);
        if (span == 0 || rva < section.virtual_address) {
            continue;
        }
        const auto offset_in_section = static_cast<std::uint64_t>(rva - section.virtual_address);
        if (offset_in_section >= span) {
            continue;
        }
        if (bytes <= span - offset_in_section) {
            return true; // the whole span sits inside this section
        }
    }
    return false;
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
                      const std::vector<BoundaryRule>& rules, const std::uint64_t base)
{
    const auto info = parse_pe(file);
    if (!info.has_value()) {
        return std::unexpected(fail(
            BoundaryDeriveError::kBadSource,
            std::format("{}: source rejected: {}", module_name, load_error_message(info.error()))));
    }
    // The derivation covers the x64 boundary pair only: no x86 directory mode,
    // though the manifest schema reserves the x86 ABI field.
    if (info->bitness != kBitness64) {
        return std::unexpected(
            fail(BoundaryDeriveError::kUnsupportedMachine,
                 std::format("{}: i386 boundary images are not derived", module_name)));
    }

    // The real file is the base: fold it, then take the same relocation
    // pipeline as every real-byte module (a base move without a usable
    // relocation table is the named rejection - no half-fixed image).
    auto image = build_image(file, *info);
    if (!image.has_value()) {
        return std::unexpected(fail(BoundaryDeriveError::kBadSource,
                                    std::format("{}: image build failed: {}", module_name,
                                                load_error_message(image.error()))));
    }
    const auto delta = base - info->image_base;
    if (delta != 0 && info->reloc_directory_rva != 0 && info->reloc_directory_size != 0) {
        if (const auto valid = validate_relocations(*image, *info); !valid.has_value()) {
            return std::unexpected(fail(BoundaryDeriveError::kBadSource,
                                        std::format("{}: relocation table names targets outside "
                                                    "the image",
                                                    module_name)));
        }
        if (const auto relocated = apply_relocations(*image, *info, delta);
            !relocated.has_value()) {
            return std::unexpected(fail(BoundaryDeriveError::kBadSource,
                                        std::format("{}: relocation failed: {}", module_name,
                                                    load_error_message(relocated.error()))));
        }
    } else if (delta != 0) {
        return std::unexpected(
            fail(BoundaryDeriveError::kBadSource,
                 std::format("{}: mapped at 0x{:x} but carries no relocation directory",
                             module_name, base)));
    }

    // The whitelist's marker slot precondition: the engine writes the
    // directory-mode marker into the reserved DOS e_res2 slot, so the
    // source must keep it zero (a dirty slot would make the marker write
    // overwrite real bytes - rejected here, before anything maps).
    bool marker_slot_zero = true;
    for (std::uint32_t i = 0; i < kBoundaryMarkerSize; ++i) {
        if ((*image)[kBoundaryMarkerOffset + i] != 0) {
            marker_slot_zero = false;
            break;
        }
    }
    if (!marker_slot_zero) {
        return std::unexpected(
            fail(BoundaryDeriveError::kBadSource,
                 std::format("{}: the reserved DOS e_res2 marker slot is not zero", module_name)));
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
    // produce one disposition per name, all sharing the ordinal's address.
    // No body is emitted: the dispositions ride the runtime table, and the
    // only image writes are the whitelist slots below.
    struct Classified {
        DerivedBoundaryExport record;
        std::uint32_t source_index{}; // EAT index the disposition belongs to
        const BoundaryRule* rule{};
        std::vector<std::uint8_t> data_bytes; // kData, when the slot writes
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
        item.record.body_rva = slot.function_rva;
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
            item.record.body_rva = 0;
            classified.push_back(std::move(item));
            return {};
        }
        if (is_forwarder_rva(*source, slot.function_rva)) {
            // Forwarder relation: preserved verbatim - the EAT keeps the
            // string's RVA inside the mapped export directory, classified
            // along the chain at bind time. A rule here means the manifest
            // and the source disagree about what this name is.
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
            // the number is validated against the source body bytes - the
            // stub keeps those bytes, no shape is synthesized
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
            break;
        }
        case BoundaryKind::kIntercept:
            // whitelist slot (c): the hook-miss guard body is written at the
            // export's own address below (the engine hook owns the answer)
            if (!rva_span_mapped(*info, image->size(), slot.function_rva, 3)) {
                return std::unexpected(fail(BoundaryDeriveError::kManifestMismatch,
                                            std::format("{}!{}: stub body RVA 0x{:x} is not mapped",
                                                        module_name, name, slot.function_rva)));
            }
            break;
        case BoundaryKind::kTrap:
            // the engine-side runtime table owns the disposition (the trap
            // stops the run at the block boundary) - the source bytes stay
            // untouched
            break;
        case BoundaryKind::kCompat:
            // whitelist slot (c): the manifest's per-function answer is
            // written at the export's own address below (6 bytes for a
            // 32-bit answer, 11 for a 64-bit one)
            {
                const auto body_bytes = rule->compat_return <= 0xFFFFFFFFULL ? 6ULL : 11ULL;
                if (!rva_span_mapped(*info, image->size(), slot.function_rva, body_bytes)) {
                    return std::unexpected(
                        fail(BoundaryDeriveError::kManifestMismatch,
                             std::format("{}!{}: stub body RVA 0x{:x} is not mapped", module_name,
                                         name, slot.function_rva)));
                }
            }
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
            // whitelist slot (b): the slot resolves to the real address; the
            // manifest's bytes only land when the mapped slot is free (all
            // zero - no real content to overwrite)
            if (!rva_span_mapped(*info, image->size(), slot.function_rva, rule->data_size)) {
                return std::unexpected(fail(BoundaryDeriveError::kManifestMismatch,
                                            std::format("{}!{}: data slot RVA 0x{:x} is not mapped",
                                                        module_name, name, slot.function_rva)));
            }
            const auto at = static_cast<std::size_t>(slot.function_rva);
            const bool slot_free =
                std::all_of(image->begin() + static_cast<std::ptrdiff_t>(at),
                            image->begin() + static_cast<std::ptrdiff_t>(at + rule->data_size),
                            [](const std::uint8_t b) { return b == 0; });
            if (slot_free) {
                item.data_bytes = rule->data_bytes;
            }
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

    // Alias integrity: names sharing one EAT index share the target's
    // address and therefore its disposition - a manifest that assigns them
    // different kinds (or different compat answers) disagrees with its own
    // aliases.
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

    // The whitelist writes, disposition order. Everything outside this loop
    // keeps the load-pipeline bytes (the pin test holds the image against
    // the plain loaded image except these slots).
    for (const auto& item : classified) {
        const auto at = static_cast<std::size_t>(item.record.body_rva);
        if (item.record.kind == BoundaryKind::kCompat) {
            // (c) the compat stub body: deterministic return at the export's
            // own address (aliases share the one address)
            const auto compat_return = item.rule->compat_return;
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
            std::memcpy(image->data() + at, body.data(), body.size());
        } else if (item.record.kind == BoundaryKind::kIntercept) {
            // (c) the intercepted entry: a deterministic, self-contained
            // return - the engine hook owns the answer, the body only
            // guards a hook miss
            constexpr std::array<std::uint8_t, 3> kInterceptBody{0x31, 0xC0, 0xC3};
            std::memcpy(image->data() + at, kInterceptBody.data(), kInterceptBody.size());
        } else if (!item.data_bytes.empty()) {
            // (b) the free data slot takes the manifest's known bytes
            std::memcpy(image->data() + at, item.data_bytes.data(), item.data_bytes.size());
        }
    }

    DerivedBoundary out;
    out.image = std::move(*image);
    out.exports.reserve(classified.size());
    for (auto& item : classified) {
        out.exports.push_back(std::move(item.record));
    }
    return out;
}

} // namespace sheller::loader
