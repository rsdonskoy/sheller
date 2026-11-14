#include "mem_region_map.h"

#include <unicorn/unicorn.h>

#include <sheller/log.h>

#include <algorithm>
#include <cstring>
#include <format>
#include <numeric>

namespace sheller::engine::mem_region {
namespace {

// Minimal in-image PE header access. The offsets mirror winnt.h field
// positions already pinned by the capture module's pe_headers.h mirrors;
// self-drawn here so the engine keeps its own portable minimum (constexpr offsets, no
// reinterpret_cast to struct pointers).
constexpr std::size_t kDosHeaderSize = 0x40;
constexpr std::size_t kELfanewOffset = 0x3C;
constexpr std::size_t kFileHeaderOffset = 4;
constexpr std::size_t kNumberOfSectionsOffset = 6;
constexpr std::size_t kSizeOfOptionalHeaderOffset = 20;
constexpr std::size_t kOptionalHeaderOffset = 24;
constexpr std::size_t kMagicOffset = 0;
constexpr std::size_t kSectionAlignmentOffset = 32;
constexpr std::size_t kSizeOfImageOffset = 56;
constexpr std::size_t kSizeOfHeadersOffset = 60;
constexpr std::uint16_t kDosMagic = 0x5A4D;
constexpr std::uint32_t kPeSignature = 0x00004550;
constexpr std::uint16_t kPe32PlusMagic = 0x20B;
constexpr std::size_t kFileHeaderSize = 20;

// Mirror of IMAGE_SECTION_HEADER (winnt.h); the stride of the section table
// is sizeof(SectionHeader) per entry.
struct SectionHeader {
    std::array<std::uint8_t, 8> name;
    std::uint32_t virtual_size;
    std::uint32_t virtual_address;
    std::uint32_t size_of_raw_data;
    std::uint32_t pointer_to_raw_data;
    std::uint32_t pointer_to_relocations;
    std::uint32_t pointer_to_line_numbers;
    std::uint16_t number_of_relocations;
    std::uint16_t number_of_line_numbers;
    std::uint32_t characteristics;
};
static_assert(sizeof(SectionHeader) == 40);
static_assert(offsetof(SectionHeader, virtual_size) == 8);
static_assert(offsetof(SectionHeader, virtual_address) == 12);
static_assert(offsetof(SectionHeader, characteristics) == 36);

std::uint16_t read_u16(const std::uint8_t* src)
{
    return static_cast<std::uint16_t>(src[0] | (src[1] << 8));
}

std::uint32_t read_u32(const std::uint8_t* src)
{
    return static_cast<std::uint32_t>(src[0]) | (static_cast<std::uint32_t>(src[1]) << 8) |
           (static_cast<std::uint32_t>(src[2]) << 16) | (static_cast<std::uint32_t>(src[3]) << 24);
}

std::uint64_t read_guest_u64(uc_engine* const uc, const std::uint64_t address)
{
    std::uint64_t value = 0;
    uc_mem_read(uc, address, &value, sizeof value);
    return value;
}

std::uint32_t read_guest_u32(uc_engine* const uc, const std::uint64_t address)
{
    std::uint32_t value = 0;
    uc_mem_read(uc, address, &value, sizeof value);
    return value;
}

std::uint16_t read_guest_u16(uc_engine* const uc, const std::uint64_t address)
{
    std::uint16_t value = 0;
    uc_mem_read(uc, address, &value, sizeof value);
    return value;
}

// Folds one Ldr BaseDllName into lowercase ASCII, replacing non-ASCII bytes
// with '?' and truncating at the record capacity. Current containers store
// the name as UTF-16 (Length = 2 * characters), matching the real loader and
// the runtime-inserted Ldr entries; containers built before the
// shared-convention change stored narrow ASCII bytes (Length = the byte
// count). The two encodings are told apart by content: UTF-16 ASCII text
// carries a zero high byte on every other byte, the narrow text never does.
// Detecting the encoding keeps the legacy containers' names readable.
//
// The narrow read is trusted only for a name the buffer holds in full: a
// UTF-16 BaseDllName always contains ASCII (at minimum the extension), and
// ASCII in UTF-16 puts a zero byte inside any complete window - so an
// all-printable byte string read in full is the legacy narrow shape, while a
// truncated all-printable prefix (a >64-byte UTF-16 name, never a legacy
// one - the longest generated name is 18 bytes) defers to the wide read.
// What remains undecidable by content: a name whose every byte is printable
// AND which would be valid non-ASCII UTF-16 - that requires not a single
// ASCII character anywhere in the name. Both readings lose such a name (the
// fold is ASCII), so the rule below only picks which flavor of noise.
void fold_module_name(std::array<char, kModuleNameBytes>& out, const std::uint64_t address,
                      const std::uint64_t length_bytes, uc_engine* const uc)
{
    std::array<std::uint8_t, kModuleNameBytes> raw{};
    const auto read_count = std::min<std::uint64_t>(length_bytes, raw.size());
    if (read_count > 0 && uc_mem_read(uc, address, raw.data(), read_count) != UC_ERR_OK) {
        out[0] = '\0';
        return;
    }
    const bool narrow =
        read_count > 0 && length_bytes <= raw.size() &&
        std::all_of(raw.begin(), raw.begin() + static_cast<std::ptrdiff_t>(read_count),
                    [](const std::uint8_t byte) { return byte >= 0x20 && byte <= 0x7E; });
    if (narrow) {
        const auto copy_count = std::min<std::uint64_t>(read_count, kModuleNameBytes - 1);
        for (std::uint64_t i = 0; i < copy_count; ++i) {
            const auto byte = raw[static_cast<std::size_t>(i)];
            out[static_cast<std::size_t>(i)] =
                static_cast<char>(byte >= 'A' && byte <= 'Z' ? byte + ('a' - 'A') : byte);
        }
        out[static_cast<std::size_t>(copy_count)] = '\0';
        return;
    }
    const auto wchar_count = std::min<std::uint64_t>(length_bytes / 2, kModuleNameBytes - 1);
    for (std::uint64_t i = 0; i < wchar_count; ++i) {
        const auto wide = read_guest_u16(uc, address + 2 * i);
        const auto folded =
            static_cast<std::uint16_t>(wide >= L'A' && wide <= L'Z' ? wide + (L'a' - L'A') : wide);
        out[static_cast<std::size_t>(i)] = folded <= 0x7F ? static_cast<char>(folded) : '?';
    }
    out[static_cast<std::size_t>(wchar_count)] = '\0';
}

} // namespace

std::vector<ModuleImage> enumerate_guest_images_x86(uc_engine* const uc, const std::uint64_t teb);

std::vector<ModuleImage> enumerate_guest_images(uc_engine* const uc, const bool wow64,
                                                const std::uint64_t wow64_teb)
{
    std::vector<ModuleImage> images;
    std::uint64_t teb = 0;
    if (wow64) {
        // FS_BASE register reads no-op under 32-bit: the caller passes the
        // TEB the engine planted (snapshot Metadata.teb_address).
        teb = wow64_teb;
    } else {
        uc_reg_read(uc, UC_X86_REG_GS_BASE, &teb);
    }
    if (teb == 0) {
        return images;
    }
    if (wow64) {
        return enumerate_guest_images_x86(uc, teb);
    }
    const auto peb = read_guest_u64(uc, teb + 0x60);
    const auto ldr = read_guest_u64(uc, peb + 0x18);
    const auto head = read_guest_u64(uc, ldr + 0x10); // InLoadOrderModuleList.Flink
    auto link = head;
    for (std::size_t guard = 0; guard < kMaxModuleImages && link != 0; ++guard) {
        const auto dll_base = read_guest_u64(uc, link + 0x30);
        const auto image_size = read_guest_u32(uc, link + 0x40);
        const auto name_bytes = read_guest_u16(uc, link + 0x58);
        const auto name_buffer = read_guest_u64(uc, link + 0x60);

        if (dll_base != 0 && image_size != 0) {
            ModuleImage image;
            image.module.base = dll_base;
            image.module.size = image_size;
            fold_module_name(image.module.name, name_buffer, name_bytes, uc);
            const auto header_bytes = std::min<std::uint64_t>(image_size, kImageHeaderBytes);
            image.header_bytes.resize(static_cast<std::size_t>(header_bytes));
            const auto read_err =
                uc_mem_read(uc, dll_base, image.header_bytes.data(), image.header_bytes.size());
            if (read_err != UC_ERR_OK) {
                image.header_bytes.clear(); // unreadable: parse will report it
            }
            images.push_back(std::move(image));
        }

        link = read_guest_u64(uc, link);
        if (link == 0 || link == head) {
            break;
        }
    }
    return images;
}

// 32-bit Ldr walk: PEB32@teb+0x30, Ldr@peb+0x0C, InLoadOrder head
// at ldr+0x0C; LDR_DATA_TABLE_ENTRY32 DllBase@0x18, SizeOfImage@0x20,
// BaseDllName UNICODE_STRING32@0x2C. Callers pass the TEB the engine
// planted (FS_BASE register reads are unreliable under wow64 hosts).
std::vector<ModuleImage> enumerate_guest_images_x86(uc_engine* const uc, const std::uint64_t teb)
{
    std::vector<ModuleImage> images;
    const auto peb = read_guest_u32(uc, teb + 0x30);
    const auto ldr = read_guest_u32(uc, peb + 0x0C);
    const auto head = read_guest_u32(uc, ldr + 0x0C);
    auto link = head;
    for (std::size_t guard = 0; guard < kMaxModuleImages && link != 0; ++guard) {
        const auto dll_base = read_guest_u32(uc, link + 0x18);
        const auto image_size = read_guest_u32(uc, link + 0x20);
        const auto name_bytes = read_guest_u16(uc, link + 0x2C);
        const auto name_buffer = read_guest_u32(uc, link + 0x30);

        if (dll_base != 0 && image_size != 0) {
            ModuleImage image;
            image.module.base = dll_base;
            image.module.size = image_size;
            fold_module_name(image.module.name, name_buffer, name_bytes, uc);
            const auto header_bytes = std::min<std::uint64_t>(image_size, kImageHeaderBytes);
            image.header_bytes.resize(static_cast<std::size_t>(header_bytes));
            const auto read_err =
                uc_mem_read(uc, dll_base, image.header_bytes.data(), image.header_bytes.size());
            if (read_err != UC_ERR_OK) {
                image.header_bytes.clear(); // unreadable: parse will report it
            }
            images.push_back(std::move(image));
        }

        link = read_guest_u32(uc, link);
        if (link == 0 || link == head) {
            break;
        }
    }
    return images;
}

std::string_view pe_parse_error_message(const PeParseError error)
{
    switch (error) {
    case PeParseError::kNone:
        return "ok";
    case PeParseError::kBadDos:
        return "missing MZ signature or e_lfanew out of range";
    case PeParseError::kBadPe:
        return "missing PE signature or headers truncated";
    case PeParseError::kNotPe32Plus:
        return "not a PE32+ image";
    case PeParseError::kTruncated:
        return "section table extends past the input";
    case PeParseError::kBadImageSize:
        return "SizeOfImage outside [1, 4GB)";
    }
    return "unknown PE parse error";
}

PeParseError parse_section_table(const std::uint8_t* image, const std::size_t size,
                                 ImageLayout& out)
{
    if (size < kDosHeaderSize || read_u16(image) != kDosMagic) {
        return PeParseError::kBadDos;
    }
    const auto pe_offset = static_cast<std::size_t>(read_u32(image + kELfanewOffset));
    if (pe_offset < kDosHeaderSize || pe_offset + kFileHeaderOffset + kFileHeaderSize > size ||
        read_u32(image + pe_offset) != kPeSignature) {
        return PeParseError::kBadPe;
    }
    const auto optional = pe_offset + 24;
    if (optional + kSizeOfHeadersOffset + 4 > size ||
        read_u16(image + optional + kMagicOffset) != kPe32PlusMagic) {
        return PeParseError::kNotPe32Plus;
    }

    const auto section_count = read_u16(image + pe_offset + kNumberOfSectionsOffset);
    const auto optional_size = read_u16(image + pe_offset + kSizeOfOptionalHeaderOffset);
    const auto table = optional + optional_size;
    if (table + sizeof(SectionHeader) * section_count > size) {
        return PeParseError::kTruncated;
    }

    out.size_of_headers = read_u32(image + optional + kSizeOfHeadersOffset);
    // SizeOfImage legality: [1, 4GB). The field is a dword, so the upper
    // bound is structural - only zero falls outside.
    out.size_of_image = read_u32(image + optional + kSizeOfImageOffset);
    if (out.size_of_image == 0) {
        return PeParseError::kBadImageSize;
    }
    const auto section_alignment =
        std::max<std::uint32_t>(1, read_u32(image + optional + kSectionAlignmentOffset));
    out.sections.clear();
    for (std::uint16_t i = 0; i < section_count; ++i) {
        SectionHeader raw{};
        std::memcpy(&raw, image + table + sizeof(SectionHeader) * i, sizeof raw);
        SectionRecord section;
        section.rva = raw.virtual_address;
        const auto span_source = raw.virtual_size != 0 ? raw.virtual_size : raw.size_of_raw_data;
        const auto span64 = std::min<std::uint64_t>(
            (static_cast<std::uint64_t>(span_source) + section_alignment - 1) / section_alignment *
                section_alignment,
            0xFFFFFFFFULL);
        section.span = static_cast<std::uint32_t>(span64);
        section.characteristics = raw.characteristics;
        std::memcpy(section.name.data(), raw.name.data(), kSectionNameBytes - 1);
        section.name[kSectionNameBytes - 1] = '\0';
        out.sections.push_back(std::move(section));
    }
    return PeParseError::kNone;
}

std::vector<ModuleImage>
synthesize_unknown_images(const std::span<const ModuleImage> ldr_images,
                          const std::span<const UnknownImageCandidate> candidates)
{
    std::vector<ModuleImage> synthesized;
    // Chains walk the candidates in base order (a local index sort: the
    // input order must not steer the output). Zero-size candidates chain
    // with nothing - they carry no extent to join.
    std::vector<std::size_t> order(candidates.size());
    std::iota(order.begin(), order.end(), std::size_t{0});
    std::sort(order.begin(), order.end(), [&](const std::size_t a, const std::size_t b) {
        return candidates[a].base < candidates[b].base;
    });

    // The no-overlap criterion is against the whole Ldr span [base,
    // base+size): a partial overlap would put a synthesized record on the
    // same base as a real module and make the attribution depend on the
    // (unstable) sort of equal spans.
    const auto overlaps_ldr = [&](const std::uint64_t base, const std::uint64_t size) {
        for (const auto& image : ldr_images) {
            if (base < image.module.base + image.module.size && image.module.base < base + size) {
                return true;
            }
        }
        return false;
    };

    constexpr std::uint64_t kImageBaseAlignment = 0x10000; // allocation granularity
    std::size_t at = 0;
    while (at < order.size()) {
        const auto& lead = candidates[order[at]];
        if (lead.size == 0 || lead.type != kMemImage) {
            ++at;
            continue;
        }
        std::size_t end = at + 1;
        while (end < order.size()) {
            const auto& prev = candidates[order[end - 1]];
            const auto& next = candidates[order[end]];
            if (next.size == 0 || next.type != kMemImage || prev.base + prev.size != next.base) {
                break;
            }
            ++end;
        }
        const std::uint64_t chain_start = candidates[order[at]].base;
        const std::uint64_t chain_end =
            candidates[order[end - 1]].base + candidates[order[end - 1]].size;
        const std::size_t chain_at = at;
        at = end; // the chain was [chain_at, end); the walk continues past it

        // Whole-chain overlap against the Ldr set; the anchor is the
        // lowest 64KB-aligned member base.
        bool overlapped = false;
        const UnknownImageCandidate* head = nullptr;
        for (std::size_t i = end; i > chain_at;) {
            const auto& member = candidates[order[--i]];
            overlapped = overlapped || overlaps_ldr(member.base, member.size);
            if (member.base % kImageBaseAlignment == 0) {
                head = &member; // descending walk: the last hit is the lowest base
            }
        }
        if (overlapped || head == nullptr || head->content.empty()) {
            continue; // criteria unmet: the chain keeps region-level attribution
        }
        ImageLayout layout;
        if (parse_section_table(head->content.data(), head->content.size(), layout) !=
            PeParseError::kNone) {
            continue;
        }
        ModuleImage image;
        image.module.base = head->base;
        image.module.size = std::min<std::uint64_t>(layout.size_of_image, chain_end - chain_start);
        image.module.synthesized = true;
        const auto name = std::format("unknown-image-{:016x}", image.module.base);
        std::memcpy(image.module.name.data(), name.data(),
                    (std::min)(name.size(), image.module.name.size() - 1));
        const auto header_bytes = static_cast<std::size_t>(
            std::min<std::uint64_t>(head->content.size(), kImageHeaderBytes));
        image.header_bytes.assign(head->content.begin(),
                                  head->content.begin() +
                                      static_cast<std::ptrdiff_t>(header_bytes));
        synthesized.push_back(std::move(image));
    }

    // Capacity self-clamp: the shared module index space, candidates skip
    // (ascending base - the first groups survive), never the Ldr set.
    const auto capacity = ldr_images.size() >= kMaxModuleImages
                              ? std::size_t{0}
                              : kMaxModuleImages - ldr_images.size();
    if (synthesized.size() > capacity) {
        synthesized.resize(capacity);
    }
    return synthesized;
}

MemRegionMap::MemRegionMap(const std::span<const ModuleImage> images,
                           const std::span<const RegionRecord> regions)
    : regions_(regions.begin(), regions.end())
{
    // Snapshot records are by definition snapshot-captured: normalize the
    // origin to the construction index (the seed of the monotonic identity
    // space) and clear the runtime flag whatever the input carried.
    for (std::size_t ri = 0; ri < regions_.size(); ++ri) {
        regions_[ri].origin = static_cast<std::uint32_t>(ri);
        regions_[ri].runtime_registered = false;
    }
    next_origin_ = static_cast<std::uint32_t>(regions_.size());

    modules_.reserve(images.size());
    for (const auto& image : images) {
        modules_.push_back(image.module);
    }

    // Module ownership of every snapshot region: overlap or contiguity with
    // a module span makes the region that module's territory (image
    // alignment gaps, companion thunk pages like ntdll's forwarder-thunk
    // page); orphans outside every module span are sample-controlled code
    // and data (the packed sample's out-of-image stub page).
    region_runtime_event_.resize(regions_.size(), 0);
    region_module_owner_.resize(regions_.size(), kNoModuleIndex);
    for (std::size_t ri = 0; ri < regions_.size(); ++ri) {
        set_region_owner(ri);
    }

    const auto clamp_to_module = [](const std::uint64_t start, const std::uint64_t span,
                                    const ModuleRecord& module) {
        const std::uint64_t module_end = module.base + module.size;
        return (std::min)(start + span, module_end);
    };

    for (std::size_t mi = 0; mi < images.size(); ++mi) {
        const auto& image = images[mi];
        // The owning snapshot region of an image attribution: the region
        // holding the image base (resolved once, here).
        std::size_t owning_region = 0;
        for (std::size_t ri = 0; ri < regions.size(); ++ri) {
            const auto& region = regions[ri];
            if (image.module.base >= region.base && image.module.base < region.base + region.size) {
                owning_region = ri;
                break;
            }
        }
        ImageLayout layout;
        if (parse_section_table(image.header_bytes.data(), image.header_bytes.size(), layout) !=
            PeParseError::kNone) {
            continue; // unparsable headers: the region interval still covers it
        }
        const auto image_end = image.module.base + image.module.size;
        const auto headers_end = (std::min)(image.module.base + layout.size_of_headers, image_end);
        if (headers_end > image.module.base) {
            Interval headers_interval{.start = image.module.base,
                                      .end = headers_end,
                                      .region_index = owning_region,
                                      .module_index = mi,
                                      .section_index = 0,
                                      .image = true,
                                      .protection = 0,
                                      .type = 0,
                                      .characteristics = 0,
                                      .section_name = {}};
            std::memcpy(headers_interval.section_name.data(), "headers", 8);
            intervals_.push_back(std::move(headers_interval));
        }
        for (std::size_t si = 0; si < layout.sections.size(); ++si) {
            const auto& section = layout.sections[si];
            const auto start = image.module.base + section.rva;
            const auto end = clamp_to_module(start, section.span, image.module);
            if (end <= start) {
                continue;
            }
            Interval interval{.start = start,
                              .end = end,
                              .region_index = owning_region,
                              .module_index = mi,
                              .section_index = si + 1,
                              .image = true,
                              .protection = 0,
                              .type = 0,
                              .characteristics = section.characteristics,
                              .section_name = {}};
            std::memcpy(interval.section_name.data(), section.name.data(), kSectionNameBytes - 1);
            intervals_.push_back(std::move(interval));
        }
    }

    for (std::size_t ri = 0; ri < regions.size(); ++ri) {
        const auto& region = regions[ri];
        if (region.size == 0) {
            continue;
        }
        intervals_.push_back(Interval{.start = region.base,
                                      .end = region.base + region.size,
                                      .region_index = ri,
                                      .module_index = 0,
                                      .section_index = 0,
                                      .image = false,
                                      .protection = region.protection,
                                      .type = region.type,
                                      .characteristics = 0,
                                      .section_name = {}});
    }

    sort_intervals();
}

void MemRegionMap::sort_intervals()
{
    std::sort(intervals_.begin(), intervals_.end(), [](const Interval& a, const Interval& b) {
        if (a.start != b.start) {
            return a.start < b.start;
        }
        return a.end - a.start < b.end - a.start; // most specific first
    });
}

std::size_t MemRegionMap::register_module_image(const ModuleImage& image,
                                                const std::uint32_t protection)
{
    // The span first becomes an infrastructure-issued region record - the
    // engine maps it, never the sample - then the section refinement rides
    // on top exactly like the constructor's image pass.
    register_region(image.module.base, image.module.size, protection, kMemImage, false);
    const std::size_t owning_region = regions_.size() - 1;
    const std::size_t module_index = modules_.size();
    modules_.push_back(image.module);

    ImageLayout layout;
    if (parse_section_table(image.header_bytes.data(), image.header_bytes.size(), layout) !=
        PeParseError::kNone) {
        // Diagnostic: a failed parse leaves the span region-level (the
        // runtime!runtime rendering) - surface it once per registration.
        sheller::log::warning(
            std::format("dll-loader: region-map module {} at 0x{:x} section parse failed",
                        module_index, image.module.base));
        return module_index; // the region interval still covers the span
    }
    sheller::log::warning(std::format("dll-loader: region-map module {} at 0x{:x} sections={} "
                                      "size=0x{:x}",
                                      module_index, image.module.base, layout.sections.size(),
                                      layout.size_of_image));
    const auto image_end = image.module.base + image.module.size;
    const auto clamp = [](const std::uint64_t start, const std::uint64_t span,
                          const std::uint64_t end) { return (std::min)(start + span, end); };
    const auto headers_end = (std::min)(image.module.base + layout.size_of_headers, image_end);
    if (headers_end > image.module.base) {
        Interval headers_interval{.start = image.module.base,
                                  .end = headers_end,
                                  .region_index = owning_region,
                                  .module_index = module_index,
                                  .section_index = 0,
                                  .image = true,
                                  .protection = 0,
                                  .type = 0,
                                  .characteristics = 0,
                                  .section_name = {}};
        std::memcpy(headers_interval.section_name.data(), "headers", 8);
        intervals_.push_back(std::move(headers_interval));
    }
    for (std::size_t si = 0; si < layout.sections.size(); ++si) {
        const auto& section = layout.sections[si];
        const auto start = image.module.base + section.rva;
        const auto end = clamp(start, section.span, image_end);
        if (end <= start) {
            continue;
        }
        Interval interval{.start = start,
                          .end = end,
                          .region_index = owning_region,
                          .module_index = module_index,
                          .section_index = si + 1,
                          .image = true,
                          .protection = 0,
                          .type = 0,
                          .characteristics = section.characteristics,
                          .section_name = {}};
        std::memcpy(interval.section_name.data(), section.name.data(), kSectionNameBytes - 1);
        intervals_.push_back(std::move(interval));
    }
    sort_intervals();
    return module_index;
}

void MemRegionMap::set_region_owner(const std::size_t index)
{
    const auto base = regions_[index].base;
    const auto size = regions_[index].size;
    for (std::size_t mi = 0; mi < modules_.size(); ++mi) {
        const auto mod_base = modules_[mi].base;
        const auto mod_end = mod_base + modules_[mi].size;
        // Overlap (image alignment gaps sit inside the module span) or
        // contiguity (companion pages mapped right at the image end, like
        // ntdll's forwarder-thunk page) makes the region that module's
        // territory.
        if ((base < mod_end && mod_base < base + size) || base == mod_end ||
            base + size == mod_base) {
            region_module_owner_[index] = mi;
            return;
        }
    }
}

void MemRegionMap::register_region(const std::uint64_t base, const std::uint64_t size,
                                   const std::uint32_t protection, const std::uint32_t type,
                                   const bool sample_issued)
{
    if (size == 0 || base + size < base) {
        return; // nothing mappable was registered; overflow-guarded no-op
    }
    RegionRecord record;
    record.base = base;
    record.size = size;
    record.protection = protection;
    record.type = type;
    record.origin = next_origin_++;
    record.runtime_registered = sample_issued;
    regions_.push_back(record);
    // Registered allocations never overlap a module span; the issuer flag
    // already decided their territory.
    region_runtime_event_.push_back(1);
    region_module_owner_.push_back(kNoModuleIndex);

    Interval interval{.start = base,
                      .end = base + size,
                      .region_index = regions_.size() - 1,
                      .module_index = 0,
                      .section_index = 0,
                      .image = false,
                      .protection = protection,
                      .type = type,
                      .characteristics = 0,
                      .section_name = {}};
    intervals_.push_back(interval);
    sort_intervals();
}

void MemRegionMap::apply_protection(const std::uint64_t base, const std::uint64_t size,
                                    const std::uint32_t protection)
{
    if (size == 0) {
        return;
    }
    const std::uint64_t page_mask = 0xFFF;
    const std::uint64_t aligned_base = base & ~page_mask;
    const std::uint64_t aligned_end = (base + size + page_mask) & ~page_mask;
    if (aligned_end <= aligned_base) {
        return; // range overflow: nothing sane to carve
    }
    // Affected region intervals, ascending by start (the vector is sorted
    // and the regions are disjoint). Snapshotting the indices first keeps
    // the walk read-only while the pass below appends.
    std::vector<std::size_t> affected;
    for (std::size_t i = 0; i < intervals_.size(); ++i) {
        const auto& interval = intervals_[i];
        if (interval.start >= aligned_end) {
            break; // sorted by start: nothing later can overlap
        }
        if (!interval.image && interval.end > aligned_base) {
            affected.push_back(i);
        }
    }
    for (const auto i : affected) {
        // Local copies: both vectors grow inside the loop, so nothing may
        // be held by reference across the appends (indices stay valid).
        const Interval interval = intervals_[i];
        const RegionRecord record = regions_[interval.region_index];
        const auto overlap_start = (std::max)(interval.start, aligned_base);
        const auto overlap_end = (std::min)(interval.end, aligned_end);

        // The carved record: new protection, inherited identity (origin and
        // runtime flag) and MEM type. Immutable once appended, like every
        // region record.
        RegionRecord carved;
        carved.base = overlap_start;
        carved.size = overlap_end - overlap_start;
        carved.protection = protection;
        carved.type = record.type;
        carved.origin = record.origin;
        carved.runtime_registered = record.runtime_registered;
        regions_.push_back(carved);
        region_runtime_event_.push_back(region_runtime_event_[interval.region_index]);
        region_module_owner_.push_back(region_module_owner_[interval.region_index]);
        const auto carved_index = regions_.size() - 1;

        // This interval is re-pointed at the covered part; the uncovered
        // head and tail (if any) stay on the original record as their own
        // intervals. Write-back by index: appends preserve indices.
        Interval middle = interval;
        middle.end = overlap_end;
        middle.region_index = carved_index;
        middle.protection = protection;
        if (interval.start < overlap_start) {
            Interval head = interval;
            head.end = overlap_start;
            head.protection = record.protection;
            intervals_.push_back(head);
            middle.start = overlap_start;
        }
        if (overlap_end < interval.end) {
            Interval tail = interval;
            tail.start = overlap_end;
            tail.protection = record.protection;
            intervals_.push_back(tail);
        }
        intervals_[i] = middle;
    }
    if (!affected.empty()) {
        sort_intervals();
    }
}

std::optional<MemAttribution> MemRegionMap::query(const std::uint64_t address) const
{
    auto best = intervals_.size();
    for (std::size_t i = 0; i < intervals_.size(); ++i) {
        const auto& interval = intervals_[i];
        if (interval.start > address) {
            break; // sorted by start: nothing later can contain the address
        }
        if (address < interval.end) {
            // Most specific wins, with one hard rule: an image interval
            // (section or headers) always refines its containing captured
            // region, whatever the fragment sizes are - protection-split
            // region fragments inside one section must not out-specific the
            // section (the UPX stub's RWX tail page inside UPX1). Among
            // same-kind intervals the smaller span wins; equal spans keep
            // the first (the iteration order is deterministic).
            if (best == intervals_.size()) {
                best = i;
            } else if (interval.image != intervals_[best].image) {
                if (interval.image) {
                    best = i;
                }
            } else if (interval.end - interval.start <
                       intervals_[best].end - intervals_[best].start) {
                best = i;
            }
        }
    }
    if (best == intervals_.size()) {
        return std::nullopt;
    }
    const auto& interval = intervals_[best];
    const auto& record = regions_[interval.region_index];

    MemAttribution result;
    result.region_index = interval.region_index;
    result.protection = record.protection;
    result.type = record.type;
    result.runtime_registered = record.runtime_registered;
    result.runtime_event = region_runtime_event_[interval.region_index] != 0;
    result.module_owner = region_module_owner_[interval.region_index];
    result.origin = record.origin;
    if (interval.image) {
        result.kind = interval.section_index == 0 ? AttributionKind::kImageHeaders
                                                  : AttributionKind::kImageSection;
        result.module_index = interval.module_index;
        result.module_name = modules_[interval.module_index].name.data();
        result.section_index = interval.section_index;
        result.section_name = interval.section_name.data();
        result.characteristics = interval.characteristics;
        result.identity = {result.kind, static_cast<std::uint32_t>(interval.module_index),
                           static_cast<std::uint32_t>(interval.section_index)};
    } else {
        result.kind = AttributionKind::kRegion;
        result.module_index = kNoModuleIndex;
        result.section_index = kNoSectionIndex;
        // The class rides its wire sentinel: the tier (snapshot vs runtime
        // registration) is part of the identity the xfer capture compares.
        result.identity = {AttributionKind::kRegion, record.origin,
                           region_class_sentinel(region_class(record.protection, record.type),
                                                 record.runtime_registered)};
    }
    return result;
}

std::optional<std::size_t> MemRegionMap::module_index_by_name(const std::string_view name) const
{
    for (std::size_t i = 0; i < modules_.size(); ++i) {
        if (name == std::string_view(modules_[i].name.data())) {
            return i;
        }
    }
    return std::nullopt;
}

} // namespace sheller::engine::mem_region
