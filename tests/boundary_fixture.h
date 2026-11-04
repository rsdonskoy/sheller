// Shared boundary-mechanism fixture: the
// deterministic self-made AMD64 "directory file" the boundary tests derive
// from and the directory-mode route tests map. Its whole-file xxhash64 is
// pinned in tools/boundary_manifest/ntdll.x64.json - edit the builder and
// the manifest together, or the applicability check will name the mismatch.
// Pure byte construction, no compiler-dependent content.

#pragma once

#include "boundary_derive.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace sheller_test {

// ---- fixture: a hand-built AMD64 source module -----------------------------
// One .text section whose RVAs are file offsets (raw pointer == RVA), body
// slots at a 16-byte stride, the export directory from RVA 0x2000.

inline constexpr std::uint32_t kBoundarySourceBase = 0x400000;
inline constexpr std::uint32_t kBoundaryTextRva = 0x1000;
inline constexpr std::uint32_t kBoundaryDirRva = 0x2000;
inline constexpr std::size_t kBoundarySourceFileSize = 0x4000;

struct BoundaryFixtureExport {
    const char* name;       // nullptr: unnamed export
    const char* alias_name; // optional second name on the same EAT index (alias)
    std::uint32_t body_rva;
    std::vector<std::uint8_t> body; // empty: EAT hole
    std::string forwarder;          // non-empty: forwarder string instead of a body
};

// Builds the source file bytes. exports[i] is EAT index i; names appear in
// the names array in the order given (alias names share one EAT index).
inline std::vector<std::uint8_t>
make_boundary_source(const std::vector<BoundaryFixtureExport>& exports)
{
    std::vector<std::uint8_t> file(kBoundarySourceFileSize, std::uint8_t{0});
    const auto at = [&](const std::uint32_t rva) { return file.data() + rva; };
    const auto put16 = [&](const std::uint32_t rva, const std::uint16_t v) {
        at(rva)[0] = static_cast<std::uint8_t>(v);
        at(rva)[1] = static_cast<std::uint8_t>(v >> 8);
    };
    const auto put32 = [&](const std::uint32_t rva, const std::uint32_t v) {
        for (unsigned i = 0; i < 4; ++i) {
            at(rva)[i] = static_cast<std::uint8_t>(v >> (8 * i));
        }
    };
    const auto put_string = [&](const std::uint32_t rva, const std::string& text) {
        std::memcpy(at(rva), text.data(), text.size());
        at(rva)[text.size()] = 0;
    };

    put16(0, 0x5A4D);
    put32(0x3C, 0x80);
    put32(0x80, 0x00004550);
    put16(0x84, 0x8664); // machine
    put16(0x86, 1);      // one section
    put16(0x94, 0xF0);   // size of optional header
    put16(0x96, 0x2022);
    put16(0x98, 0x020B);                   // PE32+ magic
    put32(0x98 + 16, kBoundaryTextRva);    // entry
    put32(0x98 + 24, kBoundarySourceBase); // image base
    put32(0x98 + 32, 0x1000);              // section alignment
    put32(0x98 + 36, 0x1000);              // file alignment
    put32(0x98 + 56, kBoundarySourceFileSize);
    put32(0x98 + 60, 0x1000); // size of headers
    put16(0x98 + 68, 3);      // subsystem
    put32(0x98 + 108, 16);    // number of data directories
    // data directory [0] filled after the directory span is known
    // section table at 0x188: .text with RVA == file offset
    put32(0x188 + 8, 0x3000);            // virtual size
    put32(0x188 + 12, kBoundaryTextRva); // virtual address
    put32(0x188 + 16, 0x3000);           // raw size
    put32(0x188 + 20, kBoundaryTextRva); // raw pointer
    put32(0x188 + 36, 0x60000020);       // characteristics

    // body slots
    for (std::size_t i = 0; i < exports.size(); ++i) {
        if (!exports[i].body.empty()) {
            std::memcpy(at(exports[i].body_rva), exports[i].body.data(), exports[i].body.size());
        }
    }

    // export directory at 0x2000; the layout cursor follows it. The name
    // count includes alias names (one directory row per name).
    const std::uint32_t name_count =
        static_cast<std::uint32_t>(
            std::count_if(exports.begin(), exports.end(),
                          [](const BoundaryFixtureExport& e) { return e.name != nullptr; })) +
        static_cast<std::uint32_t>(
            std::count_if(exports.begin(), exports.end(),
                          [](const BoundaryFixtureExport& e) { return e.alias_name != nullptr; }));
    const std::uint32_t eat_rva = kBoundaryDirRva + 40;
    const std::uint32_t names_rva = eat_rva + 4 * static_cast<std::uint32_t>(exports.size());
    const std::uint32_t ordinals_rva = names_rva + 4 * name_count;
    std::uint32_t cursor = ordinals_rva + 2 * name_count;
    const std::uint32_t module_name_rva = cursor;
    put_string(cursor, "fakentdll.dll");
    cursor += static_cast<std::uint32_t>(std::strlen("fakentdll.dll")) + 1;
    std::uint32_t name_index = 0;
    for (std::size_t i = 0; i < exports.size(); ++i) {
        const auto& entry = exports[i];
        const auto emit_name = [&](const char* text) {
            if (text == nullptr) {
                return;
            }
            put_string(cursor, text);
            put32(names_rva + 4 * name_index, cursor);
            put16(ordinals_rva + 2 * name_index, static_cast<std::uint16_t>(i));
            ++name_index;
            cursor += static_cast<std::uint32_t>(std::strlen(text)) + 1;
        };
        emit_name(entry.name);
        emit_name(entry.alias_name);
    }
    std::vector<std::uint32_t> forwarder_rvas(exports.size(), 0);
    for (std::size_t i = 0; i < exports.size(); ++i) {
        if (!exports[i].forwarder.empty()) {
            forwarder_rvas[i] = cursor;
            put_string(cursor, exports[i].forwarder);
            cursor += static_cast<std::uint32_t>(exports[i].forwarder.size()) + 1;
        }
    }
    put32(kBoundaryDirRva + 0x0C, module_name_rva);
    put32(kBoundaryDirRva + 0x10, 0); // export base
    put32(kBoundaryDirRva + 0x14, static_cast<std::uint32_t>(exports.size()));
    put32(kBoundaryDirRva + 0x18, name_count);
    put32(kBoundaryDirRva + 0x1C, eat_rva);
    put32(kBoundaryDirRva + 0x20, names_rva);
    put32(kBoundaryDirRva + 0x24, ordinals_rva);
    for (std::size_t i = 0; i < exports.size(); ++i) {
        put32(eat_rva + 4 * static_cast<std::uint32_t>(i),
              exports[i].forwarder.empty() ? exports[i].body_rva : forwarder_rvas[i]);
    }
    put32(0x98 + 112, kBoundaryDirRva);          // export dir RVA
    put32(0x98 + 116, cursor - kBoundaryDirRva); // export dir size
    return file;
}

inline constexpr std::uint32_t kBoundaryStubRva = kBoundaryTextRva;          // EAT 0
inline constexpr std::uint32_t kBoundaryZwStubRva = kBoundaryTextRva + 0x10; // EAT 1
inline constexpr std::uint32_t kBoundaryInterceptRva = kBoundaryTextRva + 0x20;
inline constexpr std::uint32_t kBoundaryNtWeirdRva = kBoundaryTextRva + 0x30;
inline constexpr std::uint32_t kBoundaryDataRva = kBoundaryTextRva + 0x40;
inline constexpr std::uint32_t kBoundaryUnnamedStubRva = kBoundaryTextRva + 0x50;
inline constexpr std::uint32_t kBoundaryTerminateRva = kBoundaryTextRva + 0x60;
inline constexpr std::uint32_t kBoundaryUnknownRva = kBoundaryTextRva + 0x70;

inline std::vector<std::uint8_t> boundary_x64_stub(const std::uint32_t number)
{
    return {0x4C,
            0x8B,
            0xD1,
            0xB8,
            static_cast<std::uint8_t>(number),
            static_cast<std::uint8_t>(number >> 8),
            static_cast<std::uint8_t>(number >> 16),
            static_cast<std::uint8_t>(number >> 24),
            0x0F,
            0x05,
            0xC3};
}

// EAT 0..5: the named/alias/unnamed mechanism set. The unknown-export
// variant appends EAT 6 (no manifest rule covers it).
inline std::vector<BoundaryFixtureExport> boundary_fixture_exports(const bool with_unknown)
{
    std::vector<BoundaryFixtureExport> exports{
        {"NtCreateFile", nullptr, kBoundaryStubRva, boundary_x64_stub(0x55), {}},
        {"ZwCreateFile", nullptr, kBoundaryZwStubRva, boundary_x64_stub(0x55), {}},
        // one EAT index carrying two names: the alias pair
        {"RtlFoo", "RtlFooAlias", kBoundaryInterceptRva, {0x31, 0xC0, 0xC3}, {}},
        {"NtWeird", nullptr, kBoundaryNtWeirdRva, {0x33, 0xC0, 0xC3}, {}}, // Nt prefix, no stub
        {"DataExport", nullptr, kBoundaryDataRva, {0x00}, {}},
        {nullptr, nullptr, kBoundaryUnnamedStubRva, boundary_x64_stub(0x66), {}},
        // the terminate service: the execution-fixture exit (the contract
        // policy answers it by name and stops the run)
        {"NtTerminateProcess", nullptr, kBoundaryTerminateRva, boundary_x64_stub(0x2C), {}},
    };
    if (with_unknown) {
        exports.push_back({"NtUnknown", nullptr, kBoundaryUnknownRva, {0x31, 0xC0, 0xC3}, {}});
    }
    return exports;
}

// The manifest rule set covering every fixture export (happy path) - the
// same dispositions tools/boundary_manifest/ntdll.x64.json registers.
inline std::vector<sheller::loader::BoundaryRule> boundary_fixture_rules()
{
    sheller::loader::BoundaryRule data;
    data.name = "DataExport";
    data.ordinal = 4;
    data.kind = sheller::loader::BoundaryKind::kData;
    data.data_size = 8;
    data.data_align = 8;
    data.data_bytes = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    return {
        {"NtCreateFile", 0, sheller::loader::BoundaryKind::kSyscallStub, 0, "", 0, 0, {}},
        {"ZwCreateFile", 1, sheller::loader::BoundaryKind::kSyscallStub, 0, "", 0, 0, {}},
        {"RtlFoo", 2, sheller::loader::BoundaryKind::kCompat, 0xC0000001, "", 0, 0, {}},
        {"RtlFooAlias", 2, sheller::loader::BoundaryKind::kCompat, 0xC0000001, "", 0, 0, {}},
        {"NtWeird", 3, sheller::loader::BoundaryKind::kTrap, 0, "", 0, 0, {}},
        data,
        {{}, 5, sheller::loader::BoundaryKind::kSyscallStub, 0, "", 0, 0, {}}, // unnamed ordinal
        {"NtTerminateProcess", 6, sheller::loader::BoundaryKind::kSyscallStub, 0, "", 0, 0, {}},
    };
}

} // namespace sheller_test

// The whole-file xxhash64 of make_boundary_source(boundary_fixture_exports(false))
// - the value pinned in tools/boundary_manifest/ntdll.x64.json. Tests
// static_assert against it so a fixture drift cannot pass silently.
namespace sheller_test {
inline constexpr std::uint64_t kFixtureNtdllXxhash64 = 0x6c806f42b18c5f46ULL;
} // namespace sheller_test

namespace sheller_test {

// ---- importing-PE fixture (resident-IAT-binding tests) ---------------------
// A full AMD64 PE with an export table AND an import table: the module the
// directory mode maps as real bytes, whose bodies call through its own IAT.
// Fixed layout: bodies 0x1000 + 16*i, the IAT at 0x1080 (8 bytes per import
// function, zero terminator), import directory 0x2000, export directory
// 0x2800. ImageBase 0x400000, no relocations.

inline constexpr std::uint32_t kImportingIatRva = 0x1080;
inline constexpr std::uint32_t kImportingMaxBodies = 8;
inline constexpr std::size_t kImportingFileSize = 0x5000;
inline constexpr std::uint32_t kImportingRelocRva = 0x3800;

struct BoundaryImport {
    const char* dll; // folded, with extension
    std::vector<const char*> functions;
};

inline std::vector<std::uint8_t>
make_importing_source(const std::vector<BoundaryFixtureExport>& exports,
                      const std::vector<BoundaryImport>& imports)
{
    std::vector<std::uint8_t> file(kImportingFileSize, std::uint8_t{0});
    const auto at = [&](const std::uint32_t rva) { return file.data() + rva; };
    const auto put16 = [&](const std::uint32_t rva, const std::uint16_t v) {
        at(rva)[0] = static_cast<std::uint8_t>(v);
        at(rva)[1] = static_cast<std::uint8_t>(v >> 8);
    };
    const auto put32 = [&](const std::uint32_t rva, const std::uint32_t v) {
        for (unsigned i = 0; i < 4; ++i) {
            at(rva)[i] = static_cast<std::uint8_t>(v >> (8 * i));
        }
    };
    const auto put_string = [&](const std::uint32_t rva, const std::string& text) {
        std::memcpy(at(rva), text.data(), text.size());
        at(rva)[text.size()] = 0;
    };

    put16(0, 0x5A4D);
    put32(0x3C, 0x80);
    put32(0x80, 0x00004550);
    put16(0x84, 0x8664);
    put16(0x86, 2); // .text + .reloc
    put16(0x94, 0xF0);
    put16(0x96, 0x2022);
    put16(0x98, 0x020B);
    put32(0x98 + 16, kBoundaryTextRva);
    put32(0x98 + 24, 0x400000);
    put32(0x98 + 32, 0x1000);
    put32(0x98 + 36, 0x1000);
    put32(0x98 + 56, kImportingFileSize);
    put32(0x98 + 60, 0x1000);
    put16(0x98 + 68, 3);
    put32(0x98 + 108, 16);

    // body slots
    for (std::size_t i = 0; i < exports.size() && i < kImportingMaxBodies; ++i) {
        if (!exports[i].body.empty()) {
            std::memcpy(at(exports[i].body_rva), exports[i].body.data(), exports[i].body.size());
        }
    }

    // import directory at 0x2000: one descriptor per import DLL + terminator;
    // ILT arrays at 0x2100; hint/name entries at 0x2200
    const std::uint32_t import_dir_size = 20 * static_cast<std::uint32_t>(imports.size() + 1);
    std::uint32_t ilt_cursor = 0x2100;
    std::uint32_t hint_cursor = 0x2200;
    for (std::size_t d = 0; d < imports.size(); ++d) {
        const auto descriptor = 0x2000 + 20 * static_cast<std::uint32_t>(d);
        // each DLL owns a 64-byte FirstThunk block (8 slots) at the IAT
        const auto first_thunk = kImportingIatRva + 64 * static_cast<std::uint32_t>(d);
        put32(descriptor, ilt_cursor); // OriginalFirstThunk (ILT)
        put32(descriptor + 16, first_thunk);
        const auto name_rva = 0x2000 + import_dir_size + 16 * static_cast<std::uint32_t>(d);
        put_string(name_rva, imports[d].dll);
        put32(descriptor + 12, name_rva);
        std::uint32_t t = 0;
        for (const auto* function : imports[d].functions) {
            put_string(hint_cursor + 2, function);
            // PE32+ thunk entries are 8 bytes: the hint/name RVA in the low
            // dword, the terminator's zero spread across both
            put32(ilt_cursor + 8 * t, hint_cursor); // by-name (hint RVA)
            put32(first_thunk + 8 * t,
                  hint_cursor); // FirstThunk mirrors the ILT until binding
            hint_cursor += 2 + static_cast<std::uint32_t>(std::strlen(function)) + 1;
            ++t;
        }
        ilt_cursor += 8 * (static_cast<std::uint32_t>(imports[d].functions.size()) + 1);
    }

    // export directory at 0x2800 (mirror of the source builder's shape)
    if (!exports.empty()) {
        const std::uint32_t dir_rva = 0x2800;
        const std::uint32_t eat_rva = dir_rva + 40;
        const std::uint32_t names_rva = eat_rva + 4 * static_cast<std::uint32_t>(exports.size());
        const std::uint32_t ordinals_rva =
            names_rva + 4 * static_cast<std::uint32_t>(exports.size());
        std::uint32_t cursor = ordinals_rva + 2 * static_cast<std::uint32_t>(exports.size());
        const std::uint32_t module_name_rva = cursor;
        put_string(cursor, "fixture.dll");
        cursor += static_cast<std::uint32_t>(std::strlen("fixture.dll")) + 1;
        std::uint32_t name_index = 0;
        for (std::size_t i = 0; i < exports.size(); ++i) {
            if (exports[i].name == nullptr) {
                continue;
            }
            put_string(cursor, exports[i].name);
            put32(names_rva + 4 * name_index, cursor);
            put16(ordinals_rva + 2 * name_index, static_cast<std::uint16_t>(i));
            ++name_index;
            cursor += static_cast<std::uint32_t>(std::strlen(exports[i].name)) + 1;
        }
        std::vector<std::uint32_t> function_rvas;
        for (const auto& exported : exports) {
            if (exported.forwarder.empty()) {
                function_rvas.push_back(exported.body_rva);
            } else {
                function_rvas.push_back(cursor);
                put_string(cursor, exported.forwarder);
                cursor += static_cast<std::uint32_t>(exported.forwarder.size()) + 1;
            }
        }
        put32(dir_rva + 0x0C, module_name_rva);
        put32(dir_rva + 0x10, 0);
        put32(dir_rva + 0x14, static_cast<std::uint32_t>(exports.size()));
        put32(dir_rva + 0x18, name_index);
        put32(dir_rva + 0x1C, eat_rva);
        put32(dir_rva + 0x20, names_rva);
        put32(dir_rva + 0x24, ordinals_rva);
        for (std::size_t i = 0; i < exports.size(); ++i) {
            put32(eat_rva + 4 * static_cast<std::uint32_t>(i), function_rvas[i]);
        }
        put32(0x98 + 112, dir_rva);
        put32(0x98 + 116, cursor - dir_rva);
    }

    // data directory [1]: the import directory
    put32(0x98 + 112 + 8, 0x2000);
    put32(0x98 + 112 + 12, import_dir_size);

    // data directory [5]: the base-relocation table. The image contains no
    // absolute fields, so the table holds one padding entry (type 0) — its
    // presence declares relocatability, which the directory-mode loader
    // requires when the image maps off its preferred base.
    put32(kImportingRelocRva, 0);          // block PageRVA 0
    put32(kImportingRelocRva + 4, 12);     // block size: header + entry + pad
    put16(kImportingRelocRva + 8, 0x0000); // ABSOLUTE padding entry
    put32(0x98 + 112 + 5 * 8, kImportingRelocRva);
    put32(0x98 + 112 + 5 * 8 + 4, 12);

    // section table at 0x188: RWX .text with RVA == file offset, then
    // INIT_DATA .reloc (also RVA == file offset)
    put32(0x188 + 8, 0x3000);
    put32(0x188 + 12, kBoundaryTextRva);
    put32(0x188 + 16, 0x3000);
    put32(0x188 + 20, kBoundaryTextRva);
    put32(0x188 + 36, 0x60000020);
    {
        auto* reloc_header = at(0x188) + 2 * 40;
        const char name[8] = {'.', 'r', 'e', 'l', 'o', 'c', 0, 0};
        std::memcpy(reloc_header, name, 8);
        const auto put = [&](const std::uint32_t field, const std::uint32_t v) {
            for (unsigned i = 0; i < 4; ++i) {
                reloc_header[field + i] = static_cast<std::uint8_t>(v >> (8 * i));
            }
        };
        put(8, 0x1000);              // virtual size
        put(12, kImportingRelocRva); // virtual address
        put(16, 0x1000);             // raw size
        put(20, kImportingRelocRva); // raw pointer (RVA == offset)
        put(36, 0x42000040);         // INIT_DATA | READ | DISCARDABLE
    }
    return file;
}

} // namespace sheller_test
