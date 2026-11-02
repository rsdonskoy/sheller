#!/usr/bin/env python3
"""Generate the versioned boundary-description seed table (design D2,
change real-dll-module-dir).

Reads tools/boundary_manifest/*.json (one (module, arch) per file: the
applicability xxhash64 list plus the per-export classification) and emits
src/engine/boundary_seed.inc - a deterministic POD table the engine maps
onto loader::BoundaryRule vectors at construction time. Builds never parse
JSON: the committed .inc is the only runtime artifact.

Deterministic: files in sorted name order, exports in JSON array order,
stable scalar formatting - the same manifest in, byte-identical .inc out.
The boundary_seed test regenerates twice and byte-compares against the
committed file, so editing a JSON without regenerating fails the build.

Regenerate:
    python tools/gen_boundary_seed.py tools/boundary_manifest src/engine/boundary_seed.inc
"""

import json
import sys
from pathlib import Path

SCHEMA = 1
KINDS = {"syscallstub": 0, "intercept": 1, "trap": 2, "compat": 3, "data": 4}


def fail(message):
    raise SystemExit(message)


def parse_u64(text):
    """Parses a decimal or 0x-prefixed u64 spelling; returns (value, ok)."""
    try:
        value = int(text, 0)
    except (TypeError, ValueError):
        return 0, False
    return value, 0 <= value < (1 << 64)


def load_module(path):
    """Validates one manifest file and returns (name, arch, rows) where rows
    is the emitted text body."""
    manifest = json.loads(path.read_text(encoding="utf-8"))
    name = manifest.get("module", "")
    arch = manifest.get("arch", "")
    images = manifest.get("images", [])
    exports = manifest.get("exports", [])
    if manifest.get("schema") != SCHEMA:
        fail("%s: schema must be %d" % (path.name, SCHEMA))
    if not name.endswith(".dll") or name != name.lower():
        fail("%s: module must be a folded name with extension" % path.name)
    if arch not in ("x64", "x86"):
        fail("%s: arch must be x64 or x86" % path.name)
    if not images:
        fail("%s: the images list is empty - nothing to bind" % path.name)
    if not exports:
        fail("%s: the exports list is empty" % path.name)
    stem = name[:-4].capitalize()
    # two files may cover the same module+arch with different rule sets
    # (e.g. the fixture build and a real Windows build) — disambiguate by
    # the file name so both arrays coexist
    suffix = ""
    stem_lower = path.stem.lower()
    if stem_lower.endswith(".real"):
        suffix = "Real"
    ident = "k%s%s%s" % (stem, "X64" if arch == "x64" else "X86", suffix)

    image_rows = []
    for image in images:
        value, ok = parse_u64(image.get("xxhash64"))
        if not ok:
            fail("%s: bad xxhash64 %r" % (path.name, image.get("xxhash64")))
        note = (str(image.get("note", "")).replace("\\", "\\\\")
                .replace('"', "'"))
        image_rows.append('    {0x%016xULL, "%s"},' % (value, note))

    export_rows = []
    seen = set()
    for entry in exports:
        export_name = str(entry.get("name", ""))
        kind_name = entry.get("kind")
        if kind_name not in KINDS:
            fail("%s: unknown kind %r" % (path.name, kind_name))
        key = (export_name, entry.get("ordinal"))
        if export_name and key in seen:
            fail("%s: duplicate export %r" % (path.name, export_name))
        seen.add(key)
        kind = KINDS[kind_name]
        ret, out, size, align, data_hex = 0, "", 0, 0, ""
        abi = entry.get("abi", {})
        if abi:
            # schema-reserved x86 stdcall cleanup; phase 1 derives x64 only
            if set(abi) != {"x86_cleanup"}:
                fail("%s: abi carries unknown fields %s" % (path.name, sorted(abi)))
        if kind_name == "compat":
            ret, ok = parse_u64(entry.get("ret"))
            if not ok:
                fail("%s: compat export %r needs ret" % (path.name, export_name))
            out = str(entry.get("out", ""))
        elif "ret" in entry or "out" in entry:
            fail("%s: %s export %r must not carry ret/out" % (path.name, kind_name, export_name))
        if kind_name == "data":
            layout = entry.get("layout", {})
            size = layout.get("size", 0)
            align = layout.get("align", 0)
            data_hex = str(layout.get("bytes", ""))
            if not isinstance(size, int) or size <= 0 or size > 0x10000:
                fail("%s: data export %r has a bad size" % (path.name, export_name))
            if align not in (1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024,
                             2048, 4096):
                fail("%s: data export %r align must be a power of two <= 4096"
                     % (path.name, export_name))
            if len(data_hex) != 2 * size or any(
                    c not in "0123456789abcdef" for c in data_hex.lower()):
                fail("%s: data export %r bytes must be %d hex chars"
                     % (path.name, export_name, 2 * size))
            data_hex = data_hex.lower()
        elif "layout" in entry:
            fail("%s: %s export %r must not carry layout" % (path.name, kind_name, export_name))
        export_rows.append(
            '    {"%s", %d, %d, 0x%016xULL, "%s", %d, %d, "%s"},'
            % (export_name, entry.get("ordinal", 0), kind, ret, out, size, align, data_hex))

    body = [
        "// %s (%s)" % (name, arch),
        "inline constexpr SeedImage %sImages[] = {" % ident,
    ]
    body.extend(image_rows)
    body.append("};")
    body.append("inline constexpr SeedExport %sExports[] = {" % ident)
    body.extend(export_rows)
    body.append("};")
    module_row = ('    {"%s", "%s", %sImages, %d, %sExports, %d},'
                  % (name, arch, ident, len(images), ident, len(exports)))
    return body, module_row


def main():
    if len(sys.argv) != 3:
        print("usage: gen_boundary_seed.py <manifest-dir> <out-file>")
        return 1
    manifest_dir = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    sources = sorted(manifest_dir.glob("*.json"))
    if not sources:
        fail("no manifest JSON under %s" % manifest_dir)

    blocks = []
    module_rows = []
    for source in sources:
        block, module_row = load_module(source)
        blocks.append(block)
        module_rows.append(module_row)

    lines = [
        "// Generated by tools/gen_boundary_seed.py from"
        " tools/boundary_manifest/*.json.",
        "// Versioned boundary-description seed (design D2, change"
        " real-dll-module-dir):",
        "// applicability binds to the source image's whole-file xxhash64."
        " Regenerate:",
        "//     python tools/gen_boundary_seed.py tools/boundary_manifest"
        " src/engine/boundary_seed.inc",
        "// Byte-stable for a fixed manifest; the boundary_seed test"
        " enforces freshness.",
        "// The kind constants mirror loader::BoundaryKind (pinned by"
        " static_assert in",
        "// boundary_manifest.cpp).",
        "#pragma once",
        "",
        "#include <cstddef>",
        "#include <cstdint>",
        "",
        "namespace sheller::engine::boundary_seed {",
        "",
        "enum : std::uint8_t {",
        "    kSeedSyscallStub = 0,",
        "    kSeedIntercept = 1,",
        "    kSeedTrap = 2,",
        "    kSeedCompat = 3,",
        "    kSeedData = 4,",
        "};",
        "",
        "struct SeedExport {",
        "    const char* name;            // empty: ordinal-only entry",
        "    std::uint32_t ordinal;",
        "    std::uint8_t kind;",
        "    std::uint64_t compat_return; // kSeedCompat failure return",
        "    const char* out;             // kSeedCompat OUT recipes, ';'-separated",
        "    std::uint32_t data_size;     // kSeedData slot layout",
        "    std::uint32_t data_align;",
        "    const char* data_hex;        // kSeedData initial bytes, hex",
        "};",
        "",
        "struct SeedImage {",
        "    std::uint64_t xxhash64; // whole-file hash of the covered image",
        "    const char* note;       // provenance spelling",
        "};",
        "",
        "struct SeedModule {",
        "    const char* module; // folded name with extension",
        "    const char* arch;   // \"x64\"",
        "    const SeedImage* images;",
        "    std::size_t image_count;",
        "    const SeedExport* exports;",
        "    std::size_t export_count;",
        "};",
        "",
    ]
    for block in blocks:
        lines.extend(block)
        lines.append("")
    lines.append("inline constexpr SeedModule kModules[] = {")
    lines.extend(module_rows)
    lines.append("};")
    lines.append("")
    lines.append("} // namespace sheller::engine::boundary_seed")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("wrote %s (%d modules)" % (out_path, len(blocks)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
