#!/usr/bin/env python3
"""Generate a boundary manifest from a REAL Windows ntdll.dll (dev-time tool,
Windows host with the DLL present; the output JSON is committed and
hash-bound to the exact source build).

Coverage (must satisfy the derive's strictness — every EAT slot needs a
disposition or must be one the derive preserves ruleless):
  - every export-directory slot is walked in EAT order, named or not;
    unnamed slots carry an empty name and their true ordinal
    (export_base + EAT index), the lookup key the derive uses for them
  - EAT holes (rva 0) and forwarder slots are skipped: the derive preserves
    both ruleless, and a rule on either is a named derive rejection
  - a body matching the x64 syscall stub shape (4C 8B D1 B8 imm32,
    syscall; ret) -> syscallstub (Nt* and Zw* aliases alike; the shape
    decides, never the prefix; the derive re-reads the number from the body)
  - any other .text function -> trap (an unsupported stop with a named
    diagnosis; the manifest later upgrades individual functions to
    intercept/compat/data as engine support lands)
  - a pointer outside .text is a data object: generation FAILS and names
    it — classification stays manual, never guessed.

Usage:
    python tools/gen_boundary_manifest.py C:/Windows/System32/ntdll.dll \
        tools/boundary_manifest/ntdll.x64.real.json
"""

import json
import struct
import sys
from pathlib import Path

X64_STUB_PREFIX = b"\x4c\x8b\xd1\xb8"
STUB_LEN = 11  # mov r10, rcx; mov eax, imm32; syscall; ret

# Reviewed data-object overrides (the manual classification the tool refuses
# to guess): exported .data objects with a bound known from their system
# contract, not inferred from bytes. Each entry zeroes that many bytes at
# the export's slot in the derived image.
REVIEWED_DATA_EXPORTS = {
    # the inverted-function-table head pointer: exactly one 8-byte pointer
    "KiUserInvertedFunctionTable": 8,
    # the init-block pointer the system hands the loader: one 8-byte pointer
    "LdrSystemDllInitBlock": 8,
    # NLS system data words: typed globals sized by their type contract,
    # not inferred from neighboring bytes
    "NlsAnsiCodePage": 2,     # USHORT
    "NlsMbCodePageTag": 1,    # BOOLEAN
    "NlsMbOemCodePageTag": 1, # BOOLEAN
    # allocator bookkeeping heads: one 8-byte pointer each
    "RtlAllocateMemoryBlockLookaside": 8,
    "RtlAllocateMemoryZone": 8,
    "RtlFreeMemoryBlockLookaside": 8,
    # the module's own name pointer: one 8-byte pointer
    "RtlNtdllName": 8,
    # the time-bias cell: one ULONG
    "RtlpFreezeTimeBias": 4,
    # the CFG policy head: one 8-byte pointer
    "RtlpScpCfgNtdllExports": 8,
    # the CRT float flag: one DWORD per the compiler contract
    "_fltused": 4,
}


def fail(message):
    raise SystemExit(message)


def parse_exports(data):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[0:2] != b"MZ" or e_lfanew + 24 > len(data):
        fail("not a PE file")
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        fail("not a PE file")
    machine, num_sections = struct.unpack_from("<HH", data, e_lfanew + 4)
    if machine != 0x8664:
        fail("x64 images only")
    magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
    if magic != 0x20B:
        fail("PE32+ images only")
    opt = e_lfanew + 24
    exp_rva, exp_size = struct.unpack_from("<II", data, opt + 112)
    if exp_rva == 0 or exp_size == 0:
        fail("image exports nothing")
    sec_table = opt + 0xF0

    sections = []
    for i in range(num_sections):
        off = sec_table + i * 40
        vsize, rva, rsize, roff = struct.unpack_from("<IIII", data, off + 8)
        sections.append((rva, max(vsize, rsize), roff))

    def rva2off(rva):
        for vrva, span, roff in sections:
            if vrva <= rva < vrva + span:
                return rva - vrva + roff
        return None

    eo = rva2off(exp_rva)
    if eo is None:
        fail("export directory not in a section")
    export_base = struct.unpack_from("<I", data, eo + 0x10)[0]
    nfuncs = struct.unpack_from("<I", data, eo + 0x14)[0]
    nnames = struct.unpack_from("<I", data, eo + 0x18)[0]
    addr_rva, names_rva, ords_rva = struct.unpack_from("<III", data, eo + 0x1C)
    addr_off, names_off, ords_off = rva2off(addr_rva), rva2off(names_rva), rva2off(ords_rva)
    if None in (addr_off, names_off, ords_off):
        fail("export arrays not in a section")

    eat = []
    for i in range(nfuncs):
        eat.append(struct.unpack_from("<I", data, addr_off + 4 * i)[0])

    # EAT index -> first exported name; slots absent here are unnamed
    names = {}
    for i in range(nnames):
        name_rva = struct.unpack_from("<I", data, names_off + 4 * i)[0]
        name_off = rva2off(name_rva)
        if name_off is None:
            continue
        end = data.index(b"\0", name_off)
        name = data[name_off:end].decode("ascii", errors="replace")
        ordinal_index = struct.unpack_from("<H", data, ords_off + 2 * i)[0]
        if ordinal_index < nfuncs:
            names.setdefault(ordinal_index, name)

    # Executable bounds: every execute-characteristic section (ntdll carries
    # AddressOfEntryPoint 0 — it is system-mapped, not run from a file — and
    # its code lives in more than one section: .text plus the fothk thunk
    # pages the CFG machinery exports through)
    exec_spans = []
    for i in range(num_sections):
        off = sec_table + i * 40
        characteristics = struct.unpack_from("<I", data, off + 36)[0]
        if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            vsize, rva = struct.unpack_from("<II", data, off + 8)
            exec_spans.append((rva, max(vsize, 1)))
    if not exec_spans:
        fail("no executable section - cannot bound the code range")

    def in_code(rva):
        return any(start <= rva < start + span for start, span in exec_spans)

    rows = []
    for index in range(nfuncs):
        func_rva = eat[index]
        if func_rva == 0:
            continue  # EAT hole: the derive preserves it ruleless
        if exp_rva <= func_rva < exp_rva + exp_size:
            continue  # forwarder: the derive preserves it ruleless
        name = names.get(index, "")
        label = name if name else "<ordinal %d>" % (export_base + index)
        if not in_code(func_rva):
            if name in REVIEWED_DATA_EXPORTS:
                size = REVIEWED_DATA_EXPORTS[name]
                rows.append({"name": name, "ordinal": export_base + index,
                             "kind": "data",
                             "layout": {"size": size, "align": 8, "bytes": "00" * size}})
                continue
            fail("export %s points outside the executable sections - classify "
                 "manually (add it to REVIEWED_DATA_EXPORTS with its "
                 "system-contract bound)" % label)
        foff = rva2off(func_rva)
        if foff is None:
            fail("export %s body not file-backed" % label)
        body = data[foff:foff + STUB_LEN]
        row = {"name": name, "ordinal": export_base + index}
        if len(body) >= 8 and body[:4] == X64_STUB_PREFIX:
            row["kind"] = "syscallstub"
        else:
            row["kind"] = "trap"
        rows.append(row)
    return rows


def main():
    if len(sys.argv) != 3:
        print("usage: gen_boundary_manifest.py <real ntdll.dll> <out.json>")
        return 1
    source = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    data = source.read_bytes()

    xxh = None
    try:
        import xxhash
        xxh = xxhash.xxh64
    except ImportError:
        fail("python xxhash module required (pip install xxhash) — the anchor "
             "must match the engine's XXH64 exactly")

    rows = parse_exports(data)
    anchor = xxh(data).intdigest()

    manifest = {
        "schema": 1,
        "module": "ntdll.dll",
        "arch": "x64",
        "images": [
            {"xxhash64": hex(anchor),
             "note": "real Windows build from %s" % source}
        ],
        "exports": rows,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print("wrote %s (%d exports, anchor %s)" % (out_path, len(rows), hex(anchor)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
