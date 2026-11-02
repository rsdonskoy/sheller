#!/usr/bin/env python3
"""Generate the directory-delivered API Set map (design D5, change
real-dll-module-dir).

Reads a reviewed text source (JSON) and emits the versioned binary
apiset-map.bin the user's system-module directory carries alongside its raw
ntdll. The engine never parses the text source: it loads the binary through
the bounded reader (src/loader/apiset_map.h), which rejects a map whose
architecture or anchor ntdll hash differs from the world.

Deterministic: entries sorted by (contract, importer), exact duplicates
deduplicated, conflicting hosts rejected, stable binary layout - the same
JSON in, byte-identical .bin out.

Regenerate (anchor = whole-file xxhash64 of the directory's raw ntdll):
    python tools/gen_apiset_map.py tools/apisetmap/ntdll.x64.json apiset-map.bin
"""

import json
import struct
import sys
from pathlib import Path

SCHEMA = 1
ARCH_BYTES = {"x64": 1, "x86": 2}
MAGIC = b"APSMMAP1"
VERSION = 1
MAX_ENTRIES = 65536


def fail(message):
    raise SystemExit(message)


def parse_u64(text):
    try:
        value = int(text, 0)
    except (TypeError, ValueError):
        fail("bad anchor xxhash64 %r" % (text,))
    if not 0 <= value < (1 << 64):
        fail("anchor xxhash64 %r out of u64 range" % (text,))
    return value


def main():
    if len(sys.argv) != 3:
        print("usage: gen_apiset_map.py <source.json> <out.bin>")
        return 1
    source = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    manifest = json.loads(source.read_text(encoding="utf-8"))
    if manifest.get("schema") != SCHEMA:
        fail("schema must be %d" % SCHEMA)
    arch = manifest.get("arch")
    if arch not in ARCH_BYTES:
        fail("arch must be one of %s" % sorted(ARCH_BYTES))
    anchor = parse_u64(manifest.get("anchor", {}).get("xxhash64"))

    entries = {}
    for entry in manifest.get("entries", []):
        contract = str(entry.get("contract", ""))
        importer = str(entry.get("importer", ""))
        host = str(entry.get("host", ""))
        if not contract or contract != contract.lower():
            fail("contract must be a folded, extension-less name: %r" % contract)
        if importer and importer != importer.lower():
            fail("importer must be folded: %r" % importer)
        if not host or host != host.lower():
            fail("host must be a folded name with extension: %r" % host)
        key = (contract, importer)
        if key in entries and entries[key] != host:
            fail("conflicting hosts for (%r, %r): %r vs %r"
                 % (contract, importer, entries[key], host))
        entries[key] = host
    if not entries:
        fail("the entries list is empty")
    if len(entries) > MAX_ENTRIES:
        fail("%d entries exceed the reader bound %d" % (len(entries), MAX_ENTRIES))

    # deterministic layout: sorted entries, pool strings in first-use order
    ordered = sorted(entries.items())
    pool = bytearray()

    def pool_offset(text):
        data = text.encode("ascii")
        offset = len(pool)
        pool.extend(data)
        return offset, len(data)

    rows = bytearray()
    for (contract, importer), host in ordered:
        c_off, c_len = pool_offset(contract)
        i_off, i_len = pool_offset(importer)
        h_off, h_len = pool_offset(host)
        rows += struct.pack("<6I", c_off, c_len, i_off, i_len, h_off, h_len)

    entry_bytes = len(rows)
    header = struct.pack("<8sIBxxxQIIII", MAGIC, VERSION, ARCH_BYTES[arch], anchor,
                         len(ordered), len(pool), entry_bytes, 40 + entry_bytes)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(header + bytes(rows) + bytes(pool))
    print("wrote %s (%d entries, pool %d bytes, anchor 0x%016x)"
          % (out_path, len(ordered), len(pool), anchor))
    return 0


if __name__ == "__main__":
    sys.exit(main())
