#!/usr/bin/env python3
"""Dump the build's same-source API Set schema as JSON (dev-time evidence tool).

The API Set schema authority for a Windows build ships in
%SystemRoot%\\System32\\apisetschema.dll: a resource PE whose `.apiset`
section carries the namespace (version-6 header, UTF-16 contract names, and
per-contract host lists including importer-specific branches - the context
the apiset evidence tool must preserve). Neither ntdll (no AMSO image, no
schema section) nor apisetmap.sys - which does not exist on either supported
build - carries it.

Zero dependencies, standard library only, works offline against copied
files. Run it against the build the map source describes:

    python dump_apiset_schema.py <System32 ntdll.dll> <apisetschema.dll> \
        apiset-schema.win26300.json

The first argument is that build's ntdll: its whole-file xxhash64 is
computed with a built-in implementation (no xxhash module needed) so the
output carries the same anchor spelling the map sources use. The JSON shape:

    {"schema": 1, "kind": "apiset-schema", "arch": "x64",
     "anchor": {"xxhash64": "0x...", "note": "..."},
     "contracts": {"<contract>": [{"importer": "", "host": "ntdll.dll"},
                                  {"importer": "kernelbase.dll", ...}]}}
"""

import json
import struct
import sys

# xxhash64 built in (the engine anchors maps to XXH64 whole-file values)
P1 = 11400714785074694791
P2 = 14029467366897019727
P3 = 1609587929392839161
P4 = 9650029242287828579
P5 = 2870177450012600261
M = (1 << 64) - 1


def _rotl(x, r):
    return ((x << r) | (x >> (64 - r))) & M


def _round(acc, val):
    return (_rotl((acc + val * P2) & M, 31) * P1) & M


def _merge(acc, val):
    return ((acc ^ _round(0, val)) * P1 + P4) & M


def xxh64(data, seed=0):
    n = len(data)
    if n >= 32:
        v1 = (seed + P1 + P2) & M
        v2 = (seed + P2) & M
        v3 = seed & M
        v4 = (seed - P1) & M
        i = 0
        while i + 32 <= n:
            v1 = _round(v1, struct.unpack_from("<Q", data, i)[0])
            v2 = _round(v2, struct.unpack_from("<Q", data, i + 8)[0])
            v3 = _round(v3, struct.unpack_from("<Q", data, i + 16)[0])
            v4 = _round(v4, struct.unpack_from("<Q", data, i + 24)[0])
            i += 32
        h = (_rotl(v1, 1) + _rotl(v2, 7) + _rotl(v3, 12) + _rotl(v4, 18)) & M
        h = _merge(h, v1)
        h = _merge(h, v2)
        h = _merge(h, v3)
        h = _merge(h, v4)
    else:
        h = (seed + P5) & M
        i = 0
    h = (h + n) & M
    while i + 8 <= n:
        h = (_rotl(h ^ _round(0, struct.unpack_from("<Q", data, i)[0]), 27) * P1 + P4) & M
        i += 8
    if i + 4 <= n:
        h = (_rotl(h ^ (struct.unpack_from("<I", data, i)[0] * P1 & M), 23) * P2 + P3) & M
        i += 4
    while i < n:
        h = (_rotl(h ^ (data[i] * P5 & M), 11) * P1) & M
        i += 1
    h ^= h >> 33
    h = (h * P2) & M
    h ^= h >> 29
    h = (h * P3) & M
    h ^= h >> 32
    return h


def fail(message):
    raise SystemExit(message)


def read_apiset_section(path):
    """Locates and returns the container's .apiset section bytes."""
    data = open(path, "rb").read()
    if data[:2] != b"MZ":
        fail("%s is not a PE image" % path)
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        fail("%s is not a PE image" % path)
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    optsz = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec_table = e_lfanew + 24 + optsz
    for i in range(num_sections):
        off = sec_table + i * 40
        name = data[off:off + 8].rstrip(b"\x00")
        rsize, ptr = struct.unpack_from("<II", data, off + 16)
        if name == b".apiset":
            return data[ptr:ptr + rsize]
    fail("%s carries no .apiset section" % path)


def decode_u16(blob, off, nbytes):
    if off < 0 or nbytes < 0 or nbytes % 2 or off + nbytes > len(blob):
        return None
    try:
        return blob[off:off + nbytes].decode("utf-16-le")
    except UnicodeDecodeError:
        return None


def looks_like_contract(name):
    return bool(name) and (name.startswith("api-ms-") or name.startswith("ext-ms-"))


def looks_like_host(name):
    if not name:
        return False
    low = name.lower()
    if low.endswith((".dll", ".sys", ".exe", ".drv")):
        return True
    # some schema forms append a stray 't' after the module spelling
    return looks_like_host(low[:-1]) if low.endswith("t") else False


def parse_layout(blob, entries_base, count, host_swap):
    """Parses entries under one host-field-order hypothesis; returns
    (contracts, hostless, broken). Entries whose host rows carry no value
    have no host binding on this build (deprecated/removed contract forms)
    and are counted hostless, not broken."""
    contracts = {}
    hostless = 0
    broken = 0
    for i in range(count):
        fields = struct.unpack_from("<6I", blob, entries_base + 24 * i)
        noff, nlen, hoff, hcount = fields[1], fields[2], fields[4], fields[5]
        name = decode_u16(blob, noff, nlen)
        if not looks_like_contract(name):
            broken += 1
            continue
        hosts = []
        bad = False
        empty = True
        for h in range(hcount):
            row = struct.unpack_from("<5I", blob, hoff + 20 * h)
            # host row: flags, importer offset/length, host offset/length;
            # some builds carry the mirrored length/offset spelling
            if host_swap:
                ioff, ilen, vlen, voff = row[1], row[2], row[3], row[4]
            else:
                ioff, ilen, voff, vlen = row[1], row[2], row[3], row[4]
            if any(row):
                empty = False
            if not ilen and not vlen:
                continue  # placeholder row: carries no host on this build
            importer = decode_u16(blob, ioff, ilen) if ilen else ""
            value = decode_u16(blob, voff, vlen) if vlen else None
            if value and value.endswith(".dllt") and not looks_like_host(value):
                value = value[:-1]
            if importer is None or value is None or not looks_like_host(value):
                bad = True
                break
            hosts.append({"importer": importer.lower(), "host": value.lower()})
        if bad:
            broken += 1
            continue
        if empty or not hosts:
            hostless += 1
            continue
        contracts[name.lower()] = hosts
    return contracts, hostless, broken


def main():
    if len(sys.argv) != 4:
        print("usage: dump_apiset_schema.py <System32 ntdll.dll> "
              "<apisetschema.dll> <out.json>")
        return 1
    ntdll_path, container_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        ntdll = open(ntdll_path, "rb").read()
    except OSError as exc:
        fail("cannot read %s: %s" % (ntdll_path, exc))
    if ntdll[:2] != b"MZ":
        fail("%s is not a PE image" % ntdll_path)

    blob = read_apiset_section(container_path)
    version, total_size = struct.unpack_from("<II", blob, 0)
    count = struct.unpack_from("<I", blob, 12)[0]
    entries_base = struct.unpack_from("<I", blob, 0x10)[0]
    if version != 6:
        fail("unexpected .apiset namespace version %d (parser knows v6)" % version)
    if total_size > len(blob):
        fail("namespace size %d exceeds the .apiset section %d"
             % (total_size, len(blob)))
    if not 0x14 <= entries_base < len(blob) or not 0 < count <= 100000:
        fail("implausible .apiset header: count=%d entries base=0x%x"
             % (count, entries_base))

    # two known host-row layouts; the validating one wins
    contracts, hostless, broken = parse_layout(blob, entries_base, count, host_swap=False)
    alt, hostless_alt, broken_alt = parse_layout(blob, entries_base, count, host_swap=True)
    if broken_alt < broken:
        contracts, hostless, broken = alt, hostless_alt, broken_alt
    if broken:
        fail("schema parse incomplete: %d/%d entries failed validation "
             "(layout differs on this build)" % (broken, count))
    if not contracts:
        fail("no contracts parsed")

    doc = {
        "schema": 1,
        "kind": "apiset-schema",
        "arch": "x64",
        "anchor": {
            "xxhash64": hex(xxh64(ntdll)),
            "note": ("API Set schema parsed from this build's apisetschema.dll "
                     ".apiset section (namespace version %d, %d contracts with "
                     "hosts, %d hostless); same-source host authority for the "
                     "apiset evidence tool" % (version, len(contracts), hostless)),
        },
        "contracts": dict(sorted(contracts.items())),
    }
    with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(doc, handle, indent=1)
        handle.write("\n")
    print("wrote %s (%d contracts with hosts, %d hostless, namespace version %d, anchor %s)"
          % (out_path, len(contracts), hostless, version, doc["anchor"]["xxhash64"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
