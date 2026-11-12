#!/usr/bin/env python3
"""Generate an API Set map source with its per-contract evidence report.

The committed tools/apisetmap/*.json are reviewed offline sources: this tool
derives them from a real build's system directory and states exactly what the
derivation proves. Host candidates come from EAT membership evidence against
the observed import closure; hosts are confirmed by the build's same-source
API Set schema (tools/apisetmap/dump_apiset_schema.py output) or by an
explicitly recorded review adjudication - a unique candidate alone is not a
confirmed host.

Evidence rules (these are the point of the tool, not incidental details):
  - a host's coverage set is its own export-directory names/ordinals. A
    forwarder SLOT name counts (importing it resolves through the loader's
    forwarding); a forwarder TARGET name does not (it is not a queryable
    export of that host: kernelbase!Foo forwarding ntdll!Bar proves
    kernelbase can export Foo, and importing Bar from kernelbase fails)
  - forwarder slots are reachability-checked through the complete named
    chain: every target must exist in the scanned set, with no cycles
  - observed functions are collected per (contract, importer) and never
    merged across importers; candidates are the hosts covering a contract's
    observed subset, and the kernelbase-first ordering only ranks review, it
    never disambiguates
  - zero candidates fail named; unique candidates still need confirmation;
    multiple candidates are named ambiguity. Until every contract is
    confirmed the tool writes the evidence report only - the reviewed map
    source is withheld, because construction passing is a smoke signal, not
    proof of mapping correctness

Usage:
    python tools/gen_apiset_evidence_map.py <system-dir> <ntdll-anchor> \
        --evidence tools/apisetmap/ntdll.x64.win26300.evidence.json \
        --map tools/apisetmap/ntdll.x64.win26300.json \
        [--schema tools/apisetmap/apiset-schema.win26300.json] \
        [--resolve tools/apisetmap/ntdll.x64.win26300.resolve.json] \
        [--extra-pe tests/packed.exe.unp]

<system-dir> must carry ntdll.dll, kernel32.dll, kernelbase.dll and
ucrtbase.dll (hosts and importers). <ntdll-anchor> is the whole-file xxhash64
spelling of that directory's ntdll and is cross-checked against the file.
--extra-pe images join the observed import closure (corpus samples the map
must serve); they are scanned for imports only, never treated as hosts.
"""

import argparse
import json
import struct
import sys
from pathlib import Path

HOST_MODULES = ("kernel32.dll", "kernelbase.dll", "ucrtbase.dll", "ntdll.dll")
IMPORTER_MODULES = ("kernel32.dll", "kernelbase.dll", "ucrtbase.dll")
CONFIRMED = ("confirmed-schema", "confirmed-review")


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


# xxhash64 built in (same spelling as tools/apisetmap/dump_apiset_schema.py;
# keeps this tool standard-library only)
_P1 = 11400714785074694791
_P2 = 14029467366897019727
_P3 = 1609587929392839161
_P4 = 9650029242287828579
_P5 = 2870177450012600261
_M = (1 << 64) - 1


def xxh64(data, seed=0):
    def rotl(x, r):
        return ((x << r) | (x >> (64 - r))) & _M

    def rnd(acc, val):
        return (rotl((acc + val * _P2) & _M, 31) * _P1) & _M

    def mrg(acc, val):
        return ((acc ^ rnd(0, val)) * _P1 + _P4) & _M

    n = len(data)
    if n >= 32:
        v1 = (seed + _P1 + _P2) & _M
        v2 = (seed + _P2) & _M
        v3 = seed & _M
        v4 = (seed - _P1) & _M
        i = 0
        while i + 32 <= n:
            v1 = rnd(v1, struct.unpack_from("<Q", data, i)[0])
            v2 = rnd(v2, struct.unpack_from("<Q", data, i + 8)[0])
            v3 = rnd(v3, struct.unpack_from("<Q", data, i + 16)[0])
            v4 = rnd(v4, struct.unpack_from("<Q", data, i + 24)[0])
            i += 32
        h = (rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18)) & _M
        h = mrg(h, v1)
        h = mrg(h, v2)
        h = mrg(h, v3)
        h = mrg(h, v4)
    else:
        h = (seed + _P5) & _M
        i = 0
    h = (h + n) & _M
    while i + 8 <= n:
        h = (rotl(h ^ rnd(0, struct.unpack_from("<Q", data, i)[0]), 27) * _P1 + _P4) & _M
        i += 8
    if i + 4 <= n:
        h = (rotl(h ^ (struct.unpack_from("<I", data, i)[0] * _P1 & _M), 23) * _P2 + _P3) & _M
        i += 4
    while i < n:
        h = (rotl(h ^ (data[i] * _P5 & _M), 11) * _P1) & _M
        i += 1
    h ^= h >> 33
    h = (h * _P2) & _M
    h ^= h >> 29
    h = (h * _P3) & _M
    h ^= h >> 32
    return h


class Image:
    """One parsed PE: export coverage set, forwarder slots, contract imports."""

    def __init__(self, path):
        self.path = path
        self.name = path.name.lower()
        self.data = path.read_bytes()
        self.hash = xxh64(self.data)
        self._parse_headers()
        self.export_names = set()      # every exported name (slots included)
        self.export_ordinals = set()   # exported ordinal numbers
        self.forwarders = {}           # slot name -> "module.function" target
        self.thunk_targets = {}        # slot name -> "module.function" (jmp [rip] IAT thunk)
        self.contract_imports = {}     # contract -> set of function names
        self.ordinal_import_skips = 0
        self._thunk_slot_rvas = {}     # slot name -> IAT slot RVA the thunk jumps through
        self._iat_slot_map = {}        # first-thunk slot RVA -> (dll, import name)
        if self.export_rva:
            self._parse_exports()
        self._parse_imports()
        self._parse_delay_imports()
        self._resolve_thunks()

    def _parse_headers(self):
        data = self.data
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[:2] != b"MZ" or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            fail("%s is not a PE image" % self.path.name)
        machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
        if machine != 0x8664:
            fail("%s is not an x64 image" % self.path.name)
        magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
        if magic != 0x20B:
            fail("%s is not a PE32+ image" % self.path.name)
        opt = e_lfanew + 24
        num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        sec_table = opt + 0xF0
        self.sections = []
        for i in range(num_sections):
            off = sec_table + i * 40
            vsize, rva, rsize, roff = struct.unpack_from("<IIII", data, off + 8)
            characteristics = struct.unpack_from("<I", data, off + 36)[0]
            self.sections.append((rva, max(vsize, rsize), roff,
                                  bool(characteristics & 0x20000000)))

        def rva2off(rva):
            for vrva, span, roff, _exec in self.sections:
                if vrva <= rva < vrva + span:
                    return roff + (rva - vrva)
            return None
        self.rva2off = rva2off

        def in_exec(rva):
            return any(vrva <= rva < vrva + span and is_exec
                       for vrva, span, _roff, is_exec in self.sections)
        self.in_exec = in_exec
        self.import_rva = struct.unpack_from("<I", data, opt + 112 + 8)[0]
        self.delay_rva = struct.unpack_from("<I", data, opt + 112 + 13 * 8)[0]
        self.export_rva = struct.unpack_from("<I", data, opt + 112)[0]
        self.export_size = struct.unpack_from("<I", data, opt + 116)[0]

    def _parse_exports(self):
        data = self.data
        eo = self.rva2off(self.export_rva)
        if eo is None:
            fail("%s export directory not file-backed" % self.path.name)
        export_base = struct.unpack_from("<I", data, eo + 0x10)[0]
        nfuncs = struct.unpack_from("<I", data, eo + 0x14)[0]
        nnames = struct.unpack_from("<I", data, eo + 0x18)[0]
        addr_rva, names_rva, ords_rva = struct.unpack_from("<III", data, eo + 0x1C)
        addr_off, names_off, ords_off = (self.rva2off(addr_rva),
                                         self.rva2off(names_rva),
                                         self.rva2off(ords_rva))
        if None in (addr_off, names_off, ords_off):
            fail("%s export arrays not file-backed" % self.path.name)

        slot_names = {}  # EAT index -> first exported name
        for i in range(nnames):
            name_off = self.rva2off(struct.unpack_from("<I", data, names_off + 4 * i)[0])
            if name_off is None:
                continue
            end = data.index(b"\0", name_off)
            name = data[name_off:end].decode("ascii", errors="replace").lower()
            ordinal_index = struct.unpack_from("<H", data, ords_off + 2 * i)[0]
            if ordinal_index < nfuncs:
                slot_names.setdefault(ordinal_index, name)

        for index in range(nfuncs):
            func_rva = struct.unpack_from("<I", data, addr_off + 4 * index)[0]
            self.export_ordinals.add(export_base + index)
            if func_rva == 0:
                continue
            name = slot_names.get(index, "")
            if name:
                self.export_names.add(name)
            # forwarder: the RVA lands inside the export directory itself
            if self.export_rva <= func_rva < self.export_rva + self.export_size:
                fo = self.rva2off(func_rva)
                if fo is None or not name:
                    fail("%s forwarder slot %r not file-backed or unnamed"
                         % (self.path.name, name or export_base + index))
                end = data.index(b"\0", fo)
                target = data[fo:end].decode("ascii", errors="replace").lower()
                self.forwarders[name] = target
            elif name and self.in_exec(func_rva):
                # jmp [rip+disp32] thunk (ff 25): a real code slot whose body
                # is a single indirect jump through this image's own IAT -
                # recent builds redirect kernel32 exports to kernelbase this
                # way instead of string forwarders. Resolve where it jumps.
                fo = self.rva2off(func_rva)
                if fo is not None:
                    # jmp [rip+disp32] spells as ff 25 or, REX.W-prefixed,
                    # 48 ff 25
                    if data[fo:fo + 2] == b"\xff\x25":
                        disp = struct.unpack_from("<i", data, fo + 2)[0]
                        self._thunk_slot_rvas[name] = func_rva + 6 + disp
                    elif data[fo:fo + 3] == b"\x48\xff\x25":
                        disp = struct.unpack_from("<i", data, fo + 3)[0]
                        self._thunk_slot_rvas[name] = func_rva + 7 + disp

    def _resolve_thunks(self):
        """Records each thunk slot's raw IAT binding "(dll, function)" - the
        dll may be a plain module or an api-set contract the image imports;
        main() finalizes contract hops once contracts are resolved."""
        for slot, iat_rva in self._thunk_slot_rvas.items():
            hit = self._iat_slot_map.get(iat_rva)
            if hit:
                self.thunk_targets[slot] = hit

    def _record_iat_slots(self, dll, int_rva, iat_rva):
        """Records which import name every FirstThunk slot of one descriptor
        binds. File-time slots hold hint/name RVAs (the INT spelling; the
        FirstThunk mirrors it before the loader binds)."""
        data = self.data
        src_rva = int_rva or iat_rva
        if not src_rva or not iat_rva:
            return
        soff = self.rva2off(src_rva)
        if soff is None:
            return
        j = 0
        while True:
            value = struct.unpack_from("<Q", data, soff + j * 8)[0]
            if value == 0:
                break
            if not (value >> 63) & 1:
                foff = self.rva2off(value & 0x7FFFFFFF)
                if foff is not None:
                    fname = data[foff + 2:data.index(b"\0", foff + 2)].decode(
                        "ascii", errors="replace").lower()
                    if fname:
                        self._iat_slot_map[iat_rva + 8 * j] = (dll, fname)
            j += 1

    def _parse_delay_imports(self):
        """Delay-load descriptors (kernel32 binds kernelbase this way):
        ImgDelayDescr is eight DWORD fields, all RVAs - grAttrs, szName,
        phmod, pIAT, pINT, pBoundIAT, pUnloadIAT, dwTimeStamp."""
        if not self.delay_rva:
            return
        data = self.data
        off = self.rva2off(self.delay_rva)
        if off is None:
            return
        while True:
            fields = struct.unpack_from("<8I", data, off)
            name_rva, iat_rva, int_rva = fields[1], fields[3], fields[4]
            if name_rva == 0:
                break
            name_off = self.rva2off(name_rva)
            if name_off is None:
                break
            dll = data[name_off:data.index(b"\0", name_off)].decode(
                "ascii", errors="replace").lower()
            self._record_iat_slots(dll, int_rva, iat_rva)
            off += 32

    def _parse_imports(self):
        if not self.import_rva:
            return
        data = self.data
        off = self.rva2off(self.import_rva)
        if off is None:
            fail("%s import directory not file-backed" % self.path.name)
        while True:
            oft, _ts, _fw, nm, ft = struct.unpack_from("<IIIII", data, off)
            if nm == 0:
                break
            name_off = self.rva2off(nm)
            dll = data[name_off:data.index(b"\0", name_off)].decode(
                "ascii", errors="replace").lower()
            base = dll[:-4] if dll.endswith(".dll") else dll
            arr_rva = oft if oft else ft
            arr = self.rva2off(arr_rva)
            if arr is None:
                fail("%s import thunk array not file-backed" % self.path.name)
            # names live in the INT (oft) when present, but the thunks jump
            # through the FirstThunk (ft) slots - keys must be ft addresses
            self._record_iat_slots(dll, oft, ft)
            if base.startswith("api-ms-") or base.startswith("ext-ms-"):
                functions = self.contract_imports.setdefault(base, set())
                j = 0
                while True:
                    value = struct.unpack_from("<Q", data, arr + j * 8)[0]
                    if value == 0:
                        break
                    if (value >> 63) & 1:
                        self.ordinal_import_skips += 1
                    else:
                        foff = self.rva2off(value & 0x7FFFFFFF)
                        fname = data[foff + 2:data.index(b"\0", foff + 2)].decode(
                            "ascii", errors="replace").lower()
                        functions.add(fname)
                    j += 1
            off += 20
        self.contract_imports = {c: f for c, f in self.contract_imports.items() if f}


def forward_target_status(target, images_by_name):
    """Walks the entire named forwarder chain; a slot alone is not a body."""
    seen = set()
    while True:
        module, separator, function = target.rpartition(".")
        if not separator:
            return "name-not-found"
        module = module if module.endswith(".dll") else module + ".dll"
        key = (module, function)
        if key in seen:
            return "forward-cycle"
        seen.add(key)
        image = images_by_name.get(module)
        if image is None:
            return "module-not-scanned"
        if function not in image.export_names:
            return "name-not-found"
        target = image.forwarders.get(function)
        if target is None:
            return "reachable"


def load_images(system_dir, extra_pes):
    images = {}
    for name in HOST_MODULES:
        path = system_dir / name
        if not path.exists():
            fail("system directory %s lacks %s" % (system_dir, name))
        images[name] = Image(path)
    extra = []
    for spec in extra_pes:
        path = Path(spec)
        if not path.exists():
            fail("extra PE %s does not exist" % spec)
        extra.append(Image(path))
    return images, extra


def main():
    parser = argparse.ArgumentParser(
        description="Derive an API Set map source with its evidence report")
    parser.add_argument("system_dir")
    parser.add_argument("anchor", help="whole-file xxhash64 of <system-dir>'s ntdll")
    parser.add_argument("--evidence", required=True, help="evidence report output")
    parser.add_argument("--map", help="reviewed map source output (withheld "
                                      "until every contract is confirmed)")
    parser.add_argument("--schema", help="same-source API Set schema hosts JSON "
                                         "(from dump_apiset_schema.py)")
    parser.add_argument("--resolve", help="review adjudications JSON: "
                                          "{contract: {host, basis}}")
    parser.add_argument("--extra-pe", action="append", default=[],
                        help="extra image whose import closure joins the "
                             "observations (repeatable)")
    args = parser.parse_args()

    system_dir = Path(args.system_dir)
    anchor_arg = parse_u64(args.anchor)
    images, extra = load_images(system_dir, args.extra_pe)

    ntdll_hash = images["ntdll.dll"].hash
    if ntdll_hash != anchor_arg:
        fail("anchor mismatch: %s is %s, argument says 0x%016x"
             % (images["ntdll.dll"].path, hex(ntdll_hash), anchor_arg))
    images_by_name = {img.name: img for img in images.values()}

    schema_contracts = {}
    if args.schema:
        schema = json.loads(Path(args.schema).read_text(encoding="utf-8"))
        if schema.get("kind") != "apiset-schema" or schema.get("schema") != 1:
            fail("%s is not an apiset-schema JSON" % args.schema)
        schema_anchor = schema.get("anchor", {}).get("xxhash64")
        if schema_anchor and parse_u64(schema_anchor) != anchor_arg:
            fail("schema anchor %s does not match the world ntdll 0x%016x"
                 % (schema_anchor, anchor_arg))
        schema_contracts = schema.get("contracts", {})
    resolve = {}
    if args.resolve:
        resolve = json.loads(Path(args.resolve).read_text(encoding="utf-8"))

    # ---- observations: per (contract, importer), never merged silently ----
    observations = {}
    importers = [(name, images[name]) for name in IMPORTER_MODULES]
    importers += [(img.name, img) for img in extra]
    for importer, img in importers:
        for contract, functions in sorted(img.contract_imports.items()):
            observations.setdefault(contract, {}).setdefault(importer, set()).update(functions)

    def fn_status(fn, host_img):
        if fn in host_img.export_names:
            if fn in host_img.forwarders:
                return "forward"
            if fn in host_img.thunk_targets:
                return "jmp-thunk"
            return "body"
        return "absent"

    forward_status = {}  # host -> slot name -> {"target", "status"}
    for host in HOST_MODULES:
        for slot, target in sorted(images[host].forwarders.items()):
            forward_status.setdefault(host, {})[slot] = {
                "target": target,
                "status": forward_target_status(target, images_by_name),
            }
    contracts_out = {}
    entries = {}
    unresolved = []

    def unusable_functions(host, functions):
        # Confirmation establishes host identity, never bypasses reachability.
        return [fn for fn in functions
                if fn_status(fn, images[host]) == "absent"
                or (fn in forward_status.get(host, {})
                    and forward_status[host][fn]["status"] != "reachable")]

    for contract in sorted(observations):
        observed = {imp: sorted(fns) for imp, fns in sorted(observations[contract].items())}
        union = sorted({fn for fns in observations[contract].values() for fn in fns})
        coverage = {}
        candidates = []
        reachable_candidates = []
        unreachable_forwards = []
        for host in HOST_MODULES:
            statuses = {fn: fn_status(fn, images[host]) for fn in union}
            coverage[host] = statuses
            if all(status != "absent" for status in statuses.values()):
                candidates.append(host)
                bad_slots = []
                for fn, status in statuses.items():
                    if status == "forward":
                        info = forward_status[host][fn]
                        if info["status"] != "reachable":
                            bad_slots.append("%s!%s -> %s (%s)" % (
                                host, fn, info["target"], info["status"]))
                if bad_slots:
                    unreachable_forwards.extend(bad_slots)
                else:
                    reachable_candidates.append(host)

        status = "unresolved"
        host = ""
        basis = ""
        importer_hosts = {}

        schema_hosts = schema_contracts.get(contract)
        if schema_hosts:
            # same-source schema: host authority. An entry with an importer
            # name scopes to that importer; the empty importer is the default
            # for every importer the branches do not name.
            branches = {b["importer"]: b["host"] for b in schema_hosts}
            default_host = branches.get("", "")
            conflicts = []
            choices = {}
            for imp in sorted(observed):
                branch_host = branches.get(imp, default_host)
                if not branch_host:
                    conflicts.append("schema carries no host for importer %s" % imp)
                    continue
                if branch_host not in HOST_MODULES:
                    conflicts.append("schema host %s outside the scanned set" % branch_host)
                    continue
                missing = unusable_functions(branch_host, observations[contract][imp])
                if missing:
                    conflicts.append("schema host %s has absent/unreachable exports for %s: %s"
                                     % (branch_host, imp, sorted(missing)[:4]))
                else:
                    choices[imp] = branch_host
            if conflicts:
                status = "schema-conflict"
                basis = "; ".join(conflicts[:4])
            else:
                # Preserve the authoritative default and every exception,
                # including branches outside the observed importer subset.
                if set(branches) == {""}:
                    status = "confirmed-schema"
                    host = default_host
                    basis = ("same-build API Set schema lists %s for %d "
                             "importer(s)" % (default_host, len(choices)))
                else:
                    status = "confirmed-schema"
                    basis = ("same-build API Set schema lists importer-specific "
                             "hosts: %s" % "; ".join(
                                 "%s->%s" % (imp, h) for imp, h in sorted(branches.items())))
                    importer_hosts = dict(branches)

        override = resolve.get(contract) if not status.startswith("confirmed") else None
        if override is not None:
            override_host = str(override.get("host", "")).lower()
            override_basis = str(override.get("basis", ""))
            if not override_host or not override_basis:
                fail("review adjudication for %s needs host and basis" % contract)
            if override_host not in HOST_MODULES:
                fail("review adjudication for %s names host %s outside the "
                     "scanned set" % (contract, override_host))
            missing = unusable_functions(override_host, union)
            if missing:
                fail("review adjudication for %s claims %s but the host lacks reachable exports "
                     "%s" % (contract, override_host, sorted(missing)[:4]))
            status = "confirmed-review"
            basis = "review: %s" % override_basis
            host = override_host

        if status not in CONFIRMED:
            if status == "unresolved":
                if not reachable_candidates:
                    status = "zero-candidate"
                    basis = ("no scanned host covers the observed functions "
                             "through reachable slots")
                elif len(reachable_candidates) == 1:
                    status = "unique-candidate-unconfirmed"
                    host = reachable_candidates[0]
                    basis = ("unique candidate from EAT evidence; needs "
                             "same-source schema or explicit review")
                elif len(reachable_candidates) > 1:
                    status = "ambiguous"
                    basis = ("multiple covering hosts: %s"
                             % ", ".join(reachable_candidates))
            unresolved.append((contract, status))

        contract_out = {
            "observed": observed,
            "candidates": candidates,
            "reachable_candidates": reachable_candidates,
            "coverage": coverage,
            "resolution": {"status": status, "host": host, "basis": basis},
        }
        if importer_hosts:
            contract_out["importer_hosts"] = importer_hosts
        if unreachable_forwards:
            contract_out["unreachable_forwards"] = unreachable_forwards
        contracts_out[contract] = contract_out

        if status in CONFIRMED:
            if importer_hosts:
                entries[contract] = importer_hosts
            else:
                entries[contract] = host

    # finalize thunk display targets: a raw hit naming a plain module is
    # final; one naming an api-set contract hops through that contract's
    # confirmed host (the rotunda layout - kernel32's exports jump through
    # its own contract imports)
    def thunk_display(dll, fname, importer):
        if dll in HOST_MODULES:
            return "%s.%s" % (dll[:-4], fname)
        if dll.endswith(".dll"):
            contract = dll[:-4]
            if contract.startswith("api-ms-") or contract.startswith("ext-ms-"):
                resolved = entries.get(contract)
                if isinstance(resolved, dict):
                    resolved = resolved.get(importer, resolved.get(""))
                if isinstance(resolved, str):
                    return "%s.%s" % (resolved[:-4], fname)
                return "unresolved:%s.%s" % (contract, fname)
        return "%s.%s" % (dll, fname)

    display_thunks = {}
    for host in HOST_MODULES:
        display_thunks[host] = {
            slot: thunk_display(dll, fname, host)
            for slot, (dll, fname) in sorted(images[host].thunk_targets.items())
        }

    doc = {
        "schema": 1,
        "kind": "apiset-evidence",
        "arch": "x64",
        "anchor": {
            "xxhash64": hex(anchor_arg),
            "note": ("host candidates derived from EAT membership evidence "
                     "against the observed import closure; hosts confirmed by "
                     "same-source API Set schema or recorded review"),
        },
        "scanned_inputs": [
            {"role": "host+importer" if name in IMPORTER_MODULES else "host",
             "name": name, "xxhash64": hex(images[name].hash)}
            for name in HOST_MODULES
        ] + [{"role": "extra-importer", "name": img.name, "xxhash64": hex(img.hash)}
             for img in extra],
        "skipped_ordinal_imports": {
            imp: img.ordinal_import_skips for imp, img in importers},
        "forwarders": forward_status,
        "thunk_targets": display_thunks,
        "contracts": contracts_out,
    }
    evidence_path = Path(args.evidence)
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    with open(evidence_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(doc, handle, indent=1)
        handle.write("\n")
    print("wrote %s (%d contracts)" % (evidence_path, len(contracts_out)))

    if args.map:
        if unresolved:
            print("map NOT written - %d contract(s) unconfirmed:" % len(unresolved))
            for contract, ustatus in unresolved:
                print("  %s: %s" % (contract, ustatus))
            print("the evidence report is the deliverable until every contract "
                  "is confirmed by schema or recorded review")
            return 0
        out = {
            "schema": 1,
            "arch": "x64",
            "anchor": {
                "xxhash64": hex(anchor_arg),
                "note": ("hosts confirmed per contract by same-source API Set "
                         "schema or recorded review; see the evidence report"),
            },
            "entries": [],
        }
        for contract in sorted(entries):
            hosts = entries[contract]
            if isinstance(hosts, str):
                out["entries"].append({"contract": contract, "host": hosts})
            else:
                for importer in sorted(hosts):
                    entry = {"contract": contract, "host": hosts[importer]}
                    if importer:
                        entry["importer"] = importer
                    out["entries"].append(entry)
        map_path = Path(args.map)
        map_path.parent.mkdir(parents=True, exist_ok=True)
        with open(map_path, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(out, handle, indent=1)
            handle.write("\n")
        print("wrote %s (%d entries, all contracts confirmed)"
              % (map_path, len(out["entries"])))
    elif unresolved:
        print("no --map requested; unconfirmed contracts: %d" % len(unresolved))
        for contract, ustatus in unresolved:
            print("  %s: %s" % (contract, ustatus))
    return 0


if __name__ == "__main__":
    sys.exit(main())
