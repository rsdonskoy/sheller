#!/usr/bin/env python3
"""Product-level parity diff between two image-form unpack products.

The craft route and the capture route deliver the same sample as a
memory-image PE (the repaired copy's shape). This tool diffs two such
products over the whole image and classifies every differing aligned 8-byte
slot by VERIFIED identity - never span membership alone:

  world-binding    the slot's identity and both sides' targets are verifiably
                   corresponding: standard IAT slots by the normalized
                   (module, export) identity on both sides, and repaired
                   name-record slots only when the record's export name is at
                   least four characters AND resolves in at least one side's
                   world export-name set - a record the worlds cannot
                   corroborate is never a binding (the other side must then
                   resolve to exactly that export for the pair to pass).
  recovery-content anything else, including one-sided span hits, same module
                   with a different target, different modules, ordinary bytes
                   that happen to look address-shaped, and known slots bound
                   to the wrong function.
  cause-uncertain  identity unreadable on a side (a value inside a module's
                   span but with no terminating export, or inside a
                   non-module world region whose target identity has no
                   applicable mapping evidence).

Image-internal positions need no classifier branch: at equal image bases the
same position reads equal (never a diff row), and unequal image bases are a
named shape failure before any classification runs.

Each product needs its world as a snapshot container (parsed with the same
reader world_diff uses) or an equivalent hashed module table (JSON schema 2:
explicit bases, exports or an image file, and for image files a mandatory
sha256 the tool verifies before trusting the exports). Exit code: 0 only when
no recovery-content and no cause-uncertain difference exists and the shape
checks pass; 1 otherwise; 2 on named input rejection.

Usage:
    python tools/product_diff.py <product-a> <product-b> \
        (--world-a-snap <snap> | --world-a-table <table.json>) \
        (--world-b-snap <snap> | --world-b-table <table.json>) \
        [--output <report.json>]

The report is machine-readable JSON. This tool is stdlib-only; it reuses the
snapshot reader and the PE parser from tools/world_diff.py.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import world_diff as wd  # noqa: E402  (sibling tool: reader + PE parser)

CLASS_WORLD_BINDING = "world-binding"
CLASS_RECOVERY_CONTENT = "recovery-content"
CLASS_CAUSE_UNCERTAIN = "cause-uncertain"

MIN_RECORD_NAME = 4


class NamedRejection(Exception):
    """A named input refusal: printed verbatim, exit code 2, no report."""


# ---------------------------------------------------------------------------
# World metadata: snapshot container or equivalent hashed module table
# ---------------------------------------------------------------------------


class WorldMeta:
    """One product's world: modules with exact export addresses, plus the
    non-module regions the world maps (heap/stack - identity-unreadable
    targets, never world-binding evidence)."""

    def __init__(self, source, modules, regions):
        self.source = source
        self._modules = modules
        self._regions = regions
        self._spans = sorted(
            [(m["base"], m["base"] + m["size"], True, m) for m in modules]
            + [(r["base"], r["base"] + r["size"], False, r) for r in regions])
        # Every export function name the world can corroborate, for the
        # record-slot verification in classify_slot. Windows export names
        # are matched case-insensitively (the loader folds them, and
        # repaired records may carry the folded spelling).
        self.export_names = {n.lower() for m in modules
                             for n in m["exports"].values()}

    def in_module(self, value):
        for start, end, is_module, payload in self._spans:
            if is_module and start <= value < end:
                return payload
        return None

    def in_region(self, value):
        for start, end, is_module, payload in self._spans:
            if not is_module and start <= value < end:
                return payload
        return None


def _read_section_table(image_bytes):
    """(rva, raw_size, raw_pointer) per section, straight from the headers;
    None when the image is not a parseable PE32+ (the caller names it)."""
    try:
        if len(image_bytes) < 0x40 or image_bytes[0:2] != b"MZ":
            return None
        pe_offset = wd.read_le(image_bytes, 0x3C, 4)
        if image_bytes[pe_offset:pe_offset + 4] != b"PE\0\0":
            return None
        magic = wd.read_le(image_bytes, pe_offset + 24, 2)
        if magic != 0x20B:
            return None  # PE32 modules: this tool's route is PE32+-only
        count = wd.read_le(image_bytes, pe_offset + 6, 2)
        opt_size = wd.read_le(image_bytes, pe_offset + 20, 2)
        table = pe_offset + 24 + opt_size
        sections = []
        for i in range(count):
            at = table + 40 * i
            if at + 40 > len(image_bytes):
                return None
            sections.append((wd.read_le(image_bytes, at + 12, 4),
                             wd.read_le(image_bytes, at + 16, 4),
                             wd.read_le(image_bytes, at + 20, 4)))
        return sections
    except wd.Unreadable:
        return None


def _rva_to_offset(image_bytes, rva):
    """RVA -> file offset through the section table; None when the RVA is not
    file-backed (a virtual-only image is refused by the caller, not
    silently misread)."""
    for sec_rva, raw_size, raw_ptr in _read_section_table(image_bytes) or ():
        if sec_rva <= rva < sec_rva + max(raw_size, 1):
            offset = rva - sec_rva + raw_ptr
            if offset + 4 <= len(image_bytes):
                return offset
    return None


def _parse_module_exports(image_bytes, base, layout="memory"):
    """Exact export addresses from a module image:
    {absolute_va: function_name}. layout picks the RVA decode: "memory" for
    a mapped image (the RVA reads directly - the loaded section headers keep
    stale file PointerToRawData values, so a table walk would misread) or
    "file" for an on-disk image (the RVA goes through the section table).
    Returns (exports, status): status names a partial parse
    ("partial:<detail>") so a truncated table is visible in the report
    instead of surfacing only as uncertain slots. PE32 images are a named
    refusal upstream (this route is PE32+-only); unnamed ordinal-only
    exports cannot appear in the map and their slots classify
    cause-uncertain, never a guess."""
    exports = {}
    if len(image_bytes) < 0x40 or image_bytes[0:2] != b"MZ":
        return exports, "no-mz"
    sections = _read_section_table(image_bytes)
    if sections is None:
        return exports, "not-pe32-plus"

    if layout == "memory":
        def at(rva, width):
            if rva + width > len(image_bytes):
                raise wd.Unreadable("rva 0x%x past image end" % rva)
            return wd.read_le(image_bytes, rva, width)

        name_at = lambda rva: int(rva)  # RVA == offset in a mapped image
    else:

        def at(rva, width):
            off = _rva_to_offset(image_bytes, rva)
            if off is None or off + width > len(image_bytes):
                raise wd.Unreadable("rva 0x%x not file-backed" % rva)
            return wd.read_le(image_bytes, off, width)

        name_at = lambda rva: _rva_to_offset(image_bytes, rva)

    try:
        pe_offset = wd.read_le(image_bytes, 0x3C, 4)
        optional = pe_offset + 24
        exp_rva = wd.read_le(image_bytes, optional + 112, 4)
        if exp_rva == 0:
            return exports, "no-export-directory"
        if layout == "file":
            exp_off = _rva_to_offset(image_bytes, exp_rva)
            if exp_off is None or exp_off + 40 > len(image_bytes):
                return exports, "export-directory-not-file-backed"

        eat_rva = at(exp_rva + 28, 4)
        names_rva = at(exp_rva + 32, 4)
        ords_rva = at(exp_rva + 36, 4)
        count = at(exp_rva + 24, 4)  # NumberOfNames
        for i in range(count):
            name_rva = at(names_rva + 4 * i, 4)
            ordinal = at(ords_rva + 2 * i, 2)
            func_rva = at(eat_rva + 4 * ordinal, 4)
            name_off = name_at(name_rva)
            if name_off is None:
                continue
            end = image_bytes.find(b"\0", name_off)
            if end < 0 or end == name_off:
                continue
            label = image_bytes[name_off:end].decode("ascii", errors="replace")
            if label:
                exports[base + func_rva] = label
    except wd.Unreadable as exc:
        return exports, "partial:%s" % exc
    return exports, "ok"


def world_meta_from_snapshot(path):
    """Snapshot container: the same reader and Ldr walk world_diff uses; each
    module's export table resolves from the mapped image bytes (memory
    layout: file offset == RVA)."""
    world = wd.read_snapshot(path)
    chains, error = wd.enumerate_ldr(world)
    if chains is None:
        raise NamedRejection("%s: Ldr walk failed: %s" % (path, error))
    modules = []
    for entry in chains.get("load", []):
        name, base, size = entry["name"], entry["base"], entry["size"]
        exports, status = {}, "unreadable"
        try:
            exports, status = _parse_module_exports(world.read(base, size), base)
        except wd.Unreadable:
            pass  # the module keeps its span; status names the gap
        modules.append({"name": name, "base": base, "size": size,
                        "exports": exports, "parse_status": status})
    module_spans = [(m["base"], m["base"] + m["size"]) for m in modules]
    regions = []
    for region in world.regions:
        if region["content"] is None:
            continue
        base, size = region["base"], region["size"]
        if any(s <= base and base + size <= e for s, e in module_spans):
            continue  # covered by a module span
        regions.append({"base": base, "size": size, "role": "world-region"})
    return WorldMeta("snapshot:%s" % path, modules, regions)


def _exports_from_image_file(image_path):
    """Exports from a file-layout image: the RVA goes through the section
    table, so ordinary on-disk DLLs parse correctly (no layout luck)."""
    try:
        return Path(image_path).read_bytes()
    except OSError as exc:
        raise NamedRejection("module table image_file unreadable: %s (%s)"
                             % (image_path, exc))


def world_meta_from_table(path):
    """Equivalent hashed module table, schema 2: explicit base + exports
    (inline map or an image file) and, for image files, a mandatory sha256
    the tool verifies before trusting anything derived from the file. The
    hash binding is what makes the table a reproducible evidence artifact:
    a drifted source image is a named rejection, never a silently different
    world."""
    try:
        table = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise NamedRejection("module table unreadable: %s (%s)" % (path, exc))
    if not isinstance(table, dict) or table.get("schema") != 2 \
            or not isinstance(table.get("modules"), list):
        raise NamedRejection("module table malformed: %s (expected schema 2 "
                             "with a modules array)" % path)
    modules = []
    for row in table["modules"]:
        try:
            base = int(row["base"], 16)
            size = int(row["size"], 16)
            name = row["name"]
        except (KeyError, ValueError) as exc:
            raise NamedRejection("module table row malformed: %r (%s)" % (row, exc))
        image_bytes = None
        if "image_file" in row:
            image_bytes = _exports_from_image_file(row["image_file"])
            digest = row.get("image_sha256")
            if not digest:
                raise NamedRejection("module table image_file row lacks the "
                                     "mandatory image_sha256: %s" % name)
            actual = hashlib.sha256(image_bytes).hexdigest()
            if actual != digest:
                raise NamedRejection(
                    "module table image_sha256 mismatch for %s: table says "
                    "%s, file %s hashes to %s - the source image drifted, "
                    "the table refuses to describe it" % (name, digest,
                                                          row["image_file"],
                                                          actual))
            exports, status = _parse_module_exports(image_bytes, base,
                                                    layout="file")
        elif "exports" in row:
            exports = {}
            for func, rva_text in row["exports"].items():
                exports[base + int(rva_text, 16)] = func
            status = "inline"
        else:
            raise NamedRejection("module table row carries neither exports "
                                 "nor image_file: %s" % name)
        modules.append({"name": name, "base": base, "size": size,
                        "exports": exports, "parse_status": status,
                        "image_sha256": row.get("image_sha256"),
                        "provenance": row.get("provenance", "")})
    regions = []
    for row in table.get("regions", []):
        try:
            regions.append({"base": int(row["base"], 16),
                            "size": int(row["size"], 16),
                            "role": row.get("role", "world-region")})
        except (KeyError, ValueError) as exc:
            raise NamedRejection("module table region malformed: %r (%s)" % (row, exc))
    return WorldMeta("table:%s" % path, modules, regions)


# ---------------------------------------------------------------------------
# Identity resolution
# ---------------------------------------------------------------------------


def _record_name(image, offset):
    """hint word + printable name + NUL, inside the image; None otherwise.
    The name must carry at least MIN_RECORD_NAME characters - two printable
    bytes plus a NUL is far too easy for ordinary data to hit by accident."""
    if offset + 2 + MIN_RECORD_NAME + 1 > len(image):
        return None
    name = wd.read_cstring(image, offset + 2, cap=256)
    if name and len(name) >= MIN_RECORD_NAME \
            and all(0x20 <= ord(c) <= 0x7E for c in name):
        return name
    return None


def resolve_identity(value, meta, image, image_base, size_of_image):
    """Classify one slot value against the product image and the world. A
    record hit here is only a CANDIDATE: classify_slot corroborates the name
    against the worlds' export-name sets before any world-binding verdict."""
    # Image-internal: a repaired name-record RVA (raw offset form) or a bound
    # pointer into the product's own image (VA form).
    candidates = [value]
    if value >= image_base:
        candidates.append(value - image_base)
    for candidate in candidates:
        if not (0 < candidate < size_of_image) or candidate >= len(image):
            continue
        name = _record_name(image, candidate)
        if name:
            return {"kind": "record", "function": name, "rva": candidate}
    module = meta.in_module(value)
    if module is not None:
        target = module["exports"].get(value)
        if target is not None:
            return {"kind": "module", "module": module["name"],
                    "function": target}
        return {"kind": "uncertain", "module": module["name"],
                "detail": "inside %s span with no terminating export"
                          % module["name"]}
    region = meta.in_region(value)
    if region is not None:
        return {"kind": "region", "role": region.get("role", "world-region")}
    return {"kind": "unmapped"}


# ---------------------------------------------------------------------------
# Standard IAT coverage: the walk world_diff's parser shares stops at the
# first zero thunk, which truncates the slot set when a binding slot is
# legitimately zero (a forwarder hole). The coverage used for the
# standard-IAT decision walks each descriptor's OriginalFirstThunk to its
# own terminator when present (the ILT length is authoritative), and falls
# back to the FirstThunk walk's first-zero stop only when the descriptor
# carries no OFT.
# ---------------------------------------------------------------------------


def _standard_iat_slots(image):
    """{slot_rva: descriptor dll name} over every import descriptor."""
    slots = {}
    try:
        if len(image) < 0x40 or image[0:2] != b"MZ":
            return slots
        pe_offset = wd.read_le(image, 0x3C, 4)
        if image[pe_offset:pe_offset + 4] != b"PE\0\0":
            return slots
        optional = pe_offset + 24
        if wd.read_le(image, optional, 2) != 0x20B:
            return slots
        dd_count = wd.read_le(image, optional + 108, 4)
        dd_base = optional + 112
        if dd_count <= 1:
            return slots
        import_rva = wd.read_le(image, dd_base + 8 * 1, 4)
        if not import_rva:
            return slots
        at = _rva_to_offset(image, import_rva)
        if at is None:
            return slots
        for _ in range(4096):  # bounded: import descriptors are finite
            if at + 20 > len(image):
                break
            oft = wd.read_le(image, at, 4)
            name_rva = wd.read_le(image, at + 12, 4)
            first_thunk = wd.read_le(image, at + 16, 4)
            if oft == 0 and name_rva == 0 and first_thunk == 0:
                break
            dll = None
            name_off = _rva_to_offset(image, name_rva) if name_rva else None
            if name_off is not None:
                end = image.find(b"\0", name_off)
                if 0 < end - name_off < 256:
                    dll = image[name_off:end].decode("ascii", errors="replace")
            if first_thunk:
                length = None
                if oft:
                    oft_off = _rva_to_offset(image, oft)
                    if oft_off is not None:
                        length = 0
                        probe = oft_off
                        while probe + 8 <= len(image) and length < 8192:
                            if wd.read_le(image, probe, 8) == 0:
                                break
                            length += 1
                            probe += 8
                walk = 0
                while True:
                    slot_rva = first_thunk + 8 * walk
                    if slot_rva + 8 > len(image):
                        break
                    if length is not None and walk >= length:
                        break
                    bound = wd.read_le(image, slot_rva, 8)
                    if length is None and bound == 0:
                        break
                    slots[slot_rva] = dll
                    walk += 1
            at += 20
    except wd.Unreadable:
        return slots
    return slots


# ---------------------------------------------------------------------------
# Product loading and diffing
# ---------------------------------------------------------------------------


def load_product(path):
    try:
        image = Path(path).read_bytes()
    except OSError as exc:
        raise NamedRejection("product unreadable: %s (%s)" % (path, exc))
    parsed = wd.parse_pe(image)
    if parsed is None:
        raise NamedRejection("product is not a parseable PE32+ image: %s" % path)
    if len(image) != parsed.size_of_image:
        raise NamedRejection(
            "product is not the full virtual-layout image: %s is %d bytes "
            "but SizeOfImage is 0x%x - the image-form contract requires the "
            "whole mapped size" % (path, len(image), parsed.size_of_image))
    try:
        pe_offset = wd.read_le(image, 0x3C, 4)
        optional = pe_offset + 24
        extra = {"entry_point": wd.read_le(image, optional + 16, 4),
                 "import_dir_rva": wd.read_le(image, optional + 112 + 8, 4)}
    except wd.Unreadable:
        raise NamedRejection("product header truncated: %s" % path)
    return image, parsed, extra


def _fold(name):
    if not name:
        return ""
    name = name.strip().lower()
    return name[:-4] if name.endswith(".dll") else name


def iter_diffs(image_a, image_b):
    """Whole-image byte diff as aligned 8-byte slot windows (the image is a
    full virtual-layout image, so SizeOfImage covers every byte and the
    length is a multiple of the alignment)."""
    size = len(image_a)
    rva = 0
    while rva < size:
        # Fast forward over equal 64-byte blocks (slice compare is C speed).
        while rva + 64 <= size and image_a[rva:rva + 64] == image_b[rva:rva + 64]:
            rva += 64
        while rva < size and image_a[rva] == image_b[rva]:
            rva += 1
        if rva >= size:
            break
        slot_start = rva - (rva % 8)
        yield slot_start, 8, "slot"
        rva = slot_start + 8


def classify_slot(rva, slot_info, id_a, id_b, value_a, value_b,
                  name_universe):
    """One pointer slot's verified-identity classification (D3).
    slot_info: {"standard": bool, "dll": descriptor module name or None}.
    name_universe: every export function name either world's module table
    can corroborate - a record whose name no world knows is never a
    binding."""
    is_standard_iat = slot_info["standard"]
    slot_dll_name = slot_info.get("dll")
    entry = {"rva": rva, "size": 8, "standard_iat": is_standard_iat,
             "value_a": "0x%016x" % value_a, "value_b": "0x%016x" % value_b,
             "identity_a": id_a, "identity_b": id_b}

    def finish(cls, reason):
        entry["class"] = cls
        entry["reason"] = reason
        return entry

    kinds = (id_a["kind"], id_b["kind"])

    # Identity unreadable on either side: reported, never guessed.
    if "uncertain" in kinds:
        if id_a["kind"] == "uncertain":
            detail = "identity-unreadable:a:%s" % id_a.get("module")
        else:
            detail = "identity-unreadable:b:%s" % id_b.get("module")
        return finish(CLASS_CAUSE_UNCERTAIN, detail)
    if "region" in kinds:
        role = id_a.get("role") if id_a["kind"] == "region" else id_b.get("role")
        return finish(CLASS_CAUSE_UNCERTAIN,
                      "region-member:%s (no applicable target-mapping evidence)"
                      % role)

    if kinds == ("module", "module"):
        if id_a["module"] != id_b["module"]:
            return finish(CLASS_RECOVERY_CONTENT, "different-module")
        if id_a["function"] != id_b["function"]:
            return finish(CLASS_RECOVERY_CONTENT,
                          "same-module-different-target")
        entry["module"] = id_a["module"]
        entry["function"] = id_a["function"]
        return finish(CLASS_WORLD_BINDING, "bound-both-sides")

    if "record" in kinds:
        record = id_a if id_a["kind"] == "record" else id_b
        other = id_b if id_a["kind"] == "record" else id_a
        # The record's name must be corroborated by at least one world's
        # export-name set (case-folded): ordinary data that happens to hit
        # the hint/printable/NUL shape can never become a binding.
        if record["function"].lower() not in name_universe:
            return finish(CLASS_RECOVERY_CONTENT,
                          "record-name-unverifiable:%s" % record["function"])
        if other["kind"] == "record":
            # Both sides repaired: each name needs the world corroboration.
            if other["function"].lower() not in name_universe:
                return finish(CLASS_RECOVERY_CONTENT,
                              "record-name-unverifiable:%s"
                              % other["function"])
            if record["function"].lower() != other["function"].lower():
                return finish(CLASS_RECOVERY_CONTENT,
                              "known-slot-wrong-binding"
                              if is_standard_iat else "function-mismatch")
            entry["function"] = record["function"]
            # Both names are world-corroborated; the descriptor-less slot
            # keeps an explicit module marker, never a null binding.
            entry["module"] = "(unattributed: no descriptor on either side)"
            return finish(CLASS_WORLD_BINDING, "record-identity-both-sides")
        if other["kind"] == "unmapped":
            return finish(CLASS_RECOVERY_CONTENT,
                          "one-sided-span (record side has no counterpart)")
        if other.get("function", "").lower() != record["function"].lower():
            return finish(CLASS_RECOVERY_CONTENT,
                          "known-slot-wrong-binding"
                          if is_standard_iat else "function-mismatch")
        # A standard-IAT record slot names its module in the descriptor: the
        # module identity is verifiable too, not just the export name.
        if is_standard_iat and slot_dll_name and other.get("module"):
            if _fold(slot_dll_name) != _fold(other["module"]):
                return finish(CLASS_RECOVERY_CONTENT, "different-module")
        entry["function"] = record["function"]
        entry["module"] = other.get("module") or slot_dll_name
        return finish(CLASS_WORLD_BINDING, "record-identity")

    if id_a["kind"] == "unmapped" and id_b["kind"] == "unmapped":
        return finish(CLASS_RECOVERY_CONTENT, "shape-coincidence")
    return finish(CLASS_RECOVERY_CONTENT, "one-sided-span")


def per_section_identity(image_a, pe_a, image_b, compare_size):
    """Per-section rows plus the unsectioned remainder (header page and
    inter-section gaps) so the report is explicit that the section rows are
    not a partition of the compared span."""
    rows = []
    covered = []
    for section in pe_a.sections:
        start = section["rva"]
        end = min(start + section["vsize"], compare_size)
        if start >= end:
            continue
        span = end - start
        same = sum(1 for a, b in zip(image_a[start:end], image_b[start:end])
                   if a == b)
        rows.append({"name": section["name"], "rva": start, "vsize": span,
                     "identical_bytes": same,
                     "identity_ratio": round(100.0 * same / span, 5)
                     if span else 100.0})
        covered.append((start, end))
    covered.sort()
    cursor = 0
    tail_spans = []
    for start, end in covered:
        if start > cursor:
            tail_spans.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < compare_size:
        tail_spans.append((cursor, compare_size))
    if tail_spans:
        same = 0
        span = 0
        for s, e in tail_spans:
            span += e - s
            same += sum(1 for a, b in zip(image_a[s:e], image_b[s:e]) if a == b)
        rows.append({"name": "(header+gaps)", "rva": tail_spans[0][0],
                     "vsize": span, "identical_bytes": same,
                     "identity_ratio": round(100.0 * same / span, 5)
                     if span else 100.0})
    return rows


def shape_checks(pe_a, pe_b, extra_a, extra_b, len_a, len_b):
    checks = []

    def check(name, passed, detail=""):
        checks.append({"check": name, "pass": bool(passed), "detail": detail})

    check("image-base-equal", pe_a.image_base == pe_b.image_base,
          "a=0x%x b=0x%x" % (pe_a.image_base, pe_b.image_base))
    check("size-of-image-equal",
          pe_a.size_of_image == pe_b.size_of_image,
          "a=0x%x b=0x%x" % (pe_a.size_of_image, pe_b.size_of_image))
    check("file-size-equal", len_a == len_b,
          "a=%d b=%d" % (len_a, len_b))
    names_a = [s["name"] for s in pe_a.sections]
    names_b = [s["name"] for s in pe_b.sections]
    check("section-table-equal", names_a == names_b,
          "a=%s b=%s" % (names_a, names_b))
    check("entry-point-equal",
          extra_a["entry_point"] == extra_b["entry_point"],
          "a=0x%x b=0x%x" % (extra_a["entry_point"], extra_b["entry_point"]))
    check("import-directory-equal",
          extra_a["import_dir_rva"] == extra_b["import_dir_rva"],
          "a=0x%x b=0x%x" % (extra_a["import_dir_rva"],
                             extra_b["import_dir_rva"]))
    return {"checks": checks, "pass": all(c["pass"] for c in checks),
            "entry_point": {"a": "0x%x" % extra_a["entry_point"],
                            "b": "0x%x" % extra_b["entry_point"],
                            "equal": extra_a["entry_point"]
                            == extra_b["entry_point"]},
            "import_directory": {"a": "0x%x" % extra_a["import_dir_rva"],
                                 "b": "0x%x" % extra_b["import_dir_rva"],
                                 "equal": extra_a["import_dir_rva"]
                                 == extra_b["import_dir_rva"]}}


def build_report(path_a, path_b, meta_a, meta_b):
    image_a, pe_a, extra_a = load_product(path_a)
    image_b, pe_b, extra_b = load_product(path_b)

    compare_size = len(image_a)
    identical = sum(1 for a, b in zip(image_a, image_b) if a == b)
    identity_ratio = 100.0 * identical / compare_size if compare_size else 100.0

    # Standard-IAT coverage: the tool's own OFT-anchored walk (world_diff's
    # parser stops at the first zero thunk, which truncates slot sets with
    # legitimate binding holes).
    slots_a = _standard_iat_slots(image_a)
    slots_b = _standard_iat_slots(image_b)

    def slot_info(rva):
        source = None
        for pool in (slots_a, slots_b):
            if rva in pool:
                source = {"standard": True, "dll": pool[rva]}
                break
        if source is None:
            source = {"standard": False, "dll": None}
        return source

    name_universe = meta_a.export_names | meta_b.export_names

    entries = []
    for rva, span, kind in iter_diffs(image_a, image_b):
        value_a = int.from_bytes(image_a[rva:rva + span], "little")
        value_b = int.from_bytes(image_b[rva:rva + span], "little")
        id_a = resolve_identity(value_a, meta_a, image_a,
                                pe_a.image_base, pe_a.size_of_image)
        id_b = resolve_identity(value_b, meta_b, image_b,
                                pe_b.image_base, pe_b.size_of_image)
        entries.append(classify_slot(rva, slot_info(rva), id_a, id_b,
                                     value_a, value_b, name_universe))

    sections = per_section_identity(image_a, pe_a, image_b, compare_size)
    shape = shape_checks(pe_a, pe_b, extra_a, extra_b,
                         len(image_a), len(image_b))

    counts = {CLASS_WORLD_BINDING: 0, CLASS_RECOVERY_CONTENT: 0,
              CLASS_CAUSE_UNCERTAIN: 0}
    for entry in entries:
        counts[entry["class"]] += 1
    shape_pass = shape["pass"]
    verdict_pass = (counts[CLASS_RECOVERY_CONTENT] == 0
                    and counts[CLASS_CAUSE_UNCERTAIN] == 0 and shape_pass)

    def world_summary(side, meta):
        return {"source": meta.source,
                "modules": [{"name": m["name"], "base": "0x%x" % m["base"],
                             "exports_count": len(m["exports"]),
                             "parse_status": m.get("parse_status", ""),
                             "image_sha256": m.get("image_sha256"),
                             "provenance": m.get("provenance", "")}
                            for m in meta._modules]}

    return {
        "tool": "product_diff",
        "products": {
            "a": {"path": str(path_a), "size": len(image_a)},
            "b": {"path": str(path_b), "size": len(image_b)},
        },
        "worlds": {"a": world_summary("a", meta_a),
                   "b": world_summary("b", meta_b)},
        "image": {"compare_bytes": compare_size,
                  "identical_bytes": identical,
                  "identity_ratio": round(identity_ratio, 5)},
        "sections": sections,
        "shape": shape,
        "classes": counts,
        "diffs": entries,
        "verdict": {
            "pass": verdict_pass,
            "exit": 0 if verdict_pass else 1,
            "recovery_content_count": counts[CLASS_RECOVERY_CONTENT],
            "cause_uncertain_count": counts[CLASS_CAUSE_UNCERTAIN],
            "shape_pass": shape_pass,
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Product-level parity diff with verified-identity cause "
                    "classification (world-binding / recovery-content / "
                    "cause-uncertain).")
    parser.add_argument("product_a", help="image-form product, side A")
    parser.add_argument("product_b", help="image-form product, side B")
    parser.add_argument("--world-a-snap",
                        help="side A's world: snapshot container file")
    parser.add_argument("--world-a-table",
                        help="side A's world: equivalent hashed module table "
                             "(JSON, schema 2)")
    parser.add_argument("--world-b-snap",
                        help="side B's world: snapshot container file")
    parser.add_argument("--world-b-table",
                        help="side B's world: equivalent hashed module table "
                             "(JSON, schema 2)")
    parser.add_argument("--output", help="write the JSON report here "
                                         "(default: stdout)")
    args = parser.parse_args(argv)

    def pick(side, snap_attr, table_attr):
        snap = getattr(args, snap_attr)
        table = getattr(args, table_attr)
        if snap and table:
            raise NamedRejection("--world-%s-snap and --world-%s-table are "
                                 "mutually exclusive" % (side, side))
        if snap:
            return world_meta_from_snapshot(snap)
        if table:
            return world_meta_from_table(table)
        raise NamedRejection("side %s lacks world metadata: give "
                             "--world-%s-snap or --world-%s-table"
                             % (side, side, side))

    try:
        meta_a = pick("a", "world_a_snap", "world_a_table")
        meta_b = pick("b", "world_b_snap", "world_b_table")
        report = build_report(args.product_a, args.product_b, meta_a, meta_b)
    except NamedRejection as exc:
        print("product_diff: %s" % exc, file=sys.stderr)
        return 2
    except wd.NamedError as exc:
        print("product_diff: %s" % exc, file=sys.stderr)
        return 2

    text = json.dumps(report, indent=1)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return report["verdict"]["exit"]


if __name__ == "__main__":
    sys.exit(main())
