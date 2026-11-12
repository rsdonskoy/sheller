#!/usr/bin/env python3
"""World diff harness: a mechanical diff of two sheller world snapshots.

Reads one capture snapshot and one crafted container (same snapshot format
family: v1, or v2 with the trailing pending-module block), aligns the two
worlds' modules by name, and renders a deterministic JSON report that
classifies every difference as expected (layout mechanics: the module set,
relocations, import binding, KUSD volatile fields) or as a divergence
candidate (infrastructure and runtime bytes - what a crafted route must get
right to be indistinguishable).

Engine facts mirrored here (sources: src/engine/mem_region_map.cpp,
src/loader/env.cpp, src/engine/rebuild_state.h):
  - KUSD lives at the ABI-fixed independent address 0x7FFE0000
    (kLoaderKUser) - never derived from a module base.
  - x64 Ldr walk: PEB@TEB+0x60, Ldr@PEB+0x18, chain heads at
    ldr+0x10/0x20/0x30; entry DllBase@+0x30, SizeOfImage@+0x40,
    BaseDllName UNICODE_STRING@+0x58 (Length u16, Buffer u64).
  - BaseDllName encoding: UTF-16 in real captures, narrow ASCII in the
    synthetic loader environment; told apart by content and folded to
    lowercase ASCII, exactly like the engine's fold_module_name.
  - PEB/TEB/image base come from the snapshot metadata block.

Pure file processing: the engine, the CLI and the snapshot format are
untouched. Same input pair, byte-identical report.
"""

import argparse
import hashlib
import json
import sys

KUSD_ADDRESS = 0x7FFE0000
KUSD_PAGE_BYTES = 0x1000

# x64 Ldr walk offsets (engine: mem_region_map.cpp / env.cpp).
LDR_HEAD_OFFSETS = (0x10, 0x20, 0x30)  # InLoad / InMemory / InInitialization
LDR_CHAIN_NAMES = ("load", "memory", "init")
LDR_ENTRY_NODE_OFFSET = (0x00, 0x10, 0x20)  # link -> entry base per chain
LDR_DLLBASE = 0x30
LDR_SIZEOFIMAGE = 0x40
LDR_NAME_LENGTH = 0x58
LDR_NAME_BUFFER = 0x60
MAX_MODULE_IMAGES = 64  # engine kMaxModuleImages
MODULE_NAME_BYTES = 64  # engine kModuleNameBytes

# PEB named-field list (engine layout, env.cpp). ImageBaseAddress is checked
# against each side's own metadata (self-consistency), not across sides -
# the two worlds sit at different bases by design.
PEB_FIELDS = (
    ("being_debugged", 0x02, 1),
    ("ldr", 0x18, 8),
    ("process_heap", 0x30, 8),
    ("nt_global_flag", 0xBC, 4),
)
PEB_IMAGE_BASE_OFFSET = 0x10
TEB_SELF_OFFSET = 0x30
TEB_PEB_OFFSET = 0x60

# KUSD named-field list, offsets per the Windows SDK (ksamd64.inc
# KUSER_SHARED_DATA: TickCountMultiplier 0x04, InterruptTime 0x08,
# SystemTime 0x14, NtSystemRoot 0x30). The volatile fields are the
# time-derived values the engine seeds with fixed deterministic constants
# (env.cpp fill_kuser_shared_data writes SystemTime at 0x14 and the tick at
# 0x320 - the same offsets); they always differ between a real capture and
# the crafted world and are listed, but never as divergence candidates.
KUSD_VOLATILE_FIELDS = (
    ("interrupt_time", 0x008, 12),
    ("systemtime", 0x014, 8),
    ("tick_count", 0x320, 4),
)
KUSD_STRUCTURAL_FIELDS = (
    ("nt_system_root", 0x030, 520),  # 260 UTF-16 chars, NUL-trimmed
)

# Snapshot format constants (include/sheller/snapshot.h - the byte layout is
# golden-file tested; a drift here turns the format tests red first).
SNAPSHOT_MAGIC = b"SHELLSNP"
HEADER_SIZE = 24
REGISTERS_SIZE = 144
METADATA_SIZE = 48
REGION_RECORD_SIZE = 25
PENDING_MARKER = b"PENDMOD1"
MAX_PENDING_NAME_BYTES = 260
MAX_PENDING_MODULE_BYTES = 64 * 1024 * 1024

DOMAIN_ORDER = {"module_set": 0, "module_image": 1, "infrastructure": 2, "pending": 3}

CLASS_EXPECTED = "expected"
CLASS_EXPECTED_RELOC = "expected-reloc"
CLASS_EXPECTED_IMPORT = "expected-import"
CLASS_EXPECTED_VOLATILE = "expected-volatile"
CLASS_CANDIDATE = "candidate"
CLASS_CANDIDATE_RELOC_ANOMALY = "candidate-reloc-anomaly"
CLASS_CANDIDATE_IMPORT_ANOMALY = "candidate-import-anomaly"
CLASS_CAUSE_UNCERTAIN = "cause-uncertain"
CLASS_UNRESOLVABLE = "unresolvable"


class NamedError(Exception):
    """A named refusal: printed verbatim, exit code 2, no report."""


class SnapshotError(NamedError):
    """Snapshot load refusal, named after the engine's snapshot::Error values."""

    def __init__(self, code, detail):
        super().__init__("%s: %s" % (code, detail))
        self.code = code


class Unreadable(Exception):
    """A guest-memory read fell outside the regions with content present."""

    def __init__(self, detail):
        super().__init__(detail)
        self.detail = detail


def hexaddr(value):
    return "0x%x" % value


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def read_le(data, offset, width):
    end = offset + width
    if offset < 0 or end > len(data):
        raise Unreadable("read of %d bytes at offset 0x%x past end" % (width, offset))
    return int.from_bytes(data[offset:end], "little")


# ---------------------------------------------------------------------------
# Snapshot reader
# ---------------------------------------------------------------------------


class World:
    """One world model: regions, registers, metadata, pending block."""

    def __init__(self, version, regions, registers, metadata, pending):
        self.version = version
        self.regions = sorted(regions, key=lambda r: (r["base"], r["size"]))
        self.registers = registers
        self.metadata = metadata
        self.pending = pending

    def read(self, address, size):
        """Guest-memory read across regions; any uncovered span fails.
        Regions are sorted and non-overlapping (engine contract), so coverage
        is interval arithmetic, never per-byte."""
        out = bytearray(size)
        covered_end = address
        for region in self.regions:
            if region["content"] is None:
                continue
            r_start = region["base"]
            r_end = r_start + region["size"]
            s, e = max(address, r_start), min(address + size, r_end)
            if s >= e:
                continue
            if s > covered_end:
                raise Unreadable("0x%x+%#x uncovered at 0x%x..0x%x"
                                 % (address, size, covered_end, s))
            out[s - address:e - address] = region["content"][s - r_start:e - r_start]
            covered_end = max(covered_end, e)
        if covered_end < address + size:
            raise Unreadable("0x%x+%#x uncovered at 0x%x..0x%x"
                             % (address, size, covered_end, address + size))
        return bytes(out)

    def read_u64(self, address):
        return read_le(self.read(address, 8), 0, 8)

    def read_u32(self, address):
        return read_le(self.read(address, 4), 0, 4)

    def read_u16(self, address):
        return read_le(self.read(address, 2), 0, 2)

    def region_with_content(self, address, size):
        """The single region covering [address, address+size) with content present."""
        for region in self.regions:
            if region["base"] <= address and address + size <= region["base"] + region["size"]:
                return region
        return None


def read_snapshot(path):
    """Load one snapshot file; named refusals mirror the engine reader."""
    with open(path, "rb") as handle:
        data = handle.read()
    if len(data) < HEADER_SIZE or data[:8] != SNAPSHOT_MAGIC:
        raise SnapshotError("kBadMagic", "not a sheller snapshot")
    version = read_le(data, 8, 4)
    if version not in (1, 2):
        raise SnapshotError("kUnsupportedVersion", "version %d" % version)
    bitness = data[12]
    if bitness != 64:
        raise SnapshotError("kBitnessMismatch", "bitness %d, this reader consumes 64-bit" % bitness)
    region_count = read_le(data, 16, 4)

    offset = HEADER_SIZE
    if offset + REGISTERS_SIZE > len(data):
        raise SnapshotError("kTruncated", "register block cut short")
    registers = {
        "rip": read_le(data, offset + 128, 8),
        "rflags": read_le(data, offset + 136, 8),
    }
    offset += REGISTERS_SIZE
    if offset + METADATA_SIZE > len(data):
        raise SnapshotError("kTruncated", "metadata block cut short")
    metadata = {
        "peb_address": read_le(data, offset, 8),
        "teb_address": read_le(data, offset + 8, 8),
        "image_base": read_le(data, offset + 16, 8),
        "entry_address": read_le(data, offset + 24, 8),
    }
    offset += METADATA_SIZE

    regions = []
    for _ in range(region_count):
        if offset + REGION_RECORD_SIZE > len(data):
            raise SnapshotError("kTruncated", "region record cut short")
        base = read_le(data, offset, 8)
        size = read_le(data, offset + 8, 8)
        protection = read_le(data, offset + 16, 4)
        region_type = read_le(data, offset + 20, 4)
        content_flag = data[offset + 24]
        offset += REGION_RECORD_SIZE
        if content_flag not in (0, 1):
            raise SnapshotError("kBadContent", "content flag %d at base 0x%x" % (content_flag, base))
        content = None
        if content_flag == 1:
            if offset + size > len(data):
                raise SnapshotError("kTruncated", "region payload cut short at base 0x%x" % base)
            content = data[offset:offset + size]
            offset += size
        regions.append({"base": base, "size": size, "protection": protection,
                        "type": region_type, "content": content})

    pending = None
    if version == 2:
        if data[offset:offset + 8] != PENDING_MARKER:
            raise SnapshotError("kBadPending", "v2 file does not carry the pending marker")
        offset += 8
        if offset + 4 > len(data):
            raise SnapshotError("kTruncated", "pending name length cut short")
        name_len = read_le(data, offset, 4)
        offset += 4
        if name_len > MAX_PENDING_NAME_BYTES:
            raise SnapshotError("kBadPending", "pending name %d bytes over the bound" % name_len)
        if offset + name_len + 4 > len(data):
            raise SnapshotError("kTruncated", "pending name cut short")
        name = data[offset:offset + name_len].decode("utf-8", errors="replace")
        offset += name_len
        pending_bitness = data[offset]
        if pending_bitness != 64:
            raise SnapshotError("kBadPending", "pending bitness %d" % pending_bitness)
        offset += 4  # bitness + 3 reserved
        if offset + 8 > len(data):
            raise SnapshotError("kTruncated", "pending payload length cut short")
        payload_len = read_le(data, offset, 8)
        offset += 8
        if payload_len > MAX_PENDING_MODULE_BYTES:
            raise SnapshotError("kBadPending", "pending payload %d bytes over the bound" % payload_len)
        if offset + payload_len > len(data):
            raise SnapshotError("kTruncated", "pending payload cut short")
        pending = {"name": name, "bitness": pending_bitness,
                   "bytes": data[offset:offset + payload_len]}

    return World(version, regions, registers, metadata, pending)


# ---------------------------------------------------------------------------
# Module enumeration: the engine's Ldr walk
# ---------------------------------------------------------------------------


def fold_module_name(world, address, length_bytes):
    """Mirror of the engine's fold_module_name: narrow-ASCII vs UTF-16 told
    apart by content, folded to lowercase ASCII, '?' for non-ASCII."""
    read_count = min(length_bytes, MODULE_NAME_BYTES)
    if read_count == 0:
        return ""
    try:
        raw = world.read(address, read_count)
    except Unreadable:
        return ""
    narrow = length_bytes <= MODULE_NAME_BYTES and all(0x20 <= b <= 0x7E for b in raw)
    if narrow:
        return raw.decode("ascii").lower()
    out = []
    for i in range(min(length_bytes // 2, MODULE_NAME_BYTES - 1)):
        try:
            wide = world.read_u16(address + 2 * i)
        except Unreadable:
            break
        folded = wide + 32 if (ord("A") <= wide <= ord("Z")) else wide
        out.append(chr(folded) if folded <= 0x7F else "?")
    return "".join(out)


def walk_ldr_chain(world, head_address, node_offset):
    """One Ldr chain, walked by Flink; entries carry name/base/size in the
    engine's fold. Named unresolvable on the first unreadable step."""
    entries = []
    visited = set()
    link = head_address
    for _ in range(MAX_MODULE_IMAGES):
        if link == 0 or link in visited:
            break
        visited.add(link)
        entry_base = link - node_offset
        try:
            dll_base = world.read_u64(entry_base + LDR_DLLBASE)
            image_size = world.read_u32(entry_base + LDR_SIZEOFIMAGE)
            name_len = world.read_u16(entry_base + LDR_NAME_LENGTH)
            name_buffer = world.read_u64(entry_base + LDR_NAME_BUFFER)
        except Unreadable as exc:
            return None, "entry read failed at 0x%x (%s)" % (entry_base, exc.detail)
        if dll_base != 0 and image_size != 0:
            entries.append({"name": fold_module_name(world, name_buffer, name_len),
                            "base": dll_base, "size": image_size})
        try:
            link = world.read_u64(link)
        except Unreadable as exc:
            return None, "flink read failed at 0x%x (%s)" % (link, exc.detail)
    return entries, None


def read_guest_string(world, address, max_bytes):
    """NUL-terminated UTF-16 string read, decoded to a folded ASCII line."""
    raw = world.read(address, max_bytes)
    chars = []
    for i in range(0, len(raw) - 1, 2):
        wide = raw[i] | (raw[i + 1] << 8)
        if wide == 0:
            break
        chars.append(chr(wide) if wide <= 0x7F else "?")
    return "".join(chars).lower()


def enumerate_ldr(world):
    """The three chains per world, plus the named failure when the walk cannot
    be grounded (TEB/PEB/Ldr pointers or a chain entry unreadable)."""
    chains = {}
    failure = None
    try:
        peb = world.read_u64(world.metadata["teb_address"] + TEB_PEB_OFFSET)
        ldr = world.read_u64(peb + 0x18)
    except Unreadable as exc:
        return None, "teb/peb/ldr grounding failed (%s)" % exc.detail
    for head_offset, node_offset, name in zip(LDR_HEAD_OFFSETS, LDR_ENTRY_NODE_OFFSET,
                                              LDR_CHAIN_NAMES):
        entries, error = walk_ldr_chain(world, ldr + head_offset, node_offset)
        if error is not None:
            failure = "ldr.%s: %s" % (name, error)
            break
        chains[name] = entries
    return (None, failure) if failure is not None else (chains, None)


# ---------------------------------------------------------------------------
# In-memory PE parsing
# ---------------------------------------------------------------------------


class PeImage:
    def __init__(self, image_base, size_of_image, sections, reloc_qwords, iat_slots):
        self.image_base = image_base
        self.size_of_image = size_of_image
        self.sections = sections  # [{name, rva, vsize}]
        self.reloc_qwords = reloc_qwords  # {rva} covered by DIR64 entries
        self.iat_slots = iat_slots  # {rva: bound value}


def parse_pe(image):
    """Parse a memory-resident PE32+ image; None names an unparseable header
    (the caller classifies the module's diffs as cause-uncertain)."""
    try:
        if len(image) < 0x40 or image[0:2] != b"MZ":
            return None
        pe_offset = read_le(image, 0x3C, 4)
        if pe_offset + 24 > len(image) or image[pe_offset:pe_offset + 4] != b"PE\0\0":
            return None
        section_count = read_le(image, pe_offset + 6, 2)
        optional = pe_offset + 24
        optional_size = read_le(image, pe_offset + 20, 2)
        if optional + optional_size > len(image) or read_le(image, optional, 2) != 0x20B:
            return None
        image_base = read_le(image, optional + 24, 8)
        size_of_image = read_le(image, optional + 56, 4)
        dd_count = read_le(image, optional + 108, 4)
        dd_base = optional + 112

        def directory(index):
            if index >= dd_count:
                return 0, 0
            return (read_le(image, dd_base + 8 * index, 4),
                    read_le(image, dd_base + 8 * index + 4, 4))

        sections = []
        table = optional + optional_size
        for i in range(section_count):
            at = table + 40 * i
            if at + 40 > len(image):
                return None
            raw_name = image[at:at + 8].split(b"\0", 1)[0]
            sections.append({"name": raw_name.decode("latin-1"),
                             "rva": read_le(image, at + 12, 4),
                             "vsize": read_le(image, at + 8, 4)})

        reloc_rva, reloc_size = directory(5)
        reloc_qwords = set()
        if reloc_rva and reloc_size:
            at = reloc_rva
            end = min(reloc_rva + reloc_size, len(image))
            while at + 8 <= end:
                page_rva = read_le(image, at, 4)
                block_size = read_le(image, at + 4, 4)
                if block_size < 8 or at + block_size > end:
                    break
                for i in range(8, block_size, 2):
                    entry = read_le(image, at + i, 2)
                    if entry >> 12 == 10:  # IMAGE_REL_BASED_DIR64
                        reloc_qwords.add(page_rva + (entry & 0xFFF))
                at += block_size

        iat_slots = {}
        import_rva, _ = directory(1)
        if import_rva:
            at = import_rva
            for _ in range(4096):  # bounded: import descriptors are finite
                if at + 20 > len(image):
                    break
                first_thunk = read_le(image, at + 16, 4)
                if (read_le(image, at, 4) == 0 and read_le(image, at + 12, 4) == 0
                        and first_thunk == 0):
                    break
                name_rva = read_le(image, at + 12, 4)
                import_name = read_cstring(image, name_rva)
                if first_thunk:
                    for i in range(8192):
                        slot_rva = first_thunk + 8 * i
                        if slot_rva + 8 > len(image):
                            break
                        bound = read_le(image, slot_rva, 8)
                        if bound == 0:
                            break
                        iat_slots[slot_rva] = {"bound": bound, "name": import_name}
                at += 20
        return PeImage(image_base, size_of_image, sections, reloc_qwords, iat_slots)
    except Unreadable:
        return None


def read_cstring(image, offset, cap=256):
    """NUL-terminated ASCII import-module name; None when it cannot be read
    in full (out of range or unterminated) - the slot keeps its identity
    marked unknown instead of guessing."""
    if offset >= len(image):
        return None
    window = image[offset:min(offset + cap, len(image))]
    cut = window.find(b"\0")
    if cut < 0:
        return None
    return window[:cut].decode("latin-1").lower()


# ---------------------------------------------------------------------------
# Guest values for the infrastructure domains
# ---------------------------------------------------------------------------


def module_by_name(modules, import_name):
    """The loaded module a folded import name refers to (extension optional)."""
    if not import_name:
        return None
    wanted = {import_name}
    if import_name.endswith(".dll"):
        wanted.add(import_name[:-4])
    else:
        wanted.add(import_name + ".dll")
    for m in modules:
        if m["name"] in wanted:
            return m
    return None


def terminal_module(modules, value):
    """The module whose span contains the bound value, or None."""
    for m in modules:
        if m["base"] <= value < m["base"] + m["size"]:
            return m
    return None


def merge_ranges(ranges):
    """Merge touching/overlapping [start, end) windows; unchanged gaps stay."""
    out = []
    for start, end in sorted(ranges):
        if out and start <= out[-1][1]:
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end])
    return [(s, e) for s, e in out]


def diff_windows(data_a, data_b):
    """Differing windows over the common length: aligned qword offsets plus
    byte runs for the sub-qword residual - a section whose only difference
    sits in its last bytes still reports it. Length inequality is reported
    separately as the tail flag."""
    common = min(len(data_a), len(data_b))
    qwords = []
    for i in range(common // 8):
        off = 8 * i
        if data_a[off:off + 8] != data_b[off:off + 8]:
            qwords.append(off)
    runs = []
    run_start = None
    for i in range((common // 8) * 8, common):
        if data_a[i] != data_b[i]:
            if run_start is None:
                run_start = i
        elif run_start is not None:
            runs.append((run_start, i))
            run_start = None
    if run_start is not None:
        runs.append((run_start, common))
    return qwords, runs, (len(data_a) != len(data_b))


# ---------------------------------------------------------------------------
# The diff
# ---------------------------------------------------------------------------


class Diff:
    def __init__(self, capture, crafted):
        self.capture = capture
        self.crafted = crafted
        self.modules = {"capture": [], "crafted": []}  # name-keyed per world
        self.chains = {"capture": None, "crafted": None}
        self.chain_failure = {"capture": None, "crafted": None}
        self.aligned = []
        self.entries = []

    # -- module set + alignment -------------------------------------------

    def build_module_sets(self):
        for side, world in (("capture", self.capture), ("crafted", self.crafted)):
            chains, failure = enumerate_ldr(world)
            self.chains[side] = chains
            self.chain_failure[side] = failure
            if chains is not None:
                seen = set()
                for entry in chains["load"]:
                    if entry["name"] not in seen:
                        seen.add(entry["name"])
                        self.modules[side].append(entry)

    def align(self):
        if self.chains["capture"] is None or self.chains["crafted"] is None:
            self.entries.append({
                "domain": "module_image", "classification": CLASS_UNRESOLVABLE,
                "note": "module grounding failed: %s" % (
                    self.chain_failure["capture"] or self.chain_failure["crafted"]),
            })
            return
        capture_names = {m["name"] for m in self.modules["capture"]}
        crafted_names = {m["name"] for m in self.modules["crafted"]}
        for name in sorted(capture_names | crafted_names):
            in_capture, in_crafted = name in capture_names, name in crafted_names
            if in_capture != in_crafted:
                self.entries.append({
                    "domain": "module_set", "classification": CLASS_EXPECTED,
                    "module": name, "present": "capture" if in_capture else "crafted",
                })
                continue
            a = next(m for m in self.modules["capture"] if m["name"] == name)
            b = next(m for m in self.modules["crafted"] if m["name"] == name)
            self.aligned.append((a, b))

    # -- module image domain ----------------------------------------------

    def diff_images(self):
        for a, b in self.aligned:
            try:
                image_a = self.capture.read(a["base"], a["size"])
            except Unreadable as exc:
                self._cause_uncertain(a, b, None, "capture image unreadable: %s" % exc.detail)
                continue
            try:
                image_b = self.crafted.read(b["base"], b["size"])
            except Unreadable as exc:
                self._cause_uncertain(a, b, None, "crafted image unreadable: %s" % exc.detail)
                continue
            pe_a = parse_pe(image_a)
            pe_b = parse_pe(image_b)
            if pe_a is None or pe_b is None:
                self._cause_uncertain(
                    a, b, (image_a, image_b),
                    "PE headers unparseable (%s)" % ("capture" if pe_a is None else "crafted"),
                    identity_uncertain=True)
                continue
            self._diff_parsed(a, b, image_a, image_b, pe_a, pe_b)

    def _cause_uncertain(self, a, b, images, note, identity_uncertain=False):
        """Same-name module whose diffs cannot be attributed: still emitted,
        never skipped (the .data-diff acceptance must hold everywhere)."""
        entry = {
            "domain": "module_image", "classification": CLASS_CAUSE_UNCERTAIN,
            "module": a["name"], "note": note,
            "capture_size": a["size"], "crafted_size": b["size"],
            "capture_base": hexaddr(a["base"]), "crafted_base": hexaddr(b["base"]),
        }
        if images is not None:
            offsets, runs, tail = diff_windows(images[0], images[1])
            windows = [(o, o + 8) for o in offsets] + list(runs)
            windows.sort()
            entry["diff_count"] = len(windows) + (1 if tail else 0)
            if windows:
                first_start, first_end = windows[0]
                entry["first_offset"] = hexaddr(first_start)
                entry["capture_addr"] = hexaddr(a["base"] + first_start)
                entry["crafted_addr"] = hexaddr(b["base"] + first_start)
                entry["_ranges"] = {
                    "capture": merge_ranges([(a["base"] + s, a["base"] + e)
                                             for s, e in windows]),
                    "crafted": merge_ranges([(b["base"] + s, b["base"] + e)
                                             for s, e in windows]),
                }
            if tail:
                entry["note"] = (entry["note"] + "; size differs"
                                 if "note" in entry else "size differs")
        if identity_uncertain:
            entry["identity_uncertain"] = True
        self.entries.append(entry)

    def _diff_parsed(self, a, b, image_a, image_b, pe_a, pe_b):
        base_delta = (a["base"] - b["base"]) % (1 << 64)
        if pe_a.size_of_image != pe_b.size_of_image:
            self.entries.append({
                "domain": "module_image", "classification": CLASS_CANDIDATE,
                "module": a["name"], "section": None,
                "capture_size": pe_a.size_of_image, "crafted_size": pe_b.size_of_image,
                "note": "size_of_image differs",
            })
        sections_a = {s["name"]: s for s in pe_a.sections}
        sections_b = {s["name"]: s for s in pe_b.sections}
        for name in sorted(set(sections_a) | set(sections_b)):
            sa, sb = sections_a.get(name), sections_b.get(name)
            if sa is None or sb is None:
                missing = "capture" if sa is None else "crafted"
                self.entries.append({
                    "domain": "module_image", "classification": CLASS_CANDIDATE,
                    "module": a["name"], "section": name,
                    "note": "section present on %s only" % missing,
                })
                continue
            end_a, end_b = sa["rva"] + sa["vsize"], sb["rva"] + sb["vsize"]
            if max(end_a, end_b) > min(len(image_a), len(image_b)):
                self.entries.append({
                    "domain": "module_image", "classification": CLASS_CANDIDATE,
                    "module": a["name"], "section": name,
                    "note": "section span exceeds the mapped image; not comparable",
                })
                continue
            bytes_a = image_a[sa["rva"]:end_a]
            bytes_b = image_b[sb["rva"]:end_b]
            qword_offsets, residual_runs, tail = diff_windows(bytes_a, bytes_b)
            if tail:
                self.entries.append({
                    "domain": "module_image", "classification": CLASS_CANDIDATE,
                    "module": a["name"], "section": name,
                    "capture_size": sa["vsize"], "crafted_size": sb["vsize"],
                    "note": "section virtual size differs",
                })
            # classification -> (windows, note); windows are section-relative
            # [start, end) pairs - interest ranges carry these actual windows,
            # never the whole section, so a read of unchanged bytes in the
            # same section cannot mark the entry.
            grouped = {}
            # PE pointer slots need not be qword-aligned. Classify each at
            # its declared RVA before comparing the remaining ordinary bytes.
            common = min(len(bytes_a), len(bytes_b))
            covered = bytearray(common)
            pointer_offsets = {
                rva - section["rva"]
                for pe, section in ((pe_a, sa), (pe_b, sb))
                for rva in pe.reloc_qwords | set(pe.iat_slots)
                if 0 <= rva - section["rva"] <= common - 8
            }
            for offset in sorted(pointer_offsets):
                if any(covered[offset:offset + 8]):
                    continue
                covered[offset:offset + 8] = b"\x01" * 8
                if bytes_a[offset:offset + 8] == bytes_b[offset:offset + 8]:
                    continue
                rva = sa["rva"] + offset
                value_a = read_le(image_a, rva, 8)
                value_b = read_le(image_b, sb["rva"] + offset, 8)
                classification, note = self._classify_qword(pe_a, pe_b, rva, value_a,
                                                            value_b, base_delta,
                                                            self.modules["capture"],
                                                            self.modules["crafted"],
                                                            sb["rva"] + offset)
                grouped.setdefault((classification, note), []).append((offset, offset + 8))
            # Subtract pointer spans from ordinary diff windows, including
            # slots crossing two windows, so no byte is classified twice.
            for start, end in ([(o, o + 8) for o in qword_offsets] + residual_runs):
                at = start
                while at < end:
                    if covered[at]:
                        at += 1
                        continue
                    run_start = at
                    while at < end and not covered[at]:
                        at += 1
                    if bytes_a[run_start:at] != bytes_b[run_start:at]:
                        grouped.setdefault((CLASS_CANDIDATE, None), []).append((run_start, at))
            for (classification, note), windows in sorted(
                    grouped.items(), key=lambda item: (item[0][0], item[0][1] or "")):
                windows.sort()
                first_start, first_end = windows[0]
                entry = {
                    "domain": "module_image", "classification": classification,
                    "module": a["name"], "section": name,
                    "diff_count": len(windows),
                    "first_offset": hexaddr(sa["rva"] + first_start),
                    "capture_addr": hexaddr(a["base"] + sa["rva"] + first_start),
                    "crafted_addr": hexaddr(b["base"] + sb["rva"] + first_start),
                    "capture_sha256": sha256_hex(bytes_a),
                    "crafted_sha256": sha256_hex(bytes_b),
                    "_ranges": {
                        "capture": merge_ranges([(a["base"] + sa["rva"] + s,
                                                  a["base"] + sa["rva"] + e)
                                                 for s, e in windows]),
                        "crafted": merge_ranges([(b["base"] + sb["rva"] + s,
                                                  b["base"] + sb["rva"] + e)
                                                 for s, e in windows]),
                    },
                }
                if note:
                    entry["note"] = note
                self.entries.append(entry)

    @staticmethod
    def _classify_qword(pe_a, pe_b, rva_a, value_a, value_b, base_delta,
                        modules_a, modules_b, rva_b=None):
        """Returns (classification, optional note)."""
        if rva_b is None:
            rva_b = rva_a
        reloc_covered = rva_a in pe_a.reloc_qwords or rva_b in pe_b.reloc_qwords
        if reloc_covered:
            delta = (value_a - value_b) % (1 << 64)
            if delta == base_delta % (1 << 64):
                return CLASS_EXPECTED_RELOC, None
            return CLASS_CANDIDATE_RELOC_ANOMALY, None
        slot_a = pe_a.iat_slots.get(rva_a)
        slot_b = pe_b.iat_slots.get(rva_b)
        if slot_a is not None or slot_b is not None:
            if slot_a is None or slot_b is None:
                return CLASS_CAUSE_UNCERTAIN, "import slot missing on one side"
            identity_a, identity_b = slot_a["name"], slot_b["name"]
            if not identity_a or not identity_b:
                # the slot is an import but its referenced module is not even
                # nameable: insufficient evidence, never "expected"
                return CLASS_CAUSE_UNCERTAIN, "import slot identity unreadable"
            if identity_a.lower().removesuffix(".dll") != identity_b.lower().removesuffix(".dll"):
                return CLASS_CANDIDATE_IMPORT_ANOMALY, "import identities differ"
            ref_a = module_by_name(modules_a, identity_a)
            ref_b = module_by_name(modules_b, identity_b)
            if ref_a is not None and ref_b is not None:
                ok = (ref_a["base"] <= value_a < ref_a["base"] + ref_a["size"]
                      and ref_b["base"] <= value_b < ref_b["base"] + ref_b["size"])
                return ((CLASS_EXPECTED_IMPORT, None) if ok
                        else (CLASS_CANDIDATE_IMPORT_ANOMALY, None))
            if ref_a is None and ref_b is None:
                # unresolved on both sides (api-set contract or a forwarder):
                # the binding must terminate in the same module on both worlds
                term_a = terminal_module(modules_a, value_a)
                term_b = terminal_module(modules_b, value_b)
                ok = (term_a is not None and term_b is not None
                      and term_a["name"] == term_b["name"])
                return ((CLASS_EXPECTED_IMPORT, "import name unresolved; terminal target match")
                        if ok else (CLASS_CANDIDATE_IMPORT_ANOMALY, None))
            # the referenced module exists on one side only: its set differs
            return CLASS_CANDIDATE_IMPORT_ANOMALY, None
        return CLASS_CANDIDATE, None

    # -- infrastructure domain --------------------------------------------

    def diff_infrastructure(self):
        self._diff_peb()
        self._diff_teb()
        self._diff_kusd()
        self._diff_ldr_chains()

    def _diff_peb(self):
        peb_a, peb_b = self.capture.metadata["peb_address"], self.crafted.metadata["peb_address"]
        for name, offset, width in PEB_FIELDS:
            try:
                value_a = self.capture.read(peb_a + offset, width)
                value_b = self.crafted.read(peb_b + offset, width)
            except Unreadable as exc:
                self.entries.append({
                    "domain": "infrastructure", "classification": CLASS_UNRESOLVABLE,
                    "target": "peb.%s" % name, "note": exc.detail,
                })
                continue
            if value_a != value_b:
                self.entries.append({
                    "domain": "infrastructure", "classification": CLASS_CANDIDATE,
                    "target": "peb.%s" % name,
                    "capture": value_a.hex(), "crafted": value_b.hex(),
                    "_ranges": {"capture": [(peb_a + offset, peb_a + offset + width)],
                                "crafted": [(peb_b + offset, peb_b + offset + width)]},
                })
        # ImageBaseAddress: self-consistency against each side's own metadata.
        for side, world in (("capture", self.capture), ("crafted", self.crafted)):
            peb = world.metadata["peb_address"]
            try:
                value = world.read_u64(peb + PEB_IMAGE_BASE_OFFSET)
            except Unreadable as exc:
                self.entries.append({
                    "domain": "infrastructure", "classification": CLASS_UNRESOLVABLE,
                    "target": "peb.image_base(%s)" % side, "note": exc.detail,
                })
                continue
            if value != world.metadata["image_base"]:
                self.entries.append({
                    "domain": "infrastructure", "classification": CLASS_CANDIDATE,
                    "target": "peb.image_base(%s)" % side,
                    "actual": hexaddr(value), "expected": hexaddr(world.metadata["image_base"]),
                    "note": "%s PEB.ImageBaseAddress != metadata image_base" % side,
                    "_ranges": {side: [(peb + PEB_IMAGE_BASE_OFFSET,
                                        peb + PEB_IMAGE_BASE_OFFSET + 8)]},
                })

    def _diff_teb(self):
        for side, world in (("capture", self.capture), ("crafted", self.crafted)):
            teb = world.metadata["teb_address"]
            checks = (("teb.self(%s)" % side, TEB_SELF_OFFSET, teb),
                      ("teb.peb(%s)" % side, TEB_PEB_OFFSET, world.metadata["peb_address"]))
            for target, offset, expected in checks:
                try:
                    value = world.read_u64(teb + offset)
                except Unreadable as exc:
                    self.entries.append({
                        "domain": "infrastructure", "classification": CLASS_UNRESOLVABLE,
                        "target": target, "note": exc.detail,
                    })
                    continue
                if value != expected:
                    self.entries.append({
                        "domain": "infrastructure", "classification": CLASS_CANDIDATE,
                        "target": target,
                        "actual": hexaddr(value), "expected": hexaddr(expected),
                        "note": "%s self-check: TEB field != metadata" % side,
                        "_ranges": {side: [(teb + offset, teb + offset + 8)]},
                    })

    def _diff_kusd(self):
        regions = {}
        for side, world in (("capture", self.capture), ("crafted", self.crafted)):
            region = world.region_with_content(KUSD_ADDRESS, KUSD_PAGE_BYTES)
            if region is None or region["content"] is None:
                regions[side] = None
            else:
                regions[side] = region["content"]
        if regions["capture"] is None or regions["crafted"] is None:
            missing = [s for s in ("capture", "crafted") if regions[s] is None]
            self.entries.append({
                "domain": "infrastructure", "classification": CLASS_UNRESOLVABLE,
                "target": "kusd.region",
                "note": "no region with content covering 0x7ffe0000 on %s" % ", ".join(missing),
            })
            return
        page_a, page_b = regions["capture"], regions["crafted"]

        def field_bytes(data, offset, width):
            return data[offset:offset + width]

        for name, offset, width in KUSD_VOLATILE_FIELDS:
            value_a, value_b = field_bytes(page_a, offset, width), field_bytes(page_b, offset, width)
            if value_a != value_b:
                self.entries.append({
                    "domain": "infrastructure", "classification": CLASS_EXPECTED_VOLATILE,
                    "target": "kusd.%s" % name,
                    "capture": value_a.hex(), "crafted": value_b.hex(),
                    "_ranges": {"capture": [(KUSD_ADDRESS + offset, KUSD_ADDRESS + offset + width)],
                                "crafted": [(KUSD_ADDRESS + offset, KUSD_ADDRESS + offset + width)]},
                })
        for name, offset, width in KUSD_STRUCTURAL_FIELDS:
            value_a = read_guest_string(self.capture, KUSD_ADDRESS + offset, width)
            value_b = read_guest_string(self.crafted, KUSD_ADDRESS + offset, width)
            if value_a != value_b:
                self.entries.append({
                    "domain": "infrastructure", "classification": CLASS_CANDIDATE,
                    "target": "kusd.%s" % name,
                    "capture": value_a, "crafted": value_b,
                    "_ranges": {"capture": [(KUSD_ADDRESS + offset, KUSD_ADDRESS + offset + width)],
                                "crafted": [(KUSD_ADDRESS + offset, KUSD_ADDRESS + offset + width)]},
                })

    def _diff_ldr_chains(self):
        for side in ("capture", "crafted"):
            if self.chains[side] is None:
                self.entries.append({
                    "domain": "infrastructure", "classification": CLASS_UNRESOLVABLE,
                    "target": "ldr.chains(%s)" % side, "note": self.chain_failure[side],
                })
                return
        for chain in LDR_CHAIN_NAMES:
            names_a = [e["name"] for e in self.chains["capture"][chain]]
            names_b = [e["name"] for e in self.chains["crafted"][chain]]
            if len(names_a) != len(names_b):
                self.entries.append({
                    "domain": "infrastructure", "classification": CLASS_CANDIDATE,
                    "target": "ldr.%s" % chain,
                    "detail": "count capture=%d crafted=%d" % (len(names_a), len(names_b)),
                })
            for i, (na, nb) in enumerate(zip(names_a, names_b)):
                if na != nb:
                    self.entries.append({
                        "domain": "infrastructure", "classification": CLASS_CANDIDATE,
                        "target": "ldr.%s" % chain,
                        "detail": "order differs at index %d: capture=%s crafted=%s"
                                  % (i, na, nb),
                    })
                    break

    # -- pending block (v2 pairs) -----------------------------------------

    def diff_pending(self):
        if self.capture.pending is None or self.crafted.pending is None:
            return
        pa, pb = self.capture.pending, self.crafted.pending
        if pa["name"] != pb["name"] or pa["bytes"] != pb["bytes"]:
            self.entries.append({
                "domain": "pending", "classification": CLASS_CANDIDATE,
                "note": "pending blocks differ (name or bytes)",
                "capture_name": pa["name"], "crafted_name": pb["name"],
                "capture_sha256": sha256_hex(pa["bytes"]),
                "crafted_sha256": sha256_hex(pb["bytes"]),
            })

    # -- interest ----------------------------------------------------------

    def apply_interest(self, report_path, side):
        try:
            with open(report_path, "rb") as handle:
                report_bytes = handle.read()
            report = json.loads(report_bytes.decode("utf-8"))
        except (OSError, ValueError) as exc:
            raise NamedError("interest report unreadable: %s" % exc)
        detail = {}
        try:
            detail = report["events"]["detail"]
            if not isinstance(detail, list):
                raise ValueError("detail is not a list")
        except (KeyError, TypeError, ValueError) as exc:
            raise NamedError("interest report carries no events.detail list (%s)" % exc)
        intervals = []
        level = "counts-or-empty"
        for entry in detail:
            if not isinstance(entry, dict) or entry.get("type") != "mem-read":
                continue
            if "tid" in entry:
                level = "full"
            elif level != "full":
                level = "semantic"
            try:
                start = int(entry["addr"], 16)
                size = int(entry["size"])
            except (KeyError, ValueError) as exc:
                raise NamedError("mem-read entry missing addr/size (%s)" % exc)
            if size > 0:
                intervals.append((start, start + size))
        insufficient = not intervals
        matched = 0
        if not insufficient:
            for entry in self.entries:
                ranges = entry.get("_ranges", {}).get(side)
                if not ranges:
                    continue
                if side_side_hit(ranges, intervals):
                    # semantic-level reports detail only sample->system-module
                    # reads; infrastructure targets stay counts-only there.
                    if level != "full" and entry["domain"] == "infrastructure":
                        continue
                    entry["interest"] = True
                    matched += 1
        notes = []
        if insufficient:
            notes.append("report carries no per-address mem-read detail; "
                         "this is not a no-hit verdict")
        elif level != "full":
            notes.append("semantic-level report: infrastructure targets lack "
                         "per-address detail; only module domains matched")
        interest = {
            "side": side,
            "report_sha256": sha256_hex(report_bytes),
            "report_level": level,
            "detail_state": "insufficient" if insufficient else "sufficient",
            "matched": matched,
        }
        if notes:
            interest["note"] = "; ".join(notes)
        return interest


def side_side_hit(ranges, intervals):
    for start, end in ranges:
        for rs, re_ in intervals:
            if rs < end and start < re_:
                return True
    return False


# ---------------------------------------------------------------------------
# Report rendering (deterministic by construction)
# ---------------------------------------------------------------------------


def strip_internal(entries):
    out = []
    for entry in entries:
        cleaned = {k: v for k, v in entry.items() if not k.startswith("_")}
        out.append(cleaned)
    return out


def sort_key(entry):
    classification = entry.get("classification", "")
    offset = entry.get("first_offset")
    return (0 if entry.get("interest") else 1,
            DOMAIN_ORDER[entry["domain"]],
            entry.get("module", ""),
            entry.get("section") or "",
            entry.get("target") or "",
            classification,
            int(offset, 16) if offset else 0)


def render_report(diff, interest):
    report = {
        "format": "world-diff/1",
        "inputs": {
            "capture": {"sha256": diff.capture_sha256, "version": diff.capture.version},
            "crafted": {"sha256": diff.crafted_sha256, "version": diff.crafted.version},
        },
        "worlds": {
            "capture": {
                "peb": hexaddr(diff.capture.metadata["peb_address"]),
                "teb": hexaddr(diff.capture.metadata["teb_address"]),
                "image_base": hexaddr(diff.capture.metadata["image_base"]),
                "region_count": len(diff.capture.regions),
            },
            "crafted": {
                "peb": hexaddr(diff.crafted.metadata["peb_address"]),
                "teb": hexaddr(diff.crafted.metadata["teb_address"]),
                "image_base": hexaddr(diff.crafted.metadata["image_base"]),
                "region_count": len(diff.crafted.regions),
            },
        },
        "modules": {
            "aligned": [
                {
                    "name": a["name"],
                    "capture_base": hexaddr(a["base"]), "crafted_base": hexaddr(b["base"]),
                    "capture_size": a["size"], "crafted_size": b["size"],
                }
                for a, b in diff.aligned
            ],
            "only_capture": sorted({m["name"] for m in diff.modules["capture"]}
                                   - {m["name"] for m in diff.modules["crafted"]}),
            "only_crafted": sorted({m["name"] for m in diff.modules["crafted"]}
                                   - {m["name"] for m in diff.modules["capture"]}),
        },
    }
    if diff.capture.pending is not None and diff.crafted.pending is not None:
        report["pending"] = {
            "equal": (diff.capture.pending["bytes"] == diff.crafted.pending["bytes"]
                      and diff.capture.pending["name"] == diff.crafted.pending["name"]),
            "sha256": sha256_hex(diff.capture.pending["bytes"]),
        }
    entries = sorted(diff.entries, key=sort_key)
    report["entries"] = strip_internal(entries)
    if interest is not None:
        report["interest"] = interest
    return json.dumps(report, indent=2, ensure_ascii=True) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Deterministic diff report for a capture snapshot vs a crafted container.")
    parser.add_argument("capture", help="capture world snapshot file")
    parser.add_argument("crafted", help="crafted world snapshot file")
    parser.add_argument("--interest", help="behavior report JSON whose mem-read "
                                           "addresses annotate diff entries")
    parser.add_argument("--interest-side", choices=("capture", "crafted"),
                        help="which world the interest report came from (required with --interest)")
    parser.add_argument("--output", help="write the report here (default: stdout)")
    args = parser.parse_args(argv)

    if args.interest is not None and args.interest_side is None:
        print("world_diff: missing --interest-side: the report's addresses are only "
              "valid in its own world's coordinates", file=sys.stderr)
        return 2
    if args.interest is None and args.interest_side is not None:
        print("world_diff: --interest-side given without --interest", file=sys.stderr)
        return 2

    try:
        capture = read_snapshot(args.capture)
        crafted = read_snapshot(args.crafted)
    except SnapshotError as exc:
        print("world_diff: %s" % exc, file=sys.stderr)
        return 2
    if capture.version != crafted.version:
        print("world_diff: version-mismatch: capture is v%d, crafted is v%d; the pair "
              "must share the format version" % (capture.version, crafted.version),
              file=sys.stderr)
        return 2

    diff = Diff(capture, crafted)
    diff.capture_sha256 = sha256_hex(open(args.capture, "rb").read())
    diff.crafted_sha256 = sha256_hex(open(args.crafted, "rb").read())
    diff.build_module_sets()
    diff.align()
    diff.diff_images()
    diff.diff_infrastructure()
    diff.diff_pending()

    interest = None
    if args.interest is not None:
        try:
            interest = diff.apply_interest(args.interest, args.interest_side)
        except NamedError as exc:
            print("world_diff: %s" % exc, file=sys.stderr)
            return 2

    # Internal determinism assertion: the same diff state must render twice to
    # the same bytes (no hidden iteration order, no volatile fields).
    first = render_report(diff, interest)
    second = render_report(diff, interest)
    assert first == second, "report rendering is not deterministic"
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(first)
    else:
        sys.stdout.write(first)
    return 0


if __name__ == "__main__":
    sys.exit(main())
