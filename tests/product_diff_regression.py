#!/usr/bin/env python3
"""Classification regressions for tools/product_diff.py.

Synthesizes a pair of image-form products and two equivalent hashed module
tables (same exports at different bases - a cross-anchor pair), plants the
two cause classes plus the five negative shapes D3 pins, and asserts the
classification and the exit code together:

  world-binding     bound-both-sides (same module+export identity at
                    per-world bases), record-identity (a repaired name
                    record against the other side's resolved export, module
                    checked through the descriptor name), and
                    record-identity-both-sides (two world-corroborated
                    records naming the same export)
  recovery-content  one-sided-span / same-module-different-target /
                    different-module / shape-coincidence /
                    known-slot-wrong-binding / record-name-unverifiable
                    (the qodercn review's guard: a record shape whose name
                    no world's export set knows is never a binding)
  cause-uncertain   module span without a terminating export; world-region
                    membership (no applicable target-mapping evidence)
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
spec = importlib.util.spec_from_file_location("product_diff", TOOLS / "product_diff.py")
pd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pd)

BASE_A = 0x180000000
ALPHA_A = 0x7FF900000000
ALPHA_B = 0x7FFB00000000
BETA_A = 0x7FFA00000000
BETA_B = 0x7FFC00000000

ALPHA_FN_RVA = 0x1100
ALPHA_OTHER_RVA = 0x2200
BETA_FN_RVA = 0x1500

MODULES_A = [
    {"name": "alpha.dll", "base": hex(ALPHA_A), "size": "0x10000",
     "exports": {"alpha_fn": hex(ALPHA_FN_RVA), "alpha_other": hex(ALPHA_OTHER_RVA)}},
    {"name": "beta.dll", "base": hex(BETA_A), "size": "0x10000",
     "exports": {"beta_fn": hex(BETA_FN_RVA)}},
]
MODULES_B = [
    {"name": "alpha.dll", "base": hex(ALPHA_B), "size": "0x10000",
     "exports": {"alpha_fn": hex(ALPHA_FN_RVA), "alpha_other": hex(ALPHA_OTHER_RVA)}},
    {"name": "beta.dll", "base": hex(BETA_B), "size": "0x10000",
     "exports": {"beta_fn": hex(BETA_FN_RVA)}},
]


def make_table(path, modules, schema=2):
    table = {"schema": schema, "note": "product_diff_regression",
             "modules": modules,
             "regions": [{"base": "0x300000000", "size": "0x100000",
                          "role": "heap"}]}
    Path(path).write_text(json.dumps(table), encoding="utf-8")
    return str(path)


IMAGE_SIZE = 0x4000


def make_product(slots, records, dir_path, name, section_name=".text",
                 size_of_image=IMAGE_SIZE, total_size=IMAGE_SIZE):
    """A flat PE32+ image: one section, an import descriptor naming
    alpha.dll with its IAT at 0x2100, values from `slots` (rva -> u64) and
    in-image name records from `records` (rva -> text). total_size is the
    byte length on disk; size_of_image goes in the header - product_diff
    requires them equal, and the size-mismatch rejection test passes them
    unequal on purpose."""
    image = bytearray(total_size)
    w16 = lambda r, v: image.__setitem__(slice(r, r + 2), struct.pack("<H", v))
    w32 = lambda r, v: image.__setitem__(slice(r, r + 4), struct.pack("<I", v))
    w64 = lambda r, v: image.__setitem__(slice(r, r + 8), struct.pack("<Q", v))
    wstr = lambda r, t: image.__setitem__(slice(r, r + len(t) + 1), t.encode() + b"\0")

    w16(0, 0x5A4D)
    w32(0x3C, 0x40)
    image[0x40:0x44] = b"PE\0\0"
    w16(0x44, 0x8664)
    w16(0x46, 1)          # one section
    w16(0x54, 0xF0)       # SizeOfOptionalHeader
    w16(0x56, 0x0022)     # characteristics
    w32(0x58, 0x20B)      # PE32+ magic (optional header starts at 0x58)
    w32(0x58 + 0x10, 0x2000)   # AddressOfEntryPoint
    w64(0x58 + 0x18, BASE_A)   # ImageBase (PE32+ field is 8 bytes)
    w32(0x58 + 0x38, size_of_image)  # SizeOfImage
    w32(0x58 + 0x6C, 16)       # NumberOfRvaAndSizes
    w32(0x58 + 0x70 + 8 * 1, 0x2000)  # DataDirectory[1] import dir
    w32(0x58 + 0x70 + 8 * 1 + 4, 40)
    # Section .text header at 0x148 (optional 0x58 + 0xF0).
    wstr(0x148, section_name)
    w32(0x148 + 8, IMAGE_SIZE - 0x1000)   # virtual size
    w32(0x148 + 12, 0x1000)               # virtual address
    w32(0x148 + 16, IMAGE_SIZE - 0x1000)  # size of raw data
    w32(0x148 + 20, 0x1000)               # pointer to raw data
    # Import descriptor at 0x2000; IAT slots at 0x2100..; dll name at 0x2200.
    w32(0x2000 + 12, 0x2200)  # Name
    w32(0x2000 + 16, 0x2100)  # FirstThunk
    wstr(0x2200, "alpha.dll")
    for rva, value in slots.items():
        w64(rva, value)
    for rva, text in records.items():
        w16(rva, 0)  # hint
        wstr(rva + 2, text)
    # Every product needs a non-zero body byte past the descriptors so the
    # header page reads as a mapped image.
    image[0x3000] = 0x90
    out = Path(dir_path) / name
    out.write_bytes(bytes(image))
    return out


class ProductDiffRegression(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="sheller_product_diff")
        self.dir = Path(self._tmp.name)
        # Slot plan (IAT first-thunk array starts at 0x2100):
        slots_a = {
            0x2100: ALPHA_A + ALPHA_FN_RVA,   # bound-both-sides
            0x2108: 0x2600,                   # record "alpha_fn" -> record-identity
            0x2110: ALPHA_A + ALPHA_FN_RVA,   # one-sided-span
            0x2118: ALPHA_A + ALPHA_FN_RVA,   # same-module-different-target
            0x2120: ALPHA_A + ALPHA_FN_RVA,   # different-module
            0x2128: 0x7777666655554444,       # shape-coincidence
            0x2130: 0x2620,                   # record "alpha_fn" -> known-slot-wrong-binding
            0x2138: ALPHA_A + ALPHA_FN_RVA,   # cause-uncertain (module gap)
            0x2140: 0x300000000 + 0x1234,     # cause-uncertain (region member)
            0x2148: 0x2700,                   # record-record same world-known name
            0x2150: 0x2720,                   # record-record, unverifiable name
            0x2158: 0x2740,                   # solo record, unverifiable name
        }
        slots_b = {
            0x2100: ALPHA_B + ALPHA_FN_RVA,
            0x2108: ALPHA_B + ALPHA_FN_RVA,
            0x2110: 0x7FFEDEADBE00,           # unmapped on side B
            0x2118: ALPHA_B + ALPHA_OTHER_RVA,
            0x2120: BETA_B + BETA_FN_RVA,
            0x2128: 0x9999888800001111,       # unmapped both sides
            0x2130: ALPHA_B + ALPHA_OTHER_RVA,
            0x2138: ALPHA_B + 0x333,          # inside alpha's span, no export
            0x2140: 0x300000000 + 0x456,
            0x2148: 0x2760,                   # record-record: same world-known name
            0x2150: 0x2740,                   # record-record: same unverifiable name
            0x2158: 0x2760,                   # solo record, unverifiable on side A
        }
        # Both sides carry every record byte at the same RVAs: only the slots
        # that reference them differ.
        records = {0x2600: "alpha_fn", 0x2620: "alpha_fn",
                   0x2700: "alpha_fn", 0x2720: "zzzz_nope",
                   0x2740: "zzzz_nope", 0x2760: "alpha_fn"}
        self.slots_a = slots_a
        self.records = records
        self.pa = make_product(slots_a, records, self.dir, "a.bin")
        self.pb = make_product(slots_b, records, self.dir, "b.bin")
        self.table_a = make_table(self.dir / "table_a.json", MODULES_A)
        self.table_b = make_table(self.dir / "table_b.json", MODULES_B)

    def tearDown(self):
        self._tmp.cleanup()

    def run_tool(self, pa=None, pb=None, table_a=None, table_b=None):
        output = self.dir / "report.json"
        code = pd.main([str(pa or self.pa), str(pb or self.pb),
                        "--world-a-table", table_a or self.table_a,
                        "--world-b-table", table_b or self.table_b,
                        "--output", str(output)])
        report = json.loads(output.read_text(encoding="utf-8"))
        return code, report

    def diff_at(self, report, rva):
        for entry in report["diffs"]:
            if entry["rva"] == rva:
                return entry
        raise AssertionError("no diff entry at rva 0x%x" % rva)

    def test_planted_classes_and_exit(self):
        code, report = self.run_tool()
        by_rva = {0x2100: ("world-binding", "bound-both-sides"),
                  0x2108: ("world-binding", "record-identity"),
                  0x2110: ("recovery-content", "one-sided-span"),
                  0x2118: ("recovery-content", "same-module-different-target"),
                  0x2120: ("recovery-content", "different-module"),
                  0x2128: ("recovery-content", "shape-coincidence"),
                  0x2130: ("recovery-content", "known-slot-wrong-binding"),
                  0x2138: ("cause-uncertain", "identity-unreadable"),
                  0x2140: ("cause-uncertain", "region-member"),
                  0x2148: ("world-binding", "record-identity-both-sides"),
                  0x2150: ("recovery-content", "record-name-unverifiable"),
                  0x2158: ("recovery-content", "record-name-unverifiable")}
        for rva, (cls, reason_prefix) in by_rva.items():
            entry = self.diff_at(report, rva)
            self.assertEqual(entry["class"], cls, "rva 0x%x: %s" % (rva, entry))
            self.assertTrue(entry["reason"].startswith(reason_prefix),
                            "rva 0x%x: %s" % (rva, entry))
        # Same module and export names rode the report for the bound slots.
        bound = self.diff_at(report, 0x2100)
        self.assertEqual(bound["module"], "alpha.dll")
        self.assertEqual(bound["function"], "alpha_fn")
        # No world-binding row may lack a module identity.
        for entry in report["diffs"]:
            if entry["class"] == "world-binding":
                self.assertTrue(entry.get("module"), entry)
        # The tool's own classification totals agree with the entry rows.
        self.assertEqual(report["classes"]["recovery-content"], 7)
        self.assertEqual(report["classes"]["cause-uncertain"], 2)
        self.assertEqual(report["verdict"]["exit"], 1)
        self.assertFalse(report["verdict"]["pass"])
        self.assertEqual(code, 1)

    def test_identical_pair_passes_with_exit_zero(self):
        # Same bytes on both sides: no diffs, shape checks pass, exit 0.
        pb2 = self.dir / "copy.bin"
        pb2.write_bytes(self.pa.read_bytes())
        output = self.dir / "report0.json"
        code = pd.main([str(self.pa), str(pb2),
                        "--world-a-table", self.table_a,
                        "--world-b-table", self.table_b,
                        "--output", str(output)])
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["diffs"], [])
        self.assertEqual(report["verdict"]["exit"], 0)
        self.assertTrue(report["verdict"]["pass"])
        self.assertEqual(code, 0)

    def test_shape_failure_alone_exits_nonzero(self):
        # A failing shape check (section name differs - the section header
        # bytes themselves become shape-coincidence rows) must exit 1 even
        # though no row carries a non-mechanical class: the shape gate is
        # independent of the class counts.
        pb2 = make_product(self.slots_a, self.records, self.dir,
                           "renamed.bin", section_name=".tEXt")
        output = self.dir / "report_shape.json"
        code = pd.main([str(self.pa), str(pb2),
                        "--world-a-table", self.table_a,
                        "--world-b-table", self.table_b,
                        "--output", str(output)])
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(report["diffs"])
        for entry in report["diffs"]:
            self.assertEqual(entry["class"], "recovery-content", entry)
            self.assertEqual(entry["reason"], "shape-coincidence", entry)
        self.assertFalse(report["shape"]["pass"])
        self.assertEqual(report["verdict"]["exit"], 1)
        self.assertEqual(code, 1)

    def test_named_rejections(self):
        # Size vs SizeOfImage mismatch is a named rejection (exit 2).
        mismatch = make_product({}, {}, self.dir, "mismatch.bin",
                                size_of_image=0x5000)
        code = pd.main([str(self.pa), str(mismatch),
                        "--world-a-table", self.table_a,
                        "--world-b-table", self.table_b])
        self.assertEqual(code, 2)
        # Unreadable product: named rejection.
        code = pd.main([str(self.dir / "missing.bin"), str(self.pb),
                        "--world-a-table", self.table_a,
                        "--world-b-table", self.table_b])
        self.assertEqual(code, 2)
        # Missing world metadata: named rejection.
        code = pd.main([str(self.pa), str(self.pb)])
        self.assertEqual(code, 2)
        # Malformed and stale-schema module tables: named rejections.
        bad = self.dir / "bad.json"
        bad.write_text("{}", encoding="utf-8")
        code = pd.main([str(self.pa), str(self.pb),
                        "--world-a-table", str(bad),
                        "--world-b-table", self.table_b])
        self.assertEqual(code, 2)
        old = self.dir / "old.json"
        old.write_text(json.dumps({"schema": 1, "modules": []}), encoding="utf-8")
        code = pd.main([str(self.pa), str(self.pb),
                        "--world-a-table", str(old),
                        "--world-b-table", self.table_b])
        self.assertEqual(code, 2)

    def test_module_table_image_file_with_hash_binding(self):
        # The schema-2 image_file channel: the table must carry the file's
        # sha256 and the tool verifies it before trusting the exports; a
        # wrong hash is a named rejection, a matching hash resolves the bound
        # slot through the parsed export table.
        image = bytearray(IMAGE_SIZE)
        w16 = lambda r, v: image.__setitem__(slice(r, r + 2), struct.pack("<H", v))
        w32 = lambda r, v: image.__setitem__(slice(r, r + 4), struct.pack("<I", v))
        image[0:2] = b"MZ"
        w32(0x3C, 0x40)
        image[0x40:0x44] = b"PE\0\0"
        w16(0x44, 0x8664)
        w16(0x46, 1)
        w16(0x54, 0xF0)
        w16(0x56, 0x0022)
        w32(0x58, 0x20B)
        w32(0x58 + 0x38, IMAGE_SIZE)  # SizeOfImage
        w32(0x58 + 0x70, 0x2000)      # DataDirectory[0] export dir RVA
        w32(0x58 + 0x70 + 4, 0x60)
        # Export directory at 0x2000: one name, EAT at 0x2080. File layout
        # equals memory layout here (flat image), and the section table
        # carries the mapping either way.
        w32(0x148 + 12, 0x1000)          # section VA
        w32(0x148 + 16, IMAGE_SIZE - 0x1000)  # section raw size
        w32(0x148 + 20, 0x1000)          # section raw pointer
        struct.pack_into("<I", image, 0x2000 + 20, 1)   # NumberOfFunctions @0x2014
        struct.pack_into("<I", image, 0x2000 + 24, 1)   # NumberOfNames @0x2018
        struct.pack_into("<I", image, 0x2000 + 28, 0x2080)  # EAT rva @0x201C
        struct.pack_into("<I", image, 0x2000 + 32, 0x2090)  # names rva @0x2020
        struct.pack_into("<I", image, 0x2000 + 36, 0x20A0)  # ordinals rva @0x2024
        image[0x2080:0x2084] = struct.pack("<I", ALPHA_FN_RVA)
        image[0x2090:0x2094] = struct.pack("<I", 0x20B0)
        image[0x20A0:0x20A2] = struct.pack("<H", 0)
        image[0x20B0:0x20B0 + 9] = b"alpha_fn\0"
        alpha_image = self.dir / "alpha_image.bin"
        alpha_image.write_bytes(bytes(image))
        good_hash = hashlib.sha256(bytes(image)).hexdigest()

        pa = make_product({0x2100: ALPHA_A + ALPHA_FN_RVA}, {}, self.dir,
                          "ia.bin")
        pb = make_product({0x2100: ALPHA_B + ALPHA_FN_RVA}, {}, self.dir,
                          "ib.bin")
        # Wrong hash: named rejection before any classification.
        table_bad = make_table(self.dir / "table_badhash.json", [
            {"name": "alpha.dll", "base": hex(ALPHA_A), "size": "0x4000",
             "image_file": str(alpha_image), "image_sha256": "0" * 64}])
        code = pd.main([str(pa), str(pb),
                        "--world-a-table", table_bad,
                        "--world-b-table", self.table_b])
        self.assertEqual(code, 2)
        # Missing hash on an image_file row: named rejection.
        table_nohash = make_table(self.dir / "table_nohash.json", [
            {"name": "alpha.dll", "base": hex(ALPHA_A), "size": "0x4000",
             "image_file": str(alpha_image)}])
        code = pd.main([str(pa), str(pb),
                        "--world-a-table", table_nohash,
                        "--world-b-table", self.table_b])
        self.assertEqual(code, 2)
        # Matching hash: the bound slot resolves through the parsed exports.
        table_good = make_table(self.dir / "table_goodhash.json", [
            {"name": "alpha.dll", "base": hex(ALPHA_A), "size": "0x4000",
             "image_file": str(alpha_image), "image_sha256": good_hash,
             "provenance": "regression fixture image"}])
        output = self.dir / "report_img.json"
        code = pd.main([str(pa), str(pb),
                        "--world-a-table", table_good,
                        "--world-b-table", self.table_b,
                        "--output", str(output)])
        report = json.loads(output.read_text(encoding="utf-8"))
        entry = self.diff_at(report, 0x2100)
        self.assertEqual(entry["class"], "world-binding")
        self.assertEqual(entry["function"], "alpha_fn")
        self.assertEqual(code, 0)  # the only planted diff is the bound slot
        # The world summary surfaces the parse status and the verified hash.
        summary = report["worlds"]["a"]["modules"][0]
        self.assertEqual(summary["parse_status"], "ok")
        self.assertEqual(summary["exports_count"], 1)
        self.assertEqual(summary["image_sha256"], good_hash)


if __name__ == "__main__":
    unittest.main()
