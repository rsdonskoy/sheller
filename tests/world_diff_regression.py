#!/usr/bin/env python3
"""Boundary regressions complementing the Writer-backed world_diff fixtures."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


tool = Path(__file__).resolve().parents[1] / "tools" / "world_diff.py"
spec = importlib.util.spec_from_file_location("world_diff", tool)
wd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wd)


def world():
    return wd.World(1, [], {}, {"peb_address": 0, "teb_address": 0, "image_base": 0}, None)


def pe(size=24, reloc=(), slots=None, rva=0):
    return wd.PeImage(0, size, [{"name": ".data", "rva": rva, "vsize": 24}],
                      set(reloc), slots or {})


class WorldDiffRegression(unittest.TestCase):
    def classify(self, slot_a, slot_b):
        modules_a = [{"name": "foo.dll", "base": 0x3000, "size": 0x1000},
                     {"name": "bar.dll", "base": 0x5000, "size": 0x1000}]
        modules_b = [{"name": "foo.dll", "base": 0x7000, "size": 0x1000},
                     {"name": "bar.dll", "base": 0x9000, "size": 0x1000}]
        return wd.Diff._classify_qword(pe(slots=slot_a), pe(slots=slot_b),
                                      0, 0x3001, 0x7001, 0, modules_a, modules_b)[0]

    def test_import_identities_must_match_on_both_sides(self):
        # Both values lie in foo, but crafted's descriptor actually names bar.
        self.assertEqual(self.classify({0: {"name": "foo.dll"}},
                                       {0: {"name": "bar.dll"}}),
                         wd.CLASS_CANDIDATE_IMPORT_ANOMALY)

    def test_unreadable_or_missing_identity_on_either_side_is_uncertain(self):
        known = {0: {"name": "foo.dll"}}
        for unknown in ({}, {0: {"name": None}}, {0: {"name": ""}}):
            for left, right in ((known, unknown), (unknown, known)):
                with self.subTest(left=left, right=right):
                    self.assertEqual(self.classify(left, right), wd.CLASS_CAUSE_UNCERTAIN)

    def test_equivalent_import_names_still_match(self):
        self.assertEqual(self.classify({0: {"name": "foo"}},
                                       {0: {"name": "foo.dll"}}), wd.CLASS_EXPECTED_IMPORT)

    def test_unknown_image_interest_covers_later_windows_on_each_side(self):
        diff = wd.Diff(world(), world())
        a = {"name": "erased.dll", "base": 0x1000, "size": 25}
        b = {"name": "erased.dll", "base": 0x2000, "size": 25}
        capture, crafted = bytearray(25), bytearray(25)
        capture[0], capture[16], capture[24] = 1, 2, 3
        diff._cause_uncertain(a, b, (capture, crafted), "PE headers unparseable", True)
        self.assertEqual(diff.entries[0]["diff_count"], 3)
        with tempfile.TemporaryDirectory(prefix="world_diff_regression_") as tmp:
            report = Path(tmp) / "interest.json"
            for side, base in (("capture", 0x1000), ("crafted", 0x2000)):
                for offset, expected in ((16, 1), (24, 1), (8, 0)):
                    with self.subTest(side=side, offset=offset):
                        diff.entries[0].pop("interest", None)
                        report.write_text(json.dumps({"events": {"detail": [
                            {"type": "mem-read", "tid": 1, "addr": hex(base + offset),
                             "size": 1}]}}), encoding="utf-8")
                        self.assertEqual(diff.apply_interest(report, side)["matched"], expected)

    def compare(self, capture, crafted, pe_a, pe_b):
        diff = wd.Diff(world(), world())
        a = {"name": "test.dll", "base": 0x1000, "size": len(capture)}
        b = {"name": "test.dll", "base": 0x2000, "size": len(crafted)}
        diff._diff_parsed(a, b, capture, crafted, pe_a, pe_b)
        return diff.entries

    def test_unaligned_dir64_uses_its_actual_rva_without_duplicate_candidates(self):
        capture, crafted = bytearray(24), bytearray(24)
        capture[1:9] = (0x1800).to_bytes(8, "little")
        crafted[1:9] = (0x2800).to_bytes(8, "little")
        entries = self.compare(capture, crafted, pe(reloc=(1,)), pe(reloc=(1,)))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["classification"], wd.CLASS_EXPECTED_RELOC)
        self.assertEqual(entries[0]["first_offset"], "0x1")
        self.assertEqual(entries[0]["diff_count"], 1)

    def test_unaligned_slot_leaves_neighboring_data_and_anomalies_visible(self):
        capture, crafted = bytearray(24), bytearray(24)
        capture[0], capture[23] = 1, 2
        capture[1:9] = (0x1800).to_bytes(8, "little")
        crafted[1:9] = (0x2800).to_bytes(8, "little")
        capture[9:17] = (0x1900).to_bytes(8, "little")
        crafted[9:17] = (0x9999).to_bytes(8, "little")
        entries = self.compare(capture, crafted, pe(reloc=(1, 9)), pe(reloc=(1, 9)))
        by_class = {e["classification"]: e for e in entries}
        self.assertEqual(set(by_class), {wd.CLASS_EXPECTED_RELOC,
                                        wd.CLASS_CANDIDATE_RELOC_ANOMALY, wd.CLASS_CANDIDATE})
        self.assertEqual(by_class[wd.CLASS_CANDIDATE]["diff_count"], 2)
        self.assertEqual(by_class[wd.CLASS_CANDIDATE_RELOC_ANOMALY]["first_offset"], "0x9")

    def test_section_relative_matching_uses_each_sides_pointer_rva(self):
        capture, crafted = bytearray(64), bytearray(64)
        capture[1:9] = (0x1800).to_bytes(8, "little")
        crafted[17:25] = (0x2800).to_bytes(8, "little")
        entries = self.compare(capture, crafted, pe(64, reloc=(1,)),
                               pe(64, reloc=(17,), rva=16))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["classification"], wd.CLASS_EXPECTED_RELOC)
        self.assertEqual(entries[0]["crafted_addr"], "0x2011")


if __name__ == "__main__":
    unittest.main()
