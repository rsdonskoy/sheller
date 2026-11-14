#!/usr/bin/env python3
"""Boundary regressions complementing the Writer-backed world_diff fixtures."""

import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch


tool = Path(__file__).resolve().parents[1] / "tools" / "world_diff.py"
spec = importlib.util.spec_from_file_location("world_diff", tool)
wd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wd)


def world():
    return wd.World(1, [], {}, {"peb_address": 0, "teb_address": 0, "image_base": 0}, None)


def pe(size=24, reloc=(), slots=None, rva=0, delay=None):
    return wd.PeImage(0, size, [{"name": ".data", "rva": rva, "vsize": 24}],
                      set(reloc), slots or {}, delay or {})


class SnapshotClockRegression(unittest.TestCase):
    def read_tail(self, tail):
        body = (wd.SNAPSHOT_MAGIC + struct.pack("<IB3xI4x", 3, 64, 0)
                + bytes(wd.REGISTERS_SIZE + wd.METADATA_SIZE))
        with patch("builtins.open", return_value=io.BytesIO(body + tail)):
            return wd.read_snapshot("memory.snap")

    def clock(self, version=1, blocks_per_tick=16, frequency=10000000):
        return wd.CLOCK_MARKER + struct.pack(
            "<II6Q6I", version, 72, 0, 150000, blocks_per_tick, frequency,
            0, 625, 1, 100, 24000000, 2400, 2400, 100)

    def test_v3_clock_refusals_match_engine_order(self):
        valid = self.clock()
        self.assertEqual(self.read_tail(valid).version, 3)
        for tail, expected in (
                (valid[:18], "kTruncated"),
                (valid + valid, "kBadClock"),
                (self.clock(version=2), "kBadClock"),
                (self.clock(blocks_per_tick=0), "kBadClock"),
                (self.clock(frequency=0), "kBadClock"),
                (b"X" * 10, "kBadClock"),
                (self.clock(version=2)[:18], "kBadClock")):
            with self.subTest(tail=tail, expected=expected):
                with self.assertRaises(wd.SnapshotError) as caught:
                    self.read_tail(tail)
                self.assertEqual(caught.exception.code, expected)

    def test_empty_pending_fields_are_rejected(self):
        for pending in (b"PXXXXXXX", wd.PENDING_MARKER + struct.pack("<I", 0),
                        wd.PENDING_MARKER + struct.pack("<I", 1) + b"x"
                        + struct.pack("<B3xQ", 64, 0)):
            with self.subTest(pending=pending):
                with self.assertRaises(wd.SnapshotError) as caught:
                    self.read_tail(pending + self.clock())
                self.assertEqual(caught.exception.code, "kBadPending")


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
        self.assertTrue(any(e.get("note") == "section RVA differs" for e in entries))
        entries = [e for e in entries if e.get("note") != "section RVA differs"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["classification"], wd.CLASS_EXPECTED_RELOC)
        self.assertEqual(entries[0]["crafted_addr"], "0x2011")


class DelayedImportClassification(unittest.TestCase):
    """The delayed-import recognition and its classification priority: a
    delay slot verifies by referenced identity FIRST - even when the
    relocation table covers the slot - and the pre-revision classifications
    for everything else stay untouched."""

    def classify_delay(self, delay_a, delay_b, reloc_a=(), reloc_b=()):
        modules_a = [{"name": "kernelbase.dll", "base": 0x3000, "size": 0x1000},
                     {"name": "kernel32.dll", "base": 0x5000, "size": 0x1000}]
        modules_b = [{"name": "kernelbase.dll", "base": 0x7000, "size": 0x1000},
                     {"name": "kernel32.dll", "base": 0x9000, "size": 0x1000}]
        # rva 0: capture value in kernelbase-a, crafted value in
        # kernelbase-b; the delta is NOT a base delta (0x3000 vs 0x7000
        # bases would make 0x4000 one) - the values differ arbitrarily, the
        # way a bound slot vs a differently-bound slot does
        return wd.Diff._classify_qword(pe(delay=delay_a, reloc=reloc_a),
                                       pe(delay=delay_b, reloc=reloc_b),
                                       0, 0x3001, 0x7001, 0, modules_a, modules_b)[0]

    def test_delay_slot_classifies_by_identity_even_under_reloc_coverage(self):
        # both worlds' reloc tables cover the slot AND the values are not a
        # base delta apart: the old order produced candidate-reloc-anomaly,
        # the identity-first revision reads the aligned referenced identity
        # and the in-span values - expected-import
        self.assertEqual(
            self.classify_delay({0: {"name": "kernelbase.dll"}},
                                {0: {"name": "kernelbase.dll"}},
                                reloc_a=(0,), reloc_b=(0,)),
            wd.CLASS_EXPECTED_IMPORT)

    def test_identity_confusion_stays_an_anomaly(self):
        # both values land in SOME resident span (kernelbase capture,
        # kernel32 crafted) but the referenced identities differ - the
        # import-anomaly verdict, never an any-span "expected"
        self.assertEqual(
            self.classify_delay({0: {"name": "kernelbase.dll"}},
                                {0: {"name": "kernel32.dll"}},
                                reloc_a=(0,), reloc_b=(0,)),
            wd.CLASS_CANDIDATE_IMPORT_ANOMALY)

    def test_unresolvable_name_verifies_by_terminal_module(self):
        # api-set/forwarder names on both sides: the terminal module must
        # match - the delay slots bind to the same endpoint on both worlds
        modules_a = [{"name": "kernelbase.dll", "base": 0x3000, "size": 0x1000}]
        modules_b = [{"name": "kernelbase.dll", "base": 0x7000, "size": 0x1000}]
        classification, _note = wd.Diff._classify_qword(
            pe(delay={0: {"name": "ext-ms-win-quirks-l1-1-0.dll"}}),
            pe(delay={0: {"name": "ext-ms-win-quirks-l1-1-0.dll"}}),
            0, 0x3001, 0x7001, 0, modules_a, modules_b)
        self.assertEqual(classification, wd.CLASS_EXPECTED_IMPORT)

    def test_unreadable_delay_identity_is_uncertain(self):
        self.assertEqual(
            self.classify_delay({0: {"name": None}}, {0: {"name": "kernelbase.dll"}}),
            wd.CLASS_CAUSE_UNCERTAIN)

    def test_delay_slot_missing_on_one_side_is_uncertain(self):
        self.assertEqual(
            self.classify_delay({0: {"name": "kernelbase.dll"}}, {}),
            wd.CLASS_CAUSE_UNCERTAIN)

    def test_non_delay_classifications_are_untouched(self):
        # a plain reloc slot (no delay coverage) keeps the pre-revision
        # verdicts exactly: base-delta -> expected-reloc, otherwise anomaly
        self.assertEqual(
            self.classify_delay({}, {}, reloc_a=(0,), reloc_b=(0,)),
            wd.CLASS_CANDIDATE_RELOC_ANOMALY)  # 0x3001 vs 0x7001: no base delta
        modules_a = [{"name": "kernelbase.dll", "base": 0x3000, "size": 0x1000}]
        modules_b = [{"name": "kernelbase.dll", "base": 0x7000, "size": 0x1000}]
        classification, _note = wd.Diff._classify_qword(
            pe(reloc=(0,)), pe(reloc=(0,)),
            0, 0x3001, 0x7001, (0x3001 - 0x7001) % (1 << 64), modules_a, modules_b)
        self.assertEqual(classification, wd.CLASS_EXPECTED_RELOC)


class ChainMultiplicityRegression(unittest.TestCase):
    def test_one_sided_duplicate_is_a_structural_candidate(self):
        diff = wd.Diff(world(), world())
        diff.chains = {
            "capture": {name: [] for name in wd.LDR_CHAIN_NAMES},
            "crafted": {name: [{"name": "apphelp.dll"}, {"name": "apphelp.dll"}]
                        for name in wd.LDR_CHAIN_NAMES},
        }
        diff._diff_ldr_chains()
        self.assertEqual(len(diff.entries), 3)
        self.assertTrue(all(e["classification"] == "candidate" for e in diff.entries))

    def test_equal_bytes_at_a_moved_section_still_report_shape(self):
        diff = wd.Diff(world(), world())
        module = {"name": "foo.dll", "base": 0, "size": 64}
        diff._diff_parsed(module, module, bytes(64), bytes(64), pe(rva=0), pe(rva=8))
        self.assertTrue(any(e.get("note") == "section RVA differs" for e in diff.entries))


class FoldModuleNameEncodingRegression(unittest.TestCase):
    @staticmethod
    def world_with_name(name_bytes):
        content = bytearray(0x100)
        content[0x80:0x80 + len(name_bytes)] = name_bytes
        region = {"base": 0x1000, "size": len(content), "content": bytes(content)}
        return wd.World(1, [region], {},
                        {"peb_address": 0, "teb_address": 0, "image_base": 0}, None)

    def test_legacy_narrow_and_utf16_names_fold_identically(self):
        # Current containers store Ldr names as UTF-16 (Length = bytes);
        # containers built before the shared-convention change stored narrow
        # ASCII (Length = the character count). The content sniff keeps the
        # legacy worlds readable: both shapes fold to the same lowercase name.
        narrow = b"ntdll.dll"
        self.assertEqual(
            wd.fold_module_name(self.world_with_name(narrow), 0x1080, len(narrow)),
            "ntdll.dll")
        wide = "kernelbase.dll".encode("utf-16-le")
        self.assertEqual(
            wd.fold_module_name(self.world_with_name(wide), 0x1080, len(wide)),
            "kernelbase.dll")


if __name__ == "__main__":
    unittest.main()
