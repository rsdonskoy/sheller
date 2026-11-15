#!/usr/bin/env python3
"""Negative cases for the equivalence-baseline machine adjudication: an
unaccepted class, a scale-cap overrun, a structural-shape class, a one-sided
structural entry, a pair-identity mismatch and an unknown domain must each
fail; the happy path must pass. Portable by design."""

import importlib.util
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

tool = Path(__file__).resolve().parents[1] / "tools" / "accept_residuals.py"
spec = importlib.util.spec_from_file_location("accept_residuals", tool)
ar = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ar)

PAIR = {
    "inputs": {"capture": {"sha256": "capture-reference", "version": 3},
               "crafted": {"version": 3}},
    "pending": {"equal": True,
                "sha256": "3b4abff6fa72fbc1f89eab066f4564d38ad33e9fb9e6bccc4e77966f87a0f175"},
    "modules": {"aligned": [
        {"name": "kernel32.dll", "capture_size": 831488, "crafted_size": 831488},
        {"name": "kernelbase.dll", "capture_size": 4231168, "crafted_size": 4231168},
        {"name": "ntdll.dll", "capture_size": 2535424, "crafted_size": 2535424}]},
}
for module in PAIR["modules"]["aligned"]:
    module["capture_build_id"] = module["crafted_build_id"] = "build-" + module["name"]

ACCEPTED = {
    "schema": 2,
    "pair": {"capture_sha256": "capture-reference", "format_version": 3,
             "module_build_ids": {m["name"]: m["capture_build_id"]
                                  for m in PAIR["modules"]["aligned"]},
             "payload_sha256": "3b4abff6fa72fbc1f89eab066f4564d38ad33e9fb9e6bccc4e77966f87a0f175",
             "module_sizes": {"kernel32.dll": 831488, "kernelbase.dll": 4231168,
                              "ntdll.dll": 2535424}},
    "runtime_init_caps": {"kernelbase.dll|.data": 248, "kernel32.dll|.data": 23,
                          "kernelbase.dll|fothk": 1, "kernel32.dll|fothk": 1,
                          "ntdll.dll|.data": 474, "ntdll.dll|.mrdata": 71,
                          "ntdll.dll|fothk": 3},
    "reloc_anomaly_caps": {"ntdll.dll|.data": 8},
    "infrastructure_accepted": {"peb.process_heap": "layout", "peb.ldr": "layout"},
    "module_set_accepted": {"apphelp.dll": "shim infra", "ucrtbase.dll": "runner crt",
                            "sheller_run.exe": "arrival", "sheller_run_x.ex": "capture temp"},
    "module_set_sides": {"apphelp.dll": "capture", "ucrtbase.dll": "crafted",
                         "sheller_run.exe": "crafted", "sheller_run_x.ex": "capture"},
}
for cap_field, range_field in (("runtime_init_caps", "runtime_init_ranges"),
                             ("reloc_anomaly_caps", "reloc_anomaly_ranges")):
    ACCEPTED[range_field] = {key: [[0x1000, 0x3000]] for key in ACCEPTED[cap_field]}


def entry(domain="module_image", module="kernelbase.dll", section=".data",
          classification="candidate", diff_count=1, **extra):
    out = {"domain": domain, "classification": classification, "diff_count": diff_count}
    if module:
        out["module"] = module
    if section:
        out["section"] = section
    if domain == "module_image" and type(diff_count) is int:
        out["diff_ranges"] = [[0x1000 + i * 8, 0x1008 + i * 8] for i in range(diff_count)]
    if domain == "module_set":
        out["present"] = "capture"
    out.update(extra)
    return out


class AcceptResidualsTest(unittest.TestCase):
    def run_adjudicate(self, entries, accepted=None, report_extra=None):
        report = copy.deepcopy(PAIR)
        report["entries"] = entries
        if report_extra:
            report.update(report_extra)
        lines = []
        ok = ar.adjudicate(report, accepted or ACCEPTED, lines)
        return ok, lines

    def test_happy_path_passes(self):
        ok, lines = self.run_adjudicate([
            entry(module="kernelbase.dll", section=".data", diff_count=248),
            entry(module="kernel32.dll", section=".data", diff_count=23),
            entry(module="ntdll.dll", section=".data", diff_count=474),
            entry(module="ntdll.dll", section=".mrdata", diff_count=71),
            entry(module="ntdll.dll", section=".data",
                  classification="candidate-reloc-anomaly", diff_count=8),
            entry(module="kernelbase.dll", section="fothk"),
            entry(module="kernel32.dll", section="fothk"),
            entry(domain="infrastructure", module=None, section=None,
                  classification="expected-volatile", target="kusd.interrupt_time"),
            entry(domain="infrastructure", module=None, section=None,
                  target="peb.process_heap"),
            entry(domain="module_set", module="apphelp.dll", section=None,
                  classification="expected"),
        ])
        self.assertTrue(ok, "\n".join(lines))

    def test_unaccepted_class_fails(self):
        ok, lines = self.run_adjudicate([entry(module="ntdll.dll", section=".text")])
        self.assertFalse(ok)
        self.assertTrue(any("unaccepted module_image candidate" in l for l in lines), lines)

    def test_scale_cap_overrun_fails(self):
        ok, lines = self.run_adjudicate([
            entry(module="kernelbase.dll", section=".data", diff_count=249)])
        self.assertFalse(ok)
        self.assertTrue(any("scale cap exceeded" in l for l in lines), lines)

    def test_structural_shape_class_fails(self):
        # an import-binding identity anomaly in a delay slot: structural,
        # never acceptable even inside an accepted module/section
        ok, lines = self.run_adjudicate([
            entry(module="kernelbase.dll", section=".didat",
                  classification="candidate-import-anomaly")])
        self.assertFalse(ok)
        self.assertTrue(any("structural-shape class" in l for l in lines), lines)

    def test_one_sided_section_entry_fails(self):
        ok, lines = self.run_adjudicate([
            entry(module="kernelbase.dll", section=".text",
                  note="section present on capture only")])
        self.assertFalse(ok)
        self.assertTrue(any("one-sided section (structural)" in l for l in lines), lines)

    def test_ldr_membership_of_unknown_member_fails(self):
        # a membership difference for a member the accepted set does not list
        # surfaces through the module_set check (the chain echo inherits its
        # classification, the member itself is the adjudicated fact)
        ok, lines = self.run_adjudicate([
            entry(domain="module_set", module="mystery.dll", section=None,
                  classification="expected"),
            entry(domain="infrastructure", module=None, section=None,
                  classification="expected", target="ldr.load",
                  detail="membership: mystery.dll present on crafted only")])
        self.assertFalse(ok)
        self.assertTrue(any("unaccepted module_set entry: mystery.dll" in l
                            for l in lines), lines)

    def test_nt_system_root_fails(self):
        ok, lines = self.run_adjudicate([
            entry(domain="infrastructure", module=None, section=None,
                  target="kusd.nt_system_root")])
        self.assertFalse(ok)
        self.assertTrue(any("unaccepted infrastructure candidate" in l for l in lines), lines)

    def test_entry_name_residual_beyond_cap_fails(self):
        ok, lines = self.run_adjudicate([
            entry(domain="infrastructure", module=None, section=None,
                  target="ldr.load", detail="order differs at index 0: capture=a crafted=b"),
            entry(domain="infrastructure", module=None, section=None,
                  target="ldr.load", detail="count differs for runner.dll: capture=1 crafted=2"),
        ])
        self.assertFalse(ok)
        self.assertTrue(any("unaccepted" in l for l in lines), lines)

    def test_pair_identity_mismatch_fails(self):
        ok, lines = self.run_adjudicate([entry(module="kernelbase.dll", section=".data")],
                                        report_extra={
                                            "pending": {"equal": True, "sha256": "deadbeef"}})
        self.assertFalse(ok)
        self.assertTrue(any("pair identity mismatch" in l for l in lines), lines)

    def test_module_size_mismatch_fails(self):
        report_extra = {"modules": {"aligned": [
            {"name": "kernelbase.dll", "capture_size": 4231168, "crafted_size": 999}]}}
        ok, lines = self.run_adjudicate([], report_extra=report_extra)
        self.assertFalse(ok)
        self.assertTrue(any("capture/crafted sizes differ" in l for l in lines), lines)

    def test_cause_uncertain_fails(self):
        ok, lines = self.run_adjudicate([
            entry(domain="infrastructure", module=None, section=None,
                  classification="cause-uncertain", target="peb.process_heap")])
        self.assertFalse(ok)
        self.assertTrue(any("unresolved infrastructure entry" in l for l in lines), lines)

    def test_unknown_domain_fails(self):
        ok, lines = self.run_adjudicate([entry(domain="somewhere_new", module=None, section=None)])
        self.assertFalse(ok)
        self.assertTrue(any("unknown report domain" in l for l in lines), lines)

    def test_empty_report_is_not_a_pass(self):
        ok, lines = self.run_adjudicate([])
        self.assertFalse(ok)
        self.assertTrue(any("no entries" in l for l in lines), lines)

    def test_main_exit_codes(self):
        with tempfile.TemporaryDirectory(prefix="accept_residuals_") as tmp:
            report = Path(tmp) / "report.json"
            accepted = Path(tmp) / "accepted.json"
            report.write_text(json.dumps(dict(PAIR, entries=[
                entry(module="kernelbase.dll", section=".data", diff_count=1)])),
                encoding="utf-8")
            accepted.write_text(json.dumps(ACCEPTED), encoding="utf-8")
            self.assertEqual(ar.main(["ar", str(report), str(accepted)]), 0)
            report.write_text(json.dumps({"entries": [
                entry(module="ntdll.dll", section=".text")]}), encoding="utf-8")
            self.assertEqual(ar.main(["ar", str(report), str(accepted)]), 1)

    def test_classifications_fail_closed_in_every_domain(self):
        for domain in ("module_image", "infrastructure", "pending"):
            for classification in ("new-class", "cause-uncertain", "unresolvable", ""):
                with self.subTest(domain=domain, classification=classification):
                    self.assertFalse(self.run_adjudicate([
                        entry(domain=domain, classification=classification,
                              target="peb.process_heap")])[0])

    def test_counts_accumulate_and_equality_passes(self):
        self.assertTrue(self.run_adjudicate([entry(diff_count=124), entry(diff_count=124)])[0])
        self.assertFalse(self.run_adjudicate([entry(diff_count=124), entry(diff_count=125)])[0])
        self.assertFalse(self.run_adjudicate([
            entry(module="ntdll.dll", classification="candidate-reloc-anomaly", diff_count=5),
            entry(module="ntdll.dll", classification="candidate-reloc-anomaly", diff_count=4)])[0])

    def test_positions_and_numeric_counts_are_required(self):
        for fields in ({"diff_count": -1}, {"diff_count": True}, {"diff_count": "1"},
                       {"diff_ranges": []}, {"diff_ranges": [[0x4000, 0x4008]]},
                       {"diff_ranges": [[0x1000, 0x1000]]}):
            self.assertFalse(self.run_adjudicate([entry(**fields)])[0])

    def test_build_and_format_identity_cannot_be_replaced_by_equal_size(self):
        for side in ("capture", "crafted"):
            report = copy.deepcopy(PAIR)
            report["modules"]["aligned"][0][side + "_build_id"] = "other-build"
            self.assertFalse(self.run_adjudicate([entry()], report_extra=report)[0])
            report = copy.deepcopy(PAIR)
            report["inputs"][side]["version"] = 2
            self.assertFalse(self.run_adjudicate([entry()], report_extra=report)[0])

    def test_duplicate_aligned_module_is_rejected(self):
        report = copy.deepcopy(PAIR)
        report["modules"]["aligned"].append(report["modules"]["aligned"][0])
        self.assertFalse(self.run_adjudicate([entry()], report_extra=report)[0])

    def test_ldr_order_is_never_an_arrival_name_exception(self):
        self.assertFalse(self.run_adjudicate([
            entry(domain="infrastructure", target="ldr.load",
                  detail="order differs at index 0: capture=ntdll.dll crafted=kernel32.dll")])[0])

    def test_accepted_one_sided_module_must_stay_on_its_accepted_side(self):
        self.assertFalse(self.run_adjudicate([
            entry(domain="module_set", module="apphelp.dll", section=None,
                  classification="expected", present="crafted")])[0])

    def test_repeated_infrastructure_residual_exceeds_one_field_cap(self):
        item = entry(domain="infrastructure", target="peb.process_heap")
        self.assertTrue(self.run_adjudicate([item])[0])
        self.assertFalse(self.run_adjudicate([item, item])[0])


if __name__ == "__main__":
    unittest.main()
