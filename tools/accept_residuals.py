#!/usr/bin/env python3
"""Machine adjudication of a world_diff report against the versioned
accepted-residuals set (the snapshot-craft equivalence gate).

Usage:
    python tools/accept_residuals.py <report.json> <accepted-residuals.json>

The accepted set is a versioned JSON (schema 2) binding the pair identity
(reference capture digest, format, payload, PE build IDs and sizes) and every accepted residual entry: its
domain, module/section, position scope, scale cap and basis. The adjudication
consumes EVERY report entry against that set:

  1. pair identity: the report's pending payload digest and per-module sizes
     must match the accepted pair - the gate only judges its own build pair;
  2. domain exhaustion: every entry must be consumed by a known check per its
     domain and classification - an unknown domain/classification, an
     unresolvable/cause-uncertain entry, or a one-sided structural entry
     (section present on one side) fails the gate outright;
  3. runtime-initialization counts (R1/R2/R1b) must stay within the caps of
     the accepted set;
  4. structural-shape classes are rejected outright (import-identity
     anomalies, membership/order/count echoes outside the accepted set);
  5. negative cases (tests/accept_residuals_test.py) prove the gate fails on
     unaccepted classes, cap overruns, position swaps and pair mismatch.

Exits 0 only when the report passes; every violation prints a named line so
the failure output is complete.
"""
import json
import re
import sys

CANDIDATE_CLASSES = ("candidate", "candidate-reloc-anomaly", "candidate-import-anomaly")
CLASS_UNRESOLVABLE = "unresolvable"


def fail(lines, message):
    lines.append("FAIL: %s" % message)


def report_identity(report, accepted, lines):
    """Pair identity: the payload digest and per-module sizes pin the build
    pair the accepted set was quantified on."""
    ok = True
    pair = accepted["pair"]
    inputs = report.get("inputs", {})
    if (inputs.get("capture", {}).get("sha256") != pair.get("capture_sha256") or
            not pair.get("capture_sha256") or
            any(inputs.get(side, {}).get("version") != pair.get("format_version")
                for side in ("capture", "crafted"))):
        fail(lines, "pair identity mismatch: capture digest or format version")
        ok = False
    pending = report.get("pending", {})
    want = accepted["pair"]["payload_sha256"]
    got = pending.get("sha256")
    if pending.get("equal") is not True or got != want:
        fail(lines, "pair identity mismatch: pending sha256 %s != accepted %s "
                    "(equal=%s)" % (got, want, pending.get("equal")))
        ok = False
    sizes = accepted["pair"]["module_sizes"]
    aligned_modules = report.get("modules", {}).get("aligned", [])
    names = [m.get("name") for m in aligned_modules]
    if len(set(names)) != len(names) or set(names) != set(sizes):
        fail(lines, "pair identity: aligned module set differs or has duplicates")
        ok = False
    for module, want_size in sorted(sizes.items()):
        got_size = None
        for aligned in report.get("modules", {}).get("aligned", []):
            if aligned.get("name") == module:
                build_id = pair.get("module_build_ids", {}).get(module)
                if (not build_id or aligned.get("capture_build_id") != build_id or
                        aligned.get("crafted_build_id") != build_id):
                    fail(lines, "pair identity mismatch: module %s build id" % module)
                    ok = False
                got_size = aligned.get("capture_size")
                if got_size != aligned.get("crafted_size"):
                    fail(lines, "module %s: capture/crafted sizes differ (%s vs %s)"
                         % (module, aligned.get("capture_size"), aligned.get("crafted_size")))
                    ok = False
                break
        if got_size is None:
            fail(lines, "pair identity: module %s missing from the report" % module)
            ok = False
        elif got_size != want_size:
            fail(lines, "pair identity mismatch: module %s size %s != accepted %s"
                 % (module, got_size, want_size))
            ok = False
    return ok


def check_scope(entry, scopes, lines):
    key = "%s|%s" % (entry.get("module", "").lower(), entry.get("section", "").lower())
    count = entry.get("diff_count")
    ranges = entry.get("diff_ranges")
    allowed = scopes.get(key, [])
    if (type(count) is not int or count <= 0 or not isinstance(ranges, list) or
            len(ranges) != count or any(
                not isinstance(r, list) or len(r) != 2 or
                any(type(v) is not int for v in r) or r[0] < 0 or r[0] >= r[1]
                for r in ranges)):
        fail(lines, "invalid count/ranges: %s" % key)
        return False
    if any(not any(a <= start < end <= b for a, b in allowed) for start, end in ranges):
        fail(lines, "unaccepted position: %s" % key)
        return False
    return True


def adjudicate(report, accepted, lines):
    ok = report_identity(report, accepted, lines)
    entries = report.get("entries", [])
    if not isinstance(entries, list) or not entries:
        fail(lines, "report carries no entries - an empty report is not a pass")
        return False

    runtime_caps = accepted["runtime_init_caps"]
    anomaly_caps = accepted["reloc_anomaly_caps"]
    infra_accepted = accepted["infrastructure_accepted"]
    module_set_accepted = accepted["module_set_accepted"]
    module_set_sides = accepted["module_set_sides"]
    runtime_counts = {}
    anomaly_counts = {}
    infra_seen = set()
    module_set_seen = set()
    consumed = 0

    for entry in entries:
        domain = entry.get("domain")
        classification = entry.get("classification", "")
        if domain == "module_set":
            module = entry.get("module", "")
            if (classification == "expected" and module in module_set_accepted and
                    entry.get("present") == module_set_sides.get(module) and
                    module not in module_set_seen):
                module_set_seen.add(module)
                consumed += 1
                continue
            fail(lines, "unaccepted module_set entry: %s (%s)" % (module, classification))
            ok = False
            continue
        if domain == "pending":
            # world_diff emits this domain only when the pending blocks differ.
            fail(lines, "unaccepted pending difference")
            ok = False
            continue
        if domain == "module_image":
            module = (entry.get("module") or "").lower()
            section = (entry.get("section") or "").lower()
            if "section present on" in entry.get("note", ""):
                fail(lines, "one-sided section (structural): %s %s - %s"
                     % (module, section, entry.get("note")))
                ok = False
                continue
            if classification not in CANDIDATE_CLASSES:
                if classification in ("expected-reloc", "expected-import"):
                    consumed += 1
                else:
                    fail(lines, "unaccepted module_image classification: %s" % classification)
                    ok = False
                continue
            if classification == "candidate-import-anomaly":
                fail(lines, "structural-shape class in module_image: %s %s (import identity)"
                     % (module, section))
                ok = False
                continue
            if classification == "candidate-reloc-anomaly":
                cap = anomaly_caps.get("%s|%s" % (module, section))
                if cap is None:
                    fail(lines, "unaccepted reloc-anomaly: %s %s" % (module, section))
                    ok = False
                    continue
                if not check_scope(entry, accepted.get("reloc_anomaly_ranges", {}), lines):
                    ok = False
                    continue
                anomaly_counts["%s|%s" % (module, section)] = \
                    anomaly_counts.get("%s|%s" % (module, section), 0) + entry.get("diff_count", 0)
                consumed += 1
                continue
            cap = runtime_caps.get("%s|%s" % (module, section))
            if cap is None:
                fail(lines, "unaccepted module_image candidate: %s %s" % (module, section))
                ok = False
                continue
            if not check_scope(entry, accepted.get("runtime_init_ranges", {}), lines):
                ok = False
                continue
            runtime_counts["%s|%s" % (module, section)] = \
                runtime_counts.get("%s|%s" % (module, section), 0) + entry.get("diff_count", 0)
            consumed += 1
            continue
        if domain == "infrastructure":
            target = entry.get("target", "")
            # Each accepted field is one physical location. Chain membership
            # echoes are independently keyed by member within each chain.
            identity = (target, entry.get("detail", "") if target.startswith("ldr.") else "")
            if identity in infra_seen:
                fail(lines, "infrastructure scale cap exceeded: %s" % target)
                ok = False
                continue
            infra_seen.add(identity)
            if classification in ("cause-uncertain", CLASS_UNRESOLVABLE):
                fail(lines, "unresolved infrastructure entry: %s (%s)" % (target, classification))
                ok = False
                continue
            if classification != "candidate":
                match = re.fullmatch(r"membership: (.+) present on (capture|crafted) only",
                                     entry.get("detail", ""))
                if (classification == "expected-volatile" and target in (
                        "kusd.interrupt_time", "kusd.systemtime", "kusd.tick_count")):
                    consumed += 1
                elif (classification == "expected" and target in (
                        "ldr.load", "ldr.memory", "ldr.init") and match and
                        match[1] in module_set_accepted and match[1] in
                        report.get("modules", {}).get("only_" + match[2], []) and
                        module_set_sides.get(match[1]) == match[2]):
                    consumed += 1
                else:
                    fail(lines, "unaccepted infrastructure classification: %s (%s)" %
                         (target, classification))
                    ok = False
                continue
            if target in infra_accepted:
                consumed += 1
                continue
            if target.startswith("ldr."):
                fail(lines, "unaccepted ldr candidate: %s (%s)"
                     % (target, entry.get("detail", "")))
                ok = False
                continue
            fail(lines, "unaccepted infrastructure candidate: %s (%s)" % (target, classification))
            ok = False
            continue
        fail(lines, "unknown report domain: %s" % domain)
        ok = False

    if consumed != len(entries):
        fail(lines, "domain exhaustion: %d of %d entries consumed - unknown entries must fail"
             % (consumed, len(entries)))
        ok = False

    for key, count in sorted(runtime_counts.items()):
        cap = runtime_caps[key]
        if count > cap:
            fail(lines, "scale cap exceeded: %s: %d > %d" % (key, count, cap))
            ok = False
    for key, count in sorted(anomaly_counts.items()):
        cap = anomaly_caps[key]
        if count > cap:
            fail(lines, "reloc-anomaly cap exceeded: %s: %d > %d" % (key, count, cap))
            ok = False
    return ok


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    with open(argv[1], "rb") as handle:
        report = json.loads(handle.read().decode("utf-8"))
    with open(argv[2], "rb") as handle:
        accepted = json.loads(handle.read().decode("utf-8"))
    if accepted.get("schema") != 2:
        print("FAIL: accepted set schema %r is not supported" % accepted.get("schema"))
        return 2
    lines = []
    ok = adjudicate(report, accepted, lines)
    for line in lines:
        print(line)
    if ok:
        print("PASS: candidates within the accepted-residuals set")
        return 0
    print("FAIL: %d violation(s)" % len(lines))
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
