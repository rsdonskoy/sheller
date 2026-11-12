#!/usr/bin/env python3
"""Expectation checker for the world diff tool's report (test helper).

Usage:
    python world_diff_check.py <report.json> <checks.json>

checks.json shape (every listed key must match exactly):
    {"must_include": [ {partial entry dict}, ... ],
     "must_not_include": [ {partial entry dict}, ... ],
     "expect": {"dotted.path": value, ...}}

A must_include row passes when at least one report entry carries every
key/value of the partial dict; a must_not_include row passes when none does.
Dotted paths walk dicts and list indices. Exits 0 only when every
expectation holds; each mismatch prints a named diff so the failure output
is complete.
"""

import json
import sys


def subset(needle, hay):
    return all(k in hay and hay[k] == v for k, v in needle.items())


def lookup(obj, dotted):
    for part in dotted.split("."):
        if isinstance(obj, dict):
            if part not in obj:
                return None, False
            obj = obj[part]
        elif isinstance(obj, list):
            if not part.isdigit() or int(part) >= len(obj):
                return None, False
            obj = obj[int(part)]
        else:
            return None, False
    return obj, True


def fail(messages):
    for m in messages:
        print("CHECK FAILED: %s" % m)
    raise SystemExit(1)


def main():
    if len(sys.argv) != 3:
        print("usage: world_diff_check.py <report.json> <checks.json>")
        return 1
    report = json.load(open(sys.argv[1], encoding="utf-8"))
    checks = json.load(open(sys.argv[2], encoding="utf-8"))
    bad = []
    entries = report.get("entries", [])
    for i, needle in enumerate(checks.get("must_include", [])):
        if not any(subset(needle, e) for e in entries):
            bad.append("must_include[%d] matched no entry: %r" % (i, needle))
    for i, needle in enumerate(checks.get("must_not_include", [])):
        hits = [e for e in entries if subset(needle, e)]
        if hits:
            bad.append("must_not_include[%d] matched %d entries: %r"
                       % (i, len(hits), needle))
    for dotted, want in sorted(checks.get("expect", {}).items()):
        got, found = lookup(report, dotted)
        if not found or got != want:
            bad.append("%s: got %r want %r" % (dotted, got, want))
    if bad:
        fail(bad)
    return 0


if __name__ == "__main__":
    sys.exit(main())
