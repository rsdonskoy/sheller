#!/usr/bin/env python3
"""Expectation checker for the apiset evidence tool's report (test helper).

Usage:
    python apiset_evidence_check.py <evidence.json> <checks.json>

checks.json shape (every listed key must match exactly):
    {"contracts": {"<contract>": {"status": ..., "candidates": [...],
                                  "coverage": {"<host>": {"<fn>": ...}}}},
     "forwarders": {"<host>": {"<slot>": {"target": ..., "status": ...}}}}

Exits 0 only when every expectation holds; each mismatch prints a named
diff so the failure output is complete.
"""

import json
import sys


def fail(messages):
    for m in messages:
        print("CHECK FAILED: %s" % m)
    raise SystemExit(1)


def main():
    if len(sys.argv) != 3:
        print("usage: apiset_evidence_check.py <evidence.json> <checks.json>")
        return 1
    evidence = json.load(open(sys.argv[1], encoding="utf-8"))
    checks = json.load(open(sys.argv[2], encoding="utf-8"))
    bad = []
    if "entries" in checks and evidence.get("entries") != checks["entries"]:
        bad.append("map entries: got %r want %r"
                   % (evidence.get("entries"), checks["entries"]))

    contracts = evidence.get("contracts", {})
    for contract, want in sorted(checks.get("contracts", {}).items()):
        got = contracts.get(contract)
        if got is None:
            bad.append("%s: missing from evidence" % contract)
            continue
        status = got.get("resolution", {}).get("status")
        if "status" in want and status != want["status"]:
            bad.append("%s.status: got %r want %r" % (contract, status, want["status"]))
        if "candidates" in want and got.get("candidates") != want["candidates"]:
            bad.append("%s.candidates: got %r want %r"
                       % (contract, got.get("candidates"), want["candidates"]))
        for host, cov in want.get("coverage", {}).items():
            got_cov = got.get("coverage", {}).get(host, {})
            for fn, fn_status in cov.items():
                if got_cov.get(fn) != fn_status:
                    bad.append("%s.coverage[%s][%s]: got %r want %r"
                               % (contract, host, fn, got_cov.get(fn), fn_status))

    forwarders = evidence.get("forwarders", {})
    for host, slots in checks.get("forwarders", {}).items():
        for slot, want in slots.items():
            got = forwarders.get(host, {}).get(slot)
            if got is None:
                bad.append("forwarders[%s][%s]: missing" % (host, slot))
                continue
            for key in ("target", "status"):
                if got.get(key) != want[key]:
                    bad.append("forwarders[%s][%s].%s: got %r want %r"
                               % (host, slot, key, got.get(key), want[key]))

    if bad:
        fail(bad)
    print("all %d contract checks and %d forwarder checks hold"
          % (len(checks.get("contracts", {})), len(checks.get("forwarders", {}))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
