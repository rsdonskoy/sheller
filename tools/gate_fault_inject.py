#!/usr/bin/env python3
"""Fault injection for the local Linux verification gates (tools/run_linux_*.sh).

A gate that cannot fail loudly is not a gate: this script proves the two Linux
gate scripts do fail loudly, by injecting the historical fault shapes into
*copies* of them and asserting every injected run (a) exits non-zero, (b) names
the failing stage, and (c) never prints PASSED. The tracked scripts are never
edited, and neither is the repository working tree - which is what the gates
mirror, so an injection into the source would be an injection into the repo.

  case                fault                                        expected stage
  a_missing_cmake     the mirror carries no cmake/ (the 19324d3 defect)  configure
  b_broken_cmake      configure dies on a doctored CMakeLists in the     configure
                      mirror copy (the injected file never touches src)
  c_empty_ctest       the test stage is pointed at an empty directory      test
  c2_empty_ctest_only only the ctest invocation is redirected, so the     test
                      --no-tests=error guard is the one that fires
  d_mount_fail        the share the mount stage is told to mount does      mount
                      not exist, and the already-mounted check cannot
                      mask it
  e_chown_fail        the chown stage hands the mirror to a user that      chown
                      does not exist
  f_maker_tar_fail    the making side of the tar pipe gets a member        mirror
                      that is not there - the gap pipefail was added to
                      close, so this is the injection that proves it holds
  g_lock_held         nothing is injected: another process holds the gate   lock
                      lock, so an unmodified gate copy must refuse
  s_missing_cmake     case (a) against the sanitizer leg's script      configure

Run from anywhere on the Windows side (the gates need root inside WSL, and the
injected runs share the gate's mirror target, so run this while no leg is in
flight):

  python tools/gate_fault_inject.py             # all nine cases
  python tools/gate_fault_inject.py a_missing_cmake s_missing_cmake
  python tools/gate_fault_inject.py --check-anchors   # no WSL, no mirror, no run

--check-anchors exists because the injections are anchored to the gate scripts' own
text: if a rewrite of a gate script silently moved a stage, the case that was supposed
to make it red would instead run an un-injected script and report a green gate that was
never tested. The check builds every variant in memory, requires each anchor to be
found, requires the result to differ from the tracked text, and requires the injected
marker to be present - so a stale anchor fails here rather than reading as a pass
later. It needs no WSL and touches nothing outside its own stdout.

Generated copies land in the temp dir below and are removed when the round ends,
together with the empty directory cases c and c2 create in WSL. An injected run
shares the gate's mirror target, so run it while no leg is in flight. Exit status is
0 only when every case behaved as required. Like the gate scripts themselves,
this one is coupled to this machine (drvfs at /mnt/devdrive).
"""

import pathlib
import subprocess
import sys
import time

BS = chr(92)  # literal backslash, kept out of string escapes

REPO = pathlib.Path(__file__).resolve().parent.parent
SCRATCH_WIN = "C:/devdrv/tmp/linux-gate-fault-inject"
SCRATCH_WSL = "/mnt/devdrive/tmp/linux-gate-fault-inject"
SUITE = "run_linux_suite.sh"
SANITIZER = "run_linux_sanitizer.sh"

# Anchors inside the tracked gate scripts. They are deliberately exact: a gate
# rewritten around its own stages makes this script say "anchor not found",
# which is the honest signal that the injection has to be re-thought.
TAR_ANCHOR = (
    'tar -C "$SRC" "${MIRROR_EXCLUDES[@]}" -cf - . | tar -C "$DST" -xf -' + "\n"
)
CTEST_ANCHOR = '--test-dir "build/$PRESET" ' + BS + "\n    --output-on-failure"
COUNT_ANCHOR = '--test-dir "build/$PRESET" -N'
WORKDIR_ANCHOR = 'WORK_DIR=""' + "\n"
EMPTY_DIR_SETUP = (
    'EMPTY_DIR=/tmp/sheller-gate-inject-empty' + "\n"
    'mkdir -p "$EMPTY_DIR"' + "\n"
)
BROKEN_CML_NEW = (
    TAR_ANCHOR
    + "  echo 'message(FATAL_ERROR \"injected: broken CMakeLists\")'"
    + ' >> "$DST/CMakeLists.txt"' + "\n"
)
EXCLUDE_CMAKE = ("MIRROR_EXCLUDES=(" + "\n", "MIRROR_EXCLUDES=(" + "\n  --exclude=cmake" + "\n")
EMPTY_CTEST_RUN = (
    CTEST_ANCHOR,
    '--test-dir "$EMPTY_DIR" ' + BS + "\n    --output-on-failure",
)

# The three stages that sit before anything is built: mount, chown and the making
# side of the mirror pipe. Their failures used to be structural arguments only.
MOUNT_ANCHOR = (
    "  mount | grep -q devdrive || mount -t drvfs 'C:" + BS + "devdrv' /mnt/devdrive" + "\n"
)
MOUNT_FAIL = (
    "  mount | grep -q devdrive-absent-probe || mount -t drvfs 'C:" + BS
    + "no_such_gate_share' /mnt/devdrive" + "\n"
)
CHOWN_ANCHOR = 'run_step chown "$CHOWN_LOG" chown -R "$RUN_AS":"$RUN_AS" "$DST"' + "\n"
CHOWN_FAIL = (
    'run_step chown "$CHOWN_LOG" chown -R no_such_gate_user:no_such_gate_user "$DST"' + "\n"
)
MAKER_TAR_FAIL = TAR_ANCHOR.replace("-cf - . |", "-cf - . no_such_gate_member |")

FAULTS = {
    "a_missing_cmake": (SUITE, [EXCLUDE_CMAKE], "configure"),
    "b_broken_cmake": (SUITE, [(TAR_ANCHOR, BROKEN_CML_NEW)], "configure"),
    "c_empty_ctest": (
        SUITE,
        [
            (WORKDIR_ANCHOR, WORKDIR_ANCHOR + EMPTY_DIR_SETUP),
            (COUNT_ANCHOR, '--test-dir "$EMPTY_DIR" -N'),
            EMPTY_CTEST_RUN,
        ],
        "test",
    ),
    "c2_empty_ctest_only": (
        SUITE,
        [
            (WORKDIR_ANCHOR, WORKDIR_ANCHOR + EMPTY_DIR_SETUP),
            EMPTY_CTEST_RUN,
        ],
        "test",
    ),
    "d_mount_fail": (SUITE, [(MOUNT_ANCHOR, MOUNT_FAIL)], "mount"),
    "e_chown_fail": (SUITE, [(CHOWN_ANCHOR, CHOWN_FAIL)], "chown"),
    "f_maker_tar_fail": (SUITE, [(TAR_ANCHOR, MAKER_TAR_FAIL)], "mirror"),
    "g_lock_held": (SUITE, [], "lock"),
    "s_missing_cmake": (SANITIZER, [EXCLUDE_CMAKE], "configure"),
}


# What each injected text must contain afterwards. The check exists so that an
# anchor which no longer matches the shipped script - or matches but replaces
# nothing - cannot be mistaken for an injected run.
PROBE_TOKEN = {
    "a_missing_cmake": "--exclude=cmake",
    "s_missing_cmake": "--exclude=cmake",
    "b_broken_cmake": "injected: broken CMakeLists",
    "c_empty_ctest": "EMPTY_DIR=/tmp/sheller-gate-inject-empty",
    "c2_empty_ctest_only": "EMPTY_DIR=/tmp/sheller-gate-inject-empty",
    "d_mount_fail": "devdrive-absent-probe",
    "e_chown_fail": "no_such_gate_user",
    "f_maker_tar_fail": "no_such_gate_member",
}


# g_lock_held injects nothing: the fault is a lock held by somebody else, so the
# script that must refuse is the tracked gate verbatim. What this case asserts is that
# the guard exists and bites - see LOCK_STAGE_ANCHOR in check_anchors for the static
# half of the same claim.
LOCK_FILE = "/tmp/sheller-gate.lock"
LOCK_STAGE_ANCHOR = 'run_step lock "$LOCK_LOG" gate_lock\n'
LOCKED_RUNS = {"g_lock_held"}
HOLDERS = []


def start_holder():
    # Hold the lock for one case only. Two lifetime details matter and neither is
    # obvious: terminate() on the Windows-side wsl.exe does not reliably kill the
    # Linux-side process, so the holder also carries a timeout and releases by itself;
    # and a holder that outlives its case poisons the next one, which is exactly how
    # this round first failed - s_missing_cmake was refused at the lock stage and never
    # reached the configure stage it asserts on.
    proc = subprocess.Popen(
        ["wsl", "-u", "root", "-e", "bash", "-c",
         "timeout 30 flock -n " + LOCK_FILE + " -c 'sleep 45' & "
         "HOLD=$!; echo held; sleep 45; echo released"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    HOLDERS.append(proc)
    time.sleep(2)  # let the holder actually take the lock before the run starts
    return proc


def stop_holders():
    # Kill it inside WSL, not just the Windows wrapper, then release locally.
    subprocess.run(
        ["wsl", "-u", "root", "-e", "bash", "-c",
         "pkill -f 'flock -n " + LOCK_FILE + "' 2>/dev/null; true"],
        capture_output=True, text=True, timeout=120,
    )
    for proc in HOLDERS:
        try:
            proc.terminate()
        except OSError:
            pass
    HOLDERS.clear()


def variant_path(name):
    return pathlib.Path(SCRATCH_WIN) / (name + ".sh")


def variant_text(name, script, edits):
    source = (REPO / "tools" / script).read_text(encoding="utf-8", newline="")
    text = source
    for old, new in edits:
        if old not in text:
            raise SystemExit("anchor not found in tools/" + script + ": " + repr(old))
        text = text.replace(old, new, 1)
    return source, text


def build_variant(name, script, edits):
    _, text = variant_text(name, script, edits)
    path = variant_path(name)
    path.write_bytes(text.encode("utf-8"))
    return path


def check_anchors():
    """Every case, without running anything: anchor present, text actually mutated,
    injected marker present. Fails loudly if a gate rewrite moved what we inject."""
    problems = []
    for name, (script, edits, stage) in FAULTS.items():
        try:
            source, text = variant_text(name, script, edits)
        except SystemExit as exc:
            problems.append(name + ": " + str(exc))
            continue
        if not edits:
            if name in LOCKED_RUNS and LOCK_STAGE_ANCHOR in source:
                print("ok " + name + " [tools/" + script + "] -> guard present, no"
                      " injection by design")
                continue
            problems.append(name + ": expected a locked-run case to carry the lock stage")
            continue
        if text == source:
            problems.append(name + ": the injection changed nothing in " + script)
            continue
        token = PROBE_TOKEN.get(name)
        if token and token not in text:
            problems.append(name + ": injected marker missing: " + token)
            continue
        print("ok " + name + " [tools/" + script + "] -> stage '" + stage + "'")
    print()
    if problems:
        print("ANCHOR CHECK FAILED")
        for p in problems:
            print("  " + p)
        return 1
    print("ANCHOR CHECK OK: " + str(len(FAULTS))
          + " case(s) anchored, mutated and carrying their marker (nothing ran)")
    return 0


def run(name):
    # The marker carries the gate's real exit status: the Windows->WSL wrapper
    # does not propagate it (measured - wsl.exe returned 0 over a gate that
    # returned 1), so reading the wrapper's status would reproduce the very
    # fake green this script exists to disprove.
    inner = "bash " + SCRATCH_WSL + "/" + name + ".sh; echo __WRC__$?"
    proc = subprocess.run(
        ["wsl", "-u", "root", "-e", "bash", "-c", inner],
        capture_output=True, text=True, timeout=5400,
    )
    out = proc.stdout + proc.stderr
    marker = [line for line in out.splitlines() if line.startswith("__WRC__")]
    rc = int(marker[0][len("__WRC__"):]) if marker else None
    return rc, out


def reclaim():
    # What the injected runs leave behind: the variant copies, and the empty
    # directory cases c and c2 point ctest at. The mirror target is deliberately
    # not repaired here - every gate run clears and re-mirrors it as its own
    # stage, which is what a suite leg coming back green after a whole injection
    # round demonstrates, so repairing it here would hide that property instead
    # of stating it.
    subprocess.run(
        ["wsl", "-u", "root", "-e", "bash", "-c",
         "rm -rf /tmp/sheller-gate-inject-empty"],
        capture_output=True, text=True, timeout=300,
    )
    stop_holders()
    for path in sorted(pathlib.Path(SCRATCH_WIN).glob("*.sh")):
        path.unlink()
    # The lock file itself is never removed: flock locks an open file description, so
    # unlinking it lets a new run open a different inode and go alongside a holder that
    # still locks the old one - removal would break the guard at the worst moment.
    print("reclaimed: the variant copies and /tmp/sheller-gate-inject-empty")
    print("note: the mirror target still holds the last injected shape until the"
          " next gate run, which clears and re-mirrors it.")


def main():
    if "--check-anchors" in sys.argv:
        return check_anchors()
    names = sys.argv[1:] or list(FAULTS)
    unknown = [n for n in names if n not in FAULTS]
    if unknown:
        raise SystemExit("unknown case(s): " + ", ".join(unknown))
    pathlib.Path(SCRATCH_WIN).mkdir(parents=True, exist_ok=True)
    failures = []
    try:
        for name in names:
            script, edits, stage = FAULTS[name]
            build_variant(name, script, edits)
            if name in LOCKED_RUNS:
                start_holder()
            try:
                rc, out = run(name)
            finally:
                if name in LOCKED_RUNS:
                    stop_holders()
            print("--- " + name + " [tools/" + script + "]: rc=" + str(rc))
            if rc == 0:
                failures.append(name + ": exited 0 under an injected fault (fake green)")
            if ("gate: " + stage + " FAILED") not in out:
                failures.append(name + ": did not name the '" + stage + "' stage; tail:\n"
                                + "\n".join(out.splitlines()[-25:]))
            if "PASSED" in out:
                failures.append(name + ": printed PASSED under an injected fault")
            for line in out.splitlines():
                if line.startswith("gate: ") or line.startswith("== gate stage:"):
                    print("    " + line)
    finally:
        reclaim()
    print()
    if failures:
        print("FAULT INJECTION FAILED")
        for f in failures:
            print("  " + f)
        return 1
    print("FAULT INJECTION OK: " + str(len(names))
          + " case(s) exited non-zero, named the failing stage, never claimed PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
