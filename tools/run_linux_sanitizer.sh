#!/bin/bash
# Local Linux verification gate, sanitizer leg: the same fail-loud structure as
# tools/run_linux_suite.sh over the linux-sanitizer preset (RelWithDebInfo with
# ASan/UBSan), reproducing the CI linux-sanitizer job's test selection. Run as
# root from Windows:
#   wsl -u root -e bash -c "bash /mnt/devdrive/src/sheller/tools/run_linux_sanitizer.sh"
#
# Differences from the suite leg on purpose: the preset, its own log files, and
# the CI's 4-name exclusion set (machine-sensitive layout goldens). There is no
# installed-consumer leg here - running an installed tree under ASan couples the
# delivery surface to a sanitizer build for no added evidence.
#
# Keep the two scripts structurally in step: stage names, the run_step/fail
# pattern and the exclusion-based mirror are shared by contract (specs/
# build-system, "Linux gate"). If you change one, change the other.
set -uo pipefail
set -x

SRC=/mnt/devdrive/src/sheller
DST=/home/user1/sheller-linux
RUN_AS=user1
VCWD=/home/user1/vcpkg
PRESET=linux-sanitizer
JOBS=8
# CI linux.yml linux-sanitizer job: the same four machine-sensitive baselines.
EXCLUDE_TESTS="event_baseline|exception_e2e|behavior_e2e|loader_byhash_x86_e2e"

LOCK=/tmp/sheller-gate.lock
LOCK_LOG=/tmp/asan_lock.log
MOUNT_LOG=/tmp/asan_mount.log
MIRROR_LOG=/tmp/asan_mirror.log
CHOWN_LOG=/tmp/asan_chown.log
CFG_LOG=/tmp/asan_cfg.log
BUILD_LOG=/tmp/asan_build.log
TEST_LOG=/tmp/asan_test.log

# Same list as tools/run_linux_suite.sh - keep the two in step. The ./ prefix is
# measured, not stylistic: the archive is made from ".", so --exclude=build also
# drops a nested src/build, while --exclude=./build leaves it alone. .git and
# __pycache__ stay unanchored - a nested copy of either is unwanted too.
MIRROR_EXCLUDES=(
  --exclude=./build --exclude=./vcpkg_installed --exclude=./cmake-build-debug
  --exclude=./out --exclude=./Testing --exclude=./openspec --exclude=./.docs
  --exclude=./.qoder --exclude=./.codex --exclude=./.claude --exclude=./.vs
  --exclude=./.idea --exclude=./.vscode --exclude=./.bak
  --exclude=.git --exclude=__pycache__
)

fail() {
  local stage="$1" log="${2:-}" note="${3:-}"
  [[ -n "$note" ]] && echo "gate: $note"
  if [[ -n "$log" && -r "$log" ]]; then
    echo "gate: last 20 line(s) of $log:"
    tail -n 20 "$log"
  fi
  echo "gate: $stage FAILED"
  exit 1
}

run_step() {
  local stage="$1" log="$2"
  shift 2
  echo "== gate stage: $stage =="
  "$@" > "$log" 2>&1 || fail "$stage" "$log"
  echo "== gate stage: $stage ok (log: $log) =="
}

ensure_root() {
  [[ "$(id -u)" -eq 0 ]] || {
    echo "gate: run as root (wsl -u root -e bash ...), it mounts drvfs and chowns $DST"
    return 1
  }
}

gate_lock() {
  # One gate run at a time: the mirror target, its build tree, the install-consumer
  # prefix and the /tmp stage logs are all single-slot. flock locks an open file
  # description, so this fd, opened here and never closed, holds until the script
  # exits - and the file must never be unlinked while a run is alive.
  exec 9>"$LOCK"
  flock -n 9 || {
    echo "gate: another gate or injection run already holds $LOCK"
    echo "gate: they share $DST; wait for it or kill the holder"
    return 1
  }
}

ensure_mount() {
  mount | grep -q devdrive || mount -t drvfs 'C:\devdrv' /mnt/devdrive
}

mirror_tree() {
  mkdir -p "$DST" || return 1
  # Drop every previous mirror entry: a stale top-level directory would be as
  # misleading as a missing one. Only build/ is kept: it is generated, and the
  # vcpkg installed tree lives inside it (build/<preset>/vcpkg_installed), so an
  # incremental run keeps its dependencies while a stray mirror-root installed
  # tree - possibly built for another platform - cannot survive into the next run.
  find "$DST" -mindepth 1 -maxdepth 1 ! -name build -exec rm -rf {} + || return 1
  tar -C "$SRC" "${MIRROR_EXCLUDES[@]}" -cf - . | tar -C "$DST" -xf -
  # Restamp the extracted sources: the drvfs mount reports lying mtimes, and a
  # stamp older than a build-tree object makes ninja skip a changed source
  # (loader.cpp.o hid a new symbol this way for three gate runs).
  find "$DST/src" "$DST/include" "$DST/tests" -type f \( -name '*.cpp' -o -name '*.h' -o -name '*.inc' \) -exec touch {} +
}

test_count_query() {
  runuser -u "$RUN_AS" -- ctest --test-dir "build/$PRESET" -N -E "$EXCLUDE_TESTS"
}

run_ctest() {
  runuser -u "$RUN_AS" -- ctest --test-dir "build/$PRESET" \
    --output-on-failure --no-tests=error -E "$EXCLUDE_TESTS"
}

run_step "preflight" /tmp/asan_preflight.log ensure_root
run_step lock "$LOCK_LOG" gate_lock
run_step mount "$MOUNT_LOG" ensure_mount
[[ -d "$SRC" ]] || fail mount "$MOUNT_LOG" "$SRC is not present after the mount stage"
run_step mirror "$MIRROR_LOG" mirror_tree
echo "gate: mirror size excluding build/: $(du -sh --exclude=build "$DST" | cut -f1)"
run_step chown "$CHOWN_LOG" chown -R "$RUN_AS":"$RUN_AS" "$DST"
cd "$DST" || fail "cd $DST"
run_step configure "$CFG_LOG" runuser -u "$RUN_AS" -- \
  env VCPKG_ROOT="$VCWD" CC=/usr/bin/gcc-13 CXX=/usr/bin/g++-13 \
  cmake --preset "$PRESET"
run_step build "$BUILD_LOG" runuser -u "$RUN_AS" -- \
  cmake --build "build/$PRESET" -j "$JOBS"

# Empty selection is a failure: with a -E filter, "no tests were found" would
# otherwise read as green for a build that registered nothing.
test_count=$(test_count_query 2>/dev/null | grep -c 'Test *#' || true)
[[ "$test_count" =~ ^[0-9]+$ ]] && (( test_count > 0 )) ||
  fail test "$TEST_LOG" "ctest registered 0 tests to run in build/$PRESET"
echo "== gate stage: test-set-count ok ($test_count test(s)) =="

run_step test "$TEST_LOG" run_ctest
tail -n 5 "$TEST_LOG"
echo "gate: linux $PRESET leg PASSED ($test_count test(s), CI exclusion set applied)"
