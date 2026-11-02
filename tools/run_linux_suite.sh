#!/bin/bash
# Local Linux verification gate, suite leg: mount the dev drive, mirror the
# working tree to ext4 (drvfs chokes on vcpkg's file ops), configure the
# linux-debug preset, build, run the full ctest suite, then the installed
# consumer leg. Run as root from Windows:
#   wsl -u root -e bash -c "bash /mnt/devdrive/src/sheller/tools/run_linux_suite.sh"
# The mount stage performs the drvfs mount itself when it is missing.
#
# Two properties this script exists to keep:
#   * fail loud - every stage decides its own outcome, prints the log tail and
#     exits non-zero on failure. An empty test set is a failure, so a dead
#     configure can never be reported as a green run by a trailing log command.
#   * immune to new top-level directories - the mirror is exclusion based, so a
#     CMake input added at the repository root travels without editing this
#     script (the defect that killed the gate silently in 19324d3).
#
# Machine paths are the environment recorded in HANDOFF (WSL Debian, user1,
# /home/user1/vcpkg, gcc-13); see tests/README.md, "local Linux verification
# gates". Stages log to /tmp as before.
set -uo pipefail
set -x

SRC=/mnt/devdrive/src/sheller
DST=/home/user1/sheller-linux
RUN_AS=user1
VCWD=/home/user1/vcpkg
PRESET=linux-debug
JOBS=8
SNAPSHOT_SRC="$SRC/build/seh.snap"

LOCK=/tmp/sheller-gate.lock
LOCK_LOG=/tmp/linux_lock.log
MOUNT_LOG=/tmp/linux_mount.log
MIRROR_LOG=/tmp/linux_mirror.log
CHOWN_LOG=/tmp/linux_chown.log
CFG_LOG=/tmp/linux_cfg.log
BUILD_LOG=/tmp/linux_build.log
TEST_LOG=/tmp/linux_test.log
INSTALL_LOG=/tmp/linux_install.log
PREFIX_DIR="$DST/build/$PRESET/install-consumer-prefix"
CONSUMER_WORK="$DST/build/$PRESET/install-consumer-work"
WORK_DIR=""

# Everything the build reads at the repository root, minus generated and
# host-local trees. .github is small and harmless; dotfiles like .clang-format
# and .clang-tidy travel as part of ".". The ./ prefix is measured, not stylistic:
# the archive is made from ".", so --exclude=build also drops a nested src/build,
# while --exclude=./build leaves it alone. .git and __pycache__ stay unanchored -
# a nested copy of either is unwanted too.
MIRROR_EXCLUDES=(
  --exclude=./build --exclude=./vcpkg_installed --exclude=./cmake-build-debug
  --exclude=./out --exclude=./Testing --exclude=./openspec --exclude=./.docs
  --exclude=./.qoder --exclude=./.codex --exclude=./.claude --exclude=./.vs
  --exclude=./.idea --exclude=./.vscode --exclude=./.bak
  --exclude=.git --exclude=__pycache__
)

cleanup() {
  [[ -n "$WORK_DIR" ]] && rm -rf "$WORK_DIR"
  rm -rf "$PREFIX_DIR" "$CONSUMER_WORK"
}
trap cleanup EXIT

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
  runuser -u "$RUN_AS" -- ctest --test-dir "build/$PRESET" -N
}

run_ctest() {
  runuser -u "$RUN_AS" -- ctest --test-dir "build/$PRESET" \
    --output-on-failure --no-tests=error
}

install_leg() {
  [[ -r "$SNAPSHOT_SRC" ]] || {
    echo "gate: no readable replayable snapshot at $SNAPSHOT_SRC - the install"
    echo "gate: leg needs one (real captures are local-only, never committed)."
    return 1
  }
  WORK_DIR=$(mktemp -d /tmp/sheller-gate-install-XXXXXX) || return 1
  cp "$SNAPSHOT_SRC" "$WORK_DIR/replay.snap" || return 1
  chown -R "$RUN_AS":"$RUN_AS" "$WORK_DIR" || return 1
  # The driver installs build/$PRESET to its own throwaway prefix under the
  # build tree, then configures, builds and runs tests/install-consumer against
  # that prefix alone. It fails with a CMake FATAL_ERROR on any step, so a zero
  # exit is the whole assertion; the prefix is removed by the exit trap.
  runuser -u "$RUN_AS" -- cmake \
    -DSHELLER_ROOT="$DST" \
    -DBUILD_DIR="$DST/build/$PRESET" \
    -DCONFIG=Debug \
    -DSNAPSHOT="$WORK_DIR/replay.snap" \
    -P "$DST/tests/install-consumer/run.cmake"
}

ensure_root() {
  [[ "$(id -u)" -eq 0 ]] || {
    echo "gate: run as root (wsl -u root -e bash ...), it mounts drvfs and chowns $DST"
    return 1
  }
}

run_step "preflight" /tmp/linux_preflight.log ensure_root
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

# Empty test set is a failure in its own right: a green run over zero tests is
# how the dead gate hid for three deliveries.
test_count=$(test_count_query 2>/dev/null | grep -c 'Test *#' || true)
[[ "$test_count" =~ ^[0-9]+$ ]] && (( test_count > 0 )) ||
  fail test "$TEST_LOG" "ctest registered 0 tests in build/$PRESET"
echo "== gate stage: test-set-count ok ($test_count test(s)) =="

run_step test "$TEST_LOG" run_ctest
tail -n 5 "$TEST_LOG"

run_step install "$INSTALL_LOG" install_leg
tail -n 3 "$INSTALL_LOG"
echo "gate: linux $PRESET suite leg PASSED ($test_count test(s), install leg included)"
