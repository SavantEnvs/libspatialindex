#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's gtest suite (test/gtest: geometry, RTree/MVRTree/TPRTree and C-API tests), built by build.sh.
BIN="$SRC/build-tests/bin/libsidxtest"
if [ ! -x "$BIN" ]; then
  echo "test.sh: $BIN missing — mayhem/build.sh should have built it" >&2
  emit_ctrf "gtest" 0 1 0
  exit 1
fi
XML="$(mktemp "${TMPDIR:-/tmp}/sidx-gtest-XXXXXX.xml")"
rm -f "$XML"
# gtest's working directory matches upstream's ctest WORKING_DIRECTORY (it writes scratch index files there).
( cd "$SRC/build-tests/bin" && "$BIN" --gtest_output="xml:$XML" ); rc=$?
if [ ! -s "$XML" ]; then
  echo "test.sh: no gtest XML report produced (rc=$rc)" >&2
  emit_ctrf "gtest" 0 1 0
  exit 1
fi
# Counts from the report: <testsuites tests="N" failures="F" disabled="D" errors="E" ...> plus skipped cases.
total=$(grep -o '<testsuites [^>]*' "$XML" | grep -o ' tests="[0-9]*"' | grep -o '[0-9]*')
failed=$(grep -o '<testsuites [^>]*' "$XML" | grep -o ' failures="[0-9]*"' | grep -o '[0-9]*')
errors=$(grep -o '<testsuites [^>]*' "$XML" | grep -o ' errors="[0-9]*"' | grep -o '[0-9]*')
skipped=$(grep -c 'result="skipped"' "$XML" || true)
rm -f "$XML"
total=${total:-0}; failed=$(( ${failed:-0} + ${errors:-0} )); skipped=${skipped:-0}
passed=$(( total - failed - skipped ))
# A crashed / neutered runner leaves no or an empty report; a non-zero exit with no failures recorded is a failure too.
if [ "$total" -eq 0 ] || { [ "$rc" -ne 0 ] && [ "$failed" -eq 0 ]; }; then failed=$(( failed + 1 )); fi
emit_ctrf "gtest" "$passed" "$failed" "$skipped"
