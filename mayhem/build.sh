#!/usr/bin/env bash
# mayhem/build.sh — build libspatialindex's fuzz harnesses (sanitized) and its gtest suite (normal flags).
# Runs in the commit image as `mayhem` in /mayhem; offline and re-runnable (no network, no rm of upstream state).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
# SanCov on the library AND the harness TUs (SANITIZER_FLAGS carries no coverage flags), unconditionally.
COV_FLAGS="-fsanitize=fuzzer-no-link"
# UBSan relaxation (library only): IndexItem_GetData (src/capi/sidx_api.cc) does memcpy(dst, NULL, 0) for every
# item stored with no data blob, which trips nonnull-attribute on nearly every C-API query and hides everything
# behind it. Only that check is relaxed; ASan and the rest of UBSan stay on and halting.
LIB_UBSAN_RELAX="-fno-sanitize=nonnull-attribute"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# 1) The library itself, static, instrumented with the sanitizers and DWARF-3. Build type "None" adds no
#    flags of its own, so asserts stay on and -gdwarf-3 is the only debug flag. (build-* is gitignored upstream.)
cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=None -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $COV_FLAGS $LIB_UBSAN_RELAX $DEBUG_FLAGS -O1" \
  -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $COV_FLAGS $LIB_UBSAN_RELAX $DEBUG_FLAGS -O1"
cmake --build build-fuzz -j"$MAYHEM_JOBS" --target spatialindex spatialindex_c
LIBSIDX=$(find build-fuzz -name 'libspatialindex.a' | head -n1)
LIBSIDX_C=$(find build-fuzz -name 'libspatialindex_c.a' | head -n1)
[ -n "$LIBSIDX" ] && [ -n "$LIBSIDX_C" ] || { echo "static libraries not found" >&2; exit 1; }

# 2) Harnesses: each linked twice — libFuzzer binary and a run-once -standalone reproducer.
H="$SRC/mayhem/harnesses"
OBJ="$SRC/build-fuzz/mayhem-obj"
mkdir -p "$OBJ"
HFLAGS=(-std=c++11 -I"$SRC/include" -I"$H")
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OBJ/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"

build_harness() {  # <name> <source> <extra flags...>
  local name="$1" src="$2"; shift 2
  $CXX $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS "${HFLAGS[@]}" "$@" -c "$src" -o "$OBJ/$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OBJ/$name.o" "$OBJ/lsan_off.o" \
    "$LIBSIDX_C" "$LIBSIDX" -o "$SRC/$name"
  $CXX $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS "$OBJ/standalone_main.o" "$OBJ/$name.o" "$OBJ/lsan_off.o" \
    "$LIBSIDX_C" "$LIBSIDX" -o "$SRC/$name-standalone"
}
build_harness fuzz_rtree_load   "$H/fuzz_load_disk.cc" -DSIDX_TREE=1
build_harness fuzz_mvrtree_load "$H/fuzz_load_disk.cc" -DSIDX_TREE=2
build_harness fuzz_tprtree_load "$H/fuzz_load_disk.cc" -DSIDX_TREE=3
build_harness fuzz_rtree_ops    "$H/fuzz_rtree_ops.cc"
build_harness fuzz_mvrtree_ops  "$H/fuzz_mvrtree_ops.cc"
build_harness fuzz_tprtree_ops  "$H/fuzz_tprtree_ops.cc"
build_harness fuzz_capi         "$H/fuzz_capi.cc"

# 3) Upstream's gtest suite (vendored googletest), NORMAL flags, separate tree; test.sh runs it.
cmake -S . -B build-tests -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=ON \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build build-tests -j"$MAYHEM_JOBS" --target libsidxtest
test -x build-tests/bin/libsidxtest
