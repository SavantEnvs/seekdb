#!/usr/bin/env bash
#
# mayhem/build.sh — seekdb: cargo-fuzz targets over the Rust parsers the server links in
# (rust/json, rust/xml-parser, rust/regex-engine), plus the upstream unit tests of those
# crates for mayhem/test.sh.
#
# AIR-GAPPED (SPEC §6.5): the first (online) build fills $CARGO_HOME=/opt/toolchains/rust/cargo;
# the PATCH re-run resolves from it (rlenv exports CARGO_NET_OFFLINE=true), so no --offline here.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${MAYHEM_JOBS:=$(nproc)}"
export CARGO_BUILD_JOBS="$MAYHEM_JOBS"
# DWARF <= 3 so Mayhem triage can read the debug info (SPEC §6.2 item 10).
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -Z dwarf-version=3}"

cd "$SRC"
# rust-toolchain.toml pins 1.100.0 for the Bazel build; use the image's pinned nightly instead
# (ASan needs -Zsanitizer). RUSTUP_TOOLCHAIN overrides the file without touching it.
export RUSTUP_TOOLCHAIN="$(rustup default | awk '{print $1}')"

BASE_RUSTFLAGS="${RUSTFLAGS:-}"
FUZZ_DIR="mayhem/fuzz"
TRIPLE="x86_64-unknown-linux-gnu"

# rust/sql-nio keeps its parsers in private modules: generate the shim crate root that
# re-exports them (mayhem/fuzz/sqlnio-shim, gitignored gen/ output).
bash "$FUZZ_DIR/gen_sqlnio_shim.sh" "$SRC"

FUZZ_TARGETS=()
for f in "$FUZZ_DIR"/fuzz_targets/*.rs; do
  FUZZ_TARGETS+=("$(basename "${f%.*}")")
done
[ "${#FUZZ_TARGETS[@]}" -gt 0 ] || { echo "ERROR: no fuzz targets under $FUZZ_DIR/fuzz_targets/" >&2; exit 1; }

# $SANITIZER_FLAGS (base ENV: ASan+UBSan) selects the rustc sanitizer: ASan when it asks for
# address, none when it is explicitly empty. UBSan has no rustc equivalent; the Rust analogue,
# overflow checks + debug assertions (panic -> abort), is on via --debug-assertions.
SANITIZER_FLAGS="${SANITIZER_FLAGS-}"
RUST_SAN=""
FUZZ_SAN=none
case "$SANITIZER_FLAGS" in *address*) RUST_SAN="-Zsanitizer=address"; FUZZ_SAN=address ;; esac
LSAN_LINK=""
if [ -n "$RUST_SAN" ]; then
  # mayhem/lsan_off.c: build-time LeakSanitizer off-switch, linked into every ASan binary.
  # Plain C object (no -fsanitize: rustc links only the ASan runtime, not UBSan's).
  mkdir -p "$SRC/$FUZZ_DIR/target"
  "${CC:-clang}" -c -fPIC -g -gdwarf-3 mayhem/lsan_off.c -o "$SRC/$FUZZ_DIR/target/lsan_off.o"
  LSAN_LINK="-Clink-arg=$SRC/$FUZZ_DIR/target/lsan_off.o"
fi
export RUSTFLAGS="$BASE_RUSTFLAGS --cfg fuzzing $RUST_SAN $RUST_DEBUG_FLAGS $LSAN_LINK"
# schema-pattern-shim compiles upstream's C++ rust/json/src/schema_pattern.cpp ($CXX, via
# cxx_build) with the same $SANITIZER_FLAGS as any C++ in the fleet (ASan + halting UBSan),
# plus SanitizerCoverage so libFuzzer sees edges inside std::regex and the wrapper.
# -fno-sanitize=vptr: the only UBSan check that needs the C++ half of the UBSan runtime
# (ubsan_standalone_cxx: __ubsan_vptr_type_cache, __ubsan_handle_dynamic_type_cache_miss),
# which rustc's ASan runtime does not carry. All other UBSan checks and ASan stay on and halt.
CXX_SAN="$SANITIZER_FLAGS"
case "$CXX_SAN" in *undefined*) CXX_SAN="$CXX_SAN -fno-sanitize=vptr" ;; esac
export SEEKDB_CXX_SANITIZER_FLAGS="$CXX_SAN -fsanitize=fuzzer-no-link"
echo "RUSTFLAGS=$RUSTFLAGS; targets: ${FUZZ_TARGETS[*]}"
for t in "${FUZZ_TARGETS[@]}"; do
  cargo fuzz build --fuzz-dir "$FUZZ_DIR" -O --debug-assertions --sanitizer "$FUZZ_SAN" "$t"
  bin="$SRC/$FUZZ_DIR/target/$TRIPLE/release/$t"
  [ -x "$bin" ] || { echo "ERROR: expected fuzz binary not found at $bin" >&2; exit 1; }
  cp "$bin" "/mayhem/$t"
  echo "built /mayhem/$t"
done

# Functional suite: upstream's own #[cfg(test)] unit tests of the fuzzed crates, built with
# normal flags into a separate target dir. Each crate's test binary is copied to a fixed path
# so test.sh only runs them.
export RUSTFLAGS="$BASE_RUSTFLAGS"
mkdir -p "$SRC/mayhem/fuzz/target/tests"
for crate in json xml-parser regex-engine; do
  exe="$(cargo test --manifest-path "$FUZZ_DIR/Cargo.toml" --target-dir "$FUZZ_DIR/target/unit" \
          -p "$crate" --lib --no-run --message-format=json \
        | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -1)"
  [ -n "$exe" ] && [ -x "$exe" ] || { echo "ERROR: no unit-test binary for $crate" >&2; exit 1; }
  cp "$exe" "$SRC/mayhem/fuzz/target/tests/$crate"
done
echo "build.sh complete"
