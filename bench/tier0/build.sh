#!/usr/bin/env bash
# Build every Tier-0 case into <outdir>/<id>/{prog,prog_asan}.
#   prog       -> the case's own cflags (what the analyzer is pointed at)
#   prog_asan  -> -O0 ASan+UBSan validator build (or the case's "asan_cflags")
# usage: bench/tier0/build.sh <outdir> [case-id ...]
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: $0 <outdir> [case-id ...]" >&2
    exit 2
fi
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$1"; shift
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
CC="${CC:-gcc}"
ASAN_DEFAULT="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined"
# MemorySanitizer (uninitialised reads) is a separate clang-only build; only built when a case
# declares an `msan` oracle (or is a uninit-class negative), since it needs clang.
MSAN_CC="${MSAN_CC:-clang}"
MSAN_FLAGS="-O0 -g -fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer"
# Format-string cases are intentional; keep the build log readable.
QUIET="-Wno-format-security"

if [ $# -gt 0 ]; then
    CASES=("$@")
else
    CASES=()
    for d in "$HERE"/*/; do
        [ -f "$d/case.json" ] && CASES+=("$(basename "$d")")
    done
fi

fail=0
for id in "${CASES[@]}"; do
    src="$HERE/$id/prog.c"
    manifest="$HERE/$id/case.json"
    flags="$(python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["cflags"]))' "$manifest")"
    aflags="$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print(" ".join(c["asan_cflags"]) if "asan_cflags" in c else "")' "$manifest")"
    [ -n "$aflags" ] || aflags="$ASAN_DEFAULT"
    mkdir -p "$OUT/$id"
    # shellcheck disable=SC2086
    if ! "$CC" $flags $QUIET -o "$OUT/$id/prog" "$src"; then
        echo "BUILD FAIL $id (prog)" >&2; fail=1
    fi
    # shellcheck disable=SC2086
    if ! "$CC" $aflags $QUIET -o "$OUT/$id/prog_asan" "$src"; then
        echo "BUILD FAIL $id (prog_asan)" >&2; fail=1
    fi
    needs_msan="$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print("1" if c.get("class")=="uninit" or any(b.get("oracle")=="msan" for b in c.get("bugs",[])) else "")' "$manifest")"
    if [ -n "$needs_msan" ]; then
        # shellcheck disable=SC2086
        if ! "$MSAN_CC" $MSAN_FLAGS $QUIET -o "$OUT/$id/prog_msan" "$src"; then
            echo "BUILD FAIL $id (prog_msan)" >&2; fail=1
        fi
    fi
done
echo "built ${#CASES[@]} case(s) into $OUT"
exit $fail
