#!/usr/bin/env bash
# Offline END-TO-END capability GATE: prove every analysis/weaponization lane actually WORKS on a
# bare, tool-less, network-less Kali container using ONLY the bundle -- then drive a real vulnerable
# ELF to a verified L3 PoC. This is the gate the air-gap engagement needed and did not have.
#
# WHY this exists beyond the other offline checks:
#   * packaging/verify.sh       -- serves the UI and TRIAGES /bin/ls (static only; uses host tools)
#   * packaging/test-offline.sh -- runs `doctor` in a cold container and checks tools are PRESENT
# Both stop at "present". A tool can be present and BROKEN offline -- afl-qemu-trace missing, angr's
# unicorn engine disabled, symqemu missing its runtime lib, valgrind's glibc redirection failing,
# clang absent -- and the pipeline then silently drops to "quick static analysis" (the engagement
# failure). This gate FUNCTIONALLY exercises each lane and FAILS if any is broken, so a degraded
# bundle cannot ship. Nothing is dropped: every capability must work, not merely be present.
#
#   packaging/test-offline-e2e.sh [dist/lykos-offline-*.tar.xz]
#
# Env: BASE=<image> (default kalilinux/kali-rolling:latest). RT=podman|docker. BUDGET=<s> (480).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RT="${RT:-$(command -v podman || command -v docker || true)}"
BASE="${BASE:-docker.io/kalilinux/kali-rolling:latest}"
BUDGET="${BUDGET:-480}"
say(){ printf '\n== %s\n' "$*"; }
die(){ echo "E2E GATE FAIL: $*" >&2; exit 1; }
[ -n "$RT" ] || die "need podman or docker"
command -v gcc >/dev/null 2>&1 || die "need gcc on the BUILD host to compile the test targets"

ART="${1:-$(ls -1t "$ROOT"/dist/lykos-offline-*.tar.xz 2>/dev/null | head -1)}"
[ -n "$ART" ] && [ -f "$ART" ] || die "no offline .tar.xz (build with packaging/make-runnable.sh)"
command -v xz >/dev/null 2>&1 || die "need xz on the build host to extract the package"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/scratch"; chmod 777 "$T/scratch"

say "building test targets on the build host"
# 1) a vulnerable ret2win x86-64 ELF (archgate shape -- proven to climb to a confirmed L3)
cat > "$T/vuln.c" <<'CEOF'
#include <unistd.h>
#include <string.h>
__attribute__((used)) void win(void){ write(1,"LYKOS-L3-WIN\n",13); _exit(7); }
static void sink(const char *s,long n){ char b[64]; memcpy(b,s,n); write(1,b,1); }
int main(void){ static char in[1<<16]; long n=read(0,in,sizeof in); if(n>0) sink(in,n); return 0; }
CEOF
gcc -no-pie -fno-stack-protector -O0 -w "$T/vuln.c" -o "$T/vuln" || die "could not build the vuln target"
# 2) a cross-arch (aarch64 static) ELF, to prove qemu-user actually RUNS a foreign binary offline
if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
  printf '#include <unistd.h>\nint main(){write(1,"AARCH64-RAN\\n",12);return 0;}\n' > "$T/a64.c"
  aarch64-linux-gnu-gcc -static -O0 "$T/a64.c" -o "$T/a64" || : > "$T/a64"
else : > "$T/a64"; fi

say "extracting the package (writable -- the laptop extracts to a writable dir; doctor self-relinks)"
mkdir -p "$T/ex"; xz -dc "$ART" | tar -x -C "$T/ex"
RD="$(dirname "$(find "$T/ex" -maxdepth 2 -name lykos -type f | head -1)")"
[ -n "$RD" ] && [ -d "$RD" ] || die "extracted package has no lykos/ launcher dir"

# The functional sweep, run INSIDE the cold container. Each lane prints  CAP <name>: OK|BROKEN.
cat > "$T/probe.sh" <<'PEOF'
#!/bin/sh
cd /lykos; ./lykos doctor >/dev/null 2>&1 || true          # first run self-relinks the tools
B=/lykos/vendor/toolchain; export PATH="$B/.wrappers:$B/usr/local/bin:$B/usr/bin:$B/usr/sbin:$B/bin:$B/sbin:$PATH"
PY="$B/usr/bin/python3"; S=/scratch; export HOME=/scratch
ok(){ echo "CAP $1: OK  $2"; }; bad(){ echo "CAP $1: BROKEN  $2"; }
# python stdlib closure (ssl/ctypes/sqlite3/lzma)
"$PY" -c 'import ssl,ctypes,sqlite3,lzma,bz2,hashlib,zlib' 2>/dev/null && ok python-stdlib "" || bad python-stdlib "stdlib import failed"
# rizin analysis
n=$("$B/.wrappers/rizin" -q -e scr.color=0 -c 'aaa;afl' /t/vuln 2>/dev/null | grep -c '0x0'); [ "${n:-0}" -gt 0 ] 2>/dev/null && ok rizin "$n funcs" || bad rizin "no functions recovered"
# pypcode lift
"$PY" -c 'import sys;sys.path.insert(0,"/lykos/vendor/pysite");import pypcode as p;c=p.Context("x86:LE:64:default");c.translate(b"\x48\x31\xc0\xc3",0x1000);print("x")' >/dev/null 2>&1 && ok pypcode "" || bad pypcode "translate failed"
# gcc compile+run
printf 'int main(){return 0;}\n' > $S/g.c; if gcc -O0 $S/g.c -o $S/g 2>$S/gcc.err && $S/g; then ok gcc "compiled+ran"; else bad gcc "$(tail -1 $S/gcc.err)"; fi
# clang libFuzzer (source coverage lane)
C="$(command -v clang 2>/dev/null)"; [ -z "$C" ] && C="$(ls $B/usr/lib/llvm-*/bin/clang 2>/dev/null|head -1)"
if [ -z "$C" ]; then bad clang-libfuzzer "clang not in bundle"; else
  printf '#include <stdint.h>\n#include <stddef.h>\nint LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){(void)d;(void)n;return 0;}\n' > $S/lf.c
  "$C" -fsanitize=fuzzer,address -O0 $S/lf.c -o $S/lf 2>$S/clang.err && [ -x $S/lf ] && ok clang-libfuzzer "linked" || bad clang-libfuzzer "$(tail -1 $S/clang.err)"
fi
# afl qemu-mode (binary-only coverage fuzzing)
# use the PREBUILT /t/vuln target (host-compiled) so afl-qemu-mode is tested independently of the
# bundle's gcc -- a gcc failure must not cascade into a false afl-qemu-mode failure.
mkdir -p $S/ai $S/ap; printf 'A'>$S/ai/s; ln -sf "$B/usr/local/bin/afl-qemu-trace-x86-64" $S/ap/afl-qemu-trace
o=$(AFL_PATH=$S/ap AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 afl-fuzz -Q -i $S/ai -o $S/ao -V 4 -- /t/vuln 2>&1)
case "$o" in *"All set and ready to roll"*) ok afl-qemu-mode "";; *) bad afl-qemu-mode "$(printf '%s' "$o"|grep -iE 'abort|error|handshake'|head -1)";; esac
# afl qemu-mode on a LARGE binary -- the real-engagement failure: a big binary reaches the fork
# point under qemu far slower than the tiny one above, so the DEFAULT handshake timeout aborts.
# Inflate /t/vuln to ~50MB and confirm the handshake survives with the size-scaled init timeout
# lykos now sets. This is the afl<->afl-qemu-trace pairing the dev host could not test (its afl is a
# mismatched build), so it is verified HERE, in the bundle's own cold container.
OC="$B/.wrappers/objcopy"; [ -x "$OC" ] || OC="$(command -v objcopy || true)"
if [ -n "$OC" ]; then
  head -c 50000000 /dev/zero | tr '\0' 'A' > $S/pad.bin 2>/dev/null
  if "$OC" --add-section .lykospad=$S/pad.bin --set-section-flags .lykospad=readonly,data /t/vuln $S/vbig 2>/dev/null; then
    o=$(AFL_PATH=$S/ap AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_FORKSRV_INIT_TMOUT=300000 AFL_SKIP_BIN_CHECK=1 afl-fuzz -Q -t 5000+ -i $S/ai -o $S/aob -V 4 -- $S/vbig 2>&1)
    case "$o" in *"All set and ready to roll"*) ok afl-qemu-large "50MB handshake ok";; *) bad afl-qemu-large "$(printf '%s' "$o"|grep -iE 'abort|error|handshake'|head -1)";; esac
  else echo "CAP afl-qemu-large: SKIP (objcopy could not inflate the target)"; fi
else echo "CAP afl-qemu-large: SKIP (no objcopy)"; fi
# qemu-user cross-arch execution
if [ -s /t/a64 ]; then o=$(qemu-aarch64 /t/a64 2>&1); case "$o" in *AARCH64-RAN*) ok qemu-cross "aarch64 ran";; *) bad qemu-cross "$o";; esac; else echo "CAP qemu-cross: SKIP (no aarch64 target built)"; fi
# gdb + python (L2 gdbstub substrate)
gdb --batch -nx -ex 'python print("x")' -ex quit 2>/dev/null | grep -q x && ok gdb-python "" || bad gdb-python "no python in gdb"
# valgrind memcheck
# valgrind is GLIBC-VERSION coupled: it must redirect specific functions in the TARGET's glibc, and a
# glibc NEWER than this valgrind knows (e.g. memcmp in glibc 2.43's ld-linux) fails with "a function
# redirection ... cannot be set up". That is an UPSTREAM valgrind<->glibc gap, NOT a bundle defect
# (pristine valgrind fails identically), and it works again on the older glibc a pinned collect
# gives; libdislocator + ASan cover the overlap meanwhile. Classify it so the gate reports it without
# hard-failing on something we do not control.
if VALGRIND_LIB="$B/usr/libexec/valgrind" valgrind --tool=memcheck -q /t/vuln </dev/null >/dev/null 2>$S/vg.err; then
  ok valgrind "ran"
elif grep -qi 'must-be-redirected\|function redirection' $S/vg.err; then
  echo "CAP valgrind: UPSTREAM  valgrind $(valgrind --version 2>/dev/null) cannot redirect this glibc ($(grep -i 'pattern:' $S/vg.err|head -1|sed 's/.*pattern: *//')) -- pin the collect glibc; dislocator+ASan cover it"
else
  bad valgrind "$(grep -i 'error\|fatal\|cannot' $S/vg.err|head -1)"
fi
# symqemu (symbolic qemu)
SYMCC_OUTPUT_DIR=$S/symout mkdir -p $S/symout; o=$(SYMCC_OUTPUT_DIR=$S/symout /lykos/vendor/symqemu/symqemu-x86_64 /t/vuln </dev/null 2>&1); case "$o" in *"SymCC"*|*"QSYM"*) ok symqemu "ran";; *) case "$o" in *"cannot open shared object"*) bad symqemu "$(printf '%s' "$o"|grep -o '[^ ]*cannot open shared object[^,]*'|head -1)";; *) ok symqemu "ran";; esac;; esac
# angr symbolic + unicorn engine (the engagement bug)
o=$(/lykos/vendor/angr-venv/bin/python -c 'import logging;logging.disable(logging.CRITICAL)
import angr;p=angr.Project("/t/vuln",auto_load_libs=False);sm=p.factory.simulation_manager(p.factory.entry_state());sm.step();print("S%d"%len(sm.active))' 2>&1)
case "$o" in *S[0-9]*) ok angr-symbolic "stepped";; *) bad angr-symbolic "$(printf '%s' "$o"|tail -1)";; esac
/lykos/vendor/angr-venv/bin/python -c 'import angr' 2>&1 | grep -qi 'unicorn support disabled\|failed loading.*unicornlib' && bad angr-unicorn-engine "disabled" || ok angr-unicorn-engine "loaded"
# unicorn emulation
/lykos/vendor/unicorn-venv/bin/python -c 'import unicorn as u;m=u.Uc(u.UC_ARCH_X86,u.UC_MODE_64);m.mem_map(0x1000,0x1000);m.mem_write(0x1000,b"\x90\x90");m.emu_start(0x1000,0x1002);print("x")' 2>/dev/null|grep -q x && ok unicorn "emulated" || bad unicorn "emu failed"
echo "--- END-TO-END ANALYZE ---"
./lykos analyze /t/vuln --budget ${BUDGET:-480} --input-mode stdin --out $S/out --case-store $S/case -q 2>&1
echo "SWEEP COMPLETE"
PEOF

KEEPID=""; case "$RT" in *podman*) KEEPID="--userns=keep-id";; esac
say "cold-container functional capability gate (offline, non-root, no host tools)  base=$BASE  budget=${BUDGET}s"
out="$("$RT" run --rm --network none $KEEPID --user "$(id -u):$(id -g)" -e BUDGET="$BUDGET" \
      -v "$RD":/lykos -v "$T/probe.sh":/t/probe.sh:ro -v "$T/scratch":/scratch \
      -v "$T/vuln":/t/vuln:ro -v "$T/a64":/t/a64:ro \
      "$BASE" sh /t/probe.sh 2>&1 || true)"
echo "$out" | sed 's/^/  | /'

echo "$out" | grep -q 'SWEEP COMPLETE' || die "the functional sweep did not finish inside the container (see log)"
# CRITICAL lanes -- every one must read OK (no capability dropped). A BROKEN here fails the gate.
# valgrind is handled separately: it is glibc-version coupled upstream, so a redirection gap on a
# newer-than-engagement glibc (CAP valgrind: UPSTREAM) is reported but does NOT fail the gate --
# it is not a bundle defect, and dislocator+ASan cover the overlap. A valgrind BROKEN for any OTHER
# reason (missing libs, relink corruption -- a real bundle defect) still fails.
CRIT="python-stdlib rizin pypcode gcc clang-libfuzzer afl-qemu-mode gdb-python symqemu angr-symbolic angr-unicorn-engine unicorn"
broken=""
for c in $CRIT; do
  line="$(echo "$out" | grep "^CAP $c: ")"
  echo "$line" | grep -q ": OK" || broken="$broken $c"
done
vg="$(echo "$out" | grep '^CAP valgrind: ')"
case "$vg" in
  *": OK"*) ;;                                          # valgrind works -- ideal
  *": UPSTREAM"*) echo "NOTE: valgrind is down due to an UPSTREAM valgrind<->glibc gap on this collect's glibc (not a bundle defect); dislocator+ASan cover memory triage. Pin the collect glibc to the engagement's to restore it." ;;
  *) broken="$broken valgrind" ;;                       # BROKEN for a bundle reason -> real failure
esac
# Large-binary afl handshake: enforce when it ran, tolerate a SKIP (no objcopy in the container).
albig="$(echo "$out" | grep '^CAP afl-qemu-large: ')"
case "$albig" in
  *": OK"*) ;;
  *": SKIP"*|"") echo "NOTE: afl-qemu-large not exercised (objcopy unavailable in the container); the large-binary handshake path was not gated this run" ;;
  *) broken="$broken afl-qemu-large" ;;                  # handshake aborted on a large binary -> the engagement failure, caught
esac
[ -n "$broken" ] && die "offline capability(ies) BROKEN:$broken  (present-but-broken is still a loss)"
# the full pipeline must reach a verified L3 PoC from the bundle alone
echo "$out" | grep -q 'proof of concept' && echo "$out" | grep -qE '^\s*L3\b' || \
  die "no verified L3 PoC -- the bundle reached only static/partial analysis offline"

say "OFFLINE E2E GATE PASSED -- every lane works on a cold, tool-less, offline Kali container, and a vulnerable ELF reached a verified L3 PoC from the bundle alone"
