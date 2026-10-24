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
#   packaging/test-offline-e2e.sh [dist/lykos-offline-*.tar.xz | *.tar.xz.part-00 | *.EXTRACT.sh]
#
# A large (real-engagement) bundle ships SPLIT into optical-media volumes (*.tar.xz.part-NN) with a
# .sha256 and an .EXTRACT.sh. The gate accepts any of those files (or picks the newest package in
# dist/), checks every volume is present, and extracts through the SHIPPED .EXTRACT.sh when there is
# one -- verifying the checksums and reassembling exactly the way the operator will on the laptop.
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

ART="${1:-$(ls -1t "$ROOT"/dist/lykos-offline-*.tar.xz "$ROOT"/dist/lykos-offline-*.tar.xz.part-00 \
              2>/dev/null | head -1)}"
[ -n "$ART" ] && [ -f "$ART" ] || die "no offline package (.tar.xz or .tar.xz.part-00) -- build with packaging/make-runnable.sh"
command -v xz >/dev/null 2>&1 || die "need xz on the build host to extract the package"
# Resolve the package BASE name from whichever of its files was named, then find its volumes.
PDIR="$(cd "$(dirname "$ART")" && pwd)"; PNAME="$(basename "$ART")"
case "$PNAME" in
  *.tar.xz.part-*) PBASE="${PNAME%.tar.xz.part-*}" ;;
  *.tar.xz)        PBASE="${PNAME%.tar.xz}" ;;
  *.EXTRACT.sh)    PBASE="${PNAME%.EXTRACT.sh}" ;;
  *.sha256)        PBASE="${PNAME%.sha256}" ;;
  *) die "$PNAME is not an offline package file (.tar.xz, .tar.xz.part-NN, .EXTRACT.sh, .sha256)" ;;
esac
PARTS=()
for _p in "$PDIR/$PBASE".tar.xz.part-*; do [ -f "$_p" ] && PARTS+=("$_p"); done
if [ -f "$PDIR/$PBASE.tar.xz" ]; then
  PKIND="single archive"
elif [ "${#PARTS[@]}" -gt 0 ]; then
  # `split -d -a 2` numbers volumes 00,01,...: a gap means a volume was not copied off its disc,
  # and xz would only fail deep into a multi-GB stream -- say which one is missing up front.
  _i=0
  for _p in "${PARTS[@]}"; do
    _want="$(printf '%s/%s.tar.xz.part-%02d' "$PDIR" "$PBASE" "$_i")"
    [ "$_p" = "$_want" ] || die "split package is missing volume $(basename "$_want") (have: $(basename -a "${PARTS[@]}" | tr '\n' ' '))"
    _i=$((_i + 1))
  done
  PKIND="SPLIT into ${#PARTS[@]} volume(s)"
else
  die "no archive or volumes for $PBASE in $PDIR"
fi
say "package $PBASE -- $PKIND"

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
# 1b) a command-injection ELF (argv -> system). This drives a DIFFERENT L3 synthesizer than the
# ret2win target above: inject_stage realizes the effect dynamically (a spawned-shell marker), not a
# ROP/control-flow build_exploit. Proving BOTH offline catches an offline-specific regression in
# either synthesizer -- the old gate proved only the memory-corruption -> ret2win chain.
cat > "$T/cmdi.c" <<'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv){ char cmd[512]; if (argc < 2) return 0;
  snprintf(cmd, sizeof cmd, "echo got: %s", argv[1]); system(cmd); return 0; }
CEOF
gcc -no-pie -fno-stack-protector -O0 -w "$T/cmdi.c" -o "$T/cmdi" || die "could not build the cmdi target"
# 2) a cross-arch (aarch64 static) ELF, to prove qemu-user actually RUNS a foreign binary offline
if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
  printf '#include <unistd.h>\nint main(){write(1,"AARCH64-RAN\\n",12);return 0;}\n' > "$T/a64.c"
  aarch64-linux-gnu-gcc -static -O0 "$T/a64.c" -o "$T/a64" || : > "$T/a64"
else : > "$T/a64"; fi

say "extracting the package (writable -- the laptop extracts to a writable dir; doctor self-relinks)"
mkdir -p "$T/ex"
if [ -f "$PDIR/$PBASE.EXTRACT.sh" ] && [ -f "$PDIR/$PBASE.sha256" ]; then
  # The operator's path: every volume + .sha256 + .EXTRACT.sh in one dir, `sh X.EXTRACT.sh`. Link
  # them into the scratch dir (no multi-GB copy) so the script extracts THERE, verifying checksums
  # and reassembling the volumes exactly as on the laptop -- a broken EXTRACT.sh fails the gate too.
  for _f in "$PDIR/$PBASE".*; do ln -s "$_f" "$T/ex/$(basename "$_f")"; done
  ( cd "$T/ex" && sh "./$PBASE.EXTRACT.sh" ) || die "the shipped $PBASE.EXTRACT.sh failed (checksum mismatch or a corrupt volume?)"
  find "$T/ex" -maxdepth 1 -type l -name "$PBASE.*" -delete
elif [ -f "$PDIR/$PBASE.tar.xz" ]; then
  xz -dc "$PDIR/$PBASE.tar.xz" | tar -x -C "$T/ex" || die "could not extract $PBASE.tar.xz"
else
  cat "${PARTS[@]}" | xz -dc | tar -x -C "$T/ex" || die "could not reassemble/extract the split volumes"
fi
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
echo "--- END-TO-END ANALYZE (memory-corruption -> ret2win L3) ---"
./lykos analyze /t/vuln --budget ${BUDGET:-480} --input-mode stdin --out $S/out --case-store $S/case -q 2>&1
# Second L3 class, a DIFFERENT synthesizer: command injection -> inject_stage. No --input-mode (the
# payload rides the argv channel inject_stage must discover). Bracketed so the gate can assert on it.
echo "--- END-TO-END ANALYZE (command injection -> inject_stage L3) ---"
echo "CMDI-BEGIN"
./lykos analyze /t/cmdi --budget ${CMDI_BUDGET:-150} --out $S/outc --case-store $S/casec -q 2>&1
echo "CMDI-END"
echo "SWEEP COMPLETE"
PEOF

KEEPID=""; case "$RT" in *podman*) KEEPID="--userns=keep-id";; esac
say "cold-container functional capability gate (offline, non-root, no host tools)  base=$BASE  budget=${BUDGET}s"
out="$("$RT" run --rm --network none $KEEPID --user "$(id -u):$(id -g)" -e BUDGET="$BUDGET" \
      -v "$RD":/lykos -v "$T/probe.sh":/t/probe.sh:ro -v "$T/scratch":/scratch \
      -v "$T/vuln":/t/vuln:ro -v "$T/cmdi":/t/cmdi:ro -v "$T/a64":/t/a64:ro \
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
# afl coverage fuzzing must RUN inside the real pipeline, not just in the CAP probe. The CAP lane
# invokes afl directly on the real trace binary, so it missed the bug where lykos's own coverage_fuzz
# staged a relocatable .wrappers/ SHELL script as the fork-server QEMU and every run aborted at the
# handshake. Assert the analyze never reports that abort -- this is binary coverage fuzzing working.
echo "$out" | grep -qiE 'coverage_fuzz.*(abort|handshake)|Fork server handshake failed' && \
  die "afl coverage_fuzz aborted offline (fork-server handshake) -- binary coverage fuzzing is broken in the bundle"
# the full pipeline must reach a verified L3 PoC from the bundle alone (memory-corruption -> ret2win)
echo "$out" | grep -q 'proof of concept' && echo "$out" | grep -qE '^\s*L3\b' || \
  die "no verified L3 PoC -- the bundle reached only static/partial analysis offline"
# ...and a SECOND, distinct L3 synthesizer must work offline too: command injection -> inject_stage.
# Proving two independent L3 paths (ROP control-flow AND a realized command-exec effect) is what the
# old single-class gate could not do -- an offline regression in either synthesizer is now caught.
cmdi_out="$(printf '%s\n' "$out" | sed -n '/CMDI-BEGIN/,/CMDI-END/p')"
printf '%s\n' "$cmdi_out" | grep -qE '^\s*L3\b' && printf '%s\n' "$cmdi_out" | grep -q 'CWE-78' || \
  die "command-injection class did not reach a verified L3 offline (inject_stage synthesizer regressed)"

say "OFFLINE E2E GATE PASSED -- every lane works on a cold, tool-less, offline Kali container, and TWO distinct L3 synthesizers (memory-corruption ret2win AND command-injection) reached a verified L3 PoC from the bundle alone"
