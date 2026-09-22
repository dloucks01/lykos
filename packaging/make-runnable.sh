#!/usr/bin/env bash
# Build the ONE-ZIP, unzip-and-run air-gap package: a single .zip that already contains the
# repo AND a fully-populated vendor/ (every tool extracted, pypcode vendored, relocatable
# wrappers generated). On the air-gapped laptop you just:
#
#     unzip lykos-airgapped-*.zip
#     cd lykos
#     ./RUN.sh            # or: make run
#
# No install, no setup step, nothing placed in system directories, and the laptop's own
# libraries are never touched (each tool runs through a relocatable scoped wrapper). Run this on
# the CONNECTED machine after `make toolchain-bundle`.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
say(){ printf '\n== %s\n' "$*"; }
die(){ echo "ERROR: $*" >&2; exit 1; }

command -v zip >/dev/null 2>&1 || die "need zip (apt-get install zip)"
TC="$(ls -1t "$DIST"/lykos-toolchain-*.tar.zst 2>/dev/null | head -1 || true)"
[ -n "$TC" ] || die "no toolchain bundle in dist/ -- run 'make toolchain-bundle' first"

STAGE="$(mktemp -d)"; BUN="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$BUN"' EXIT

say "repo snapshot from the working tree (no commit)"
# temp index -> dangling commit -> archive, so the current working tree (incl. the no-install
# code) ships without touching HEAD/branch. .gitignore keeps dist/ and vendor/ out.
tmpidx="$(mktemp)"; cp "$ROOT/.git/index" "$tmpidx" 2>/dev/null || : > "$tmpidx"
GIT_INDEX_FILE="$tmpidx" git -C "$ROOT" add -A
tree="$(GIT_INDEX_FILE="$tmpidx" git -C "$ROOT" write-tree)"
commit="$(git -C "$ROOT" commit-tree "$tree" -m 'runnable snapshot')"
rm -f "$tmpidx"
mkdir -p "$STAGE"
git -C "$ROOT" archive --prefix=lykos/ "$commit" | tar -x -C "$STAGE"
APP="$STAGE/lykos"

say "extracting the toolchain bundle"
tar xf "$TC" -C "$BUN"

say "populating vendor/ (tools ready to run in place)"
V="$APP/vendor"; mkdir -p "$V"
cp -a "$BUN/toolchain" "$V/toolchain"
# per-guest afl-qemu emulators onto the vendored tree
if [ -n "$(ls -A "$BUN/afl-qemu" 2>/dev/null)" ]; then
  mkdir -p "$V/toolchain/usr/local/bin"
  for f in "$BUN"/afl-qemu/*; do install -m 0755 "$f" "$V/toolchain/usr/local/bin/"; done
fi
# engine venvs: keep their ORIGINAL pyvenv.cfg -- they were built for the TARGET distro's
# Python (the bundle is distro-locked), not this build host's.
for v in "$BUN"/venvs/*-venv; do [ -d "$v" ] && cp -a "$v" "$V/$(basename "$v")"; done
# vendored Python site (pypcode) -> vendor/pysite (lykos puts it on sys.path)
[ -d "$BUN/pysite" ] && [ -n "$(ls -A "$BUN/pysite" 2>/dev/null)" ] && cp -a "$BUN/pysite" "$V/pysite"
# non-apt engines staged under extras/
for g in "$BUN"/extras/ghidra/*/; do [ -d "$g" ] && cp -a "$g" "$V/ghidra"; done
[ -d "$BUN/extras/symqemu" ] && [ -n "$(ls -A "$BUN/extras/symqemu" 2>/dev/null)" ] && \
  { mkdir -p "$V/symqemu"; cp -a "$BUN"/extras/symqemu/* "$V/symqemu/"; }
printf '  vendor/ is %s\n' "$(du -sh "$V" | cut -f1)"

say "vendoring a self-contained Python (the bundle runs under its OWN interpreter, not the laptop's)"
# The engine venvs + the pypcode wheel are ABI-locked to ONE Python minor version. Historically
# the bundle relied on the LAPTOP already having that exact python3 -- when it did not (a different
# distro/version), pypcode/angr/unicorn silently vanished. Ship a matching interpreter instead.
# REQUIRE this build host's python to equal the venvs' version so interpreter, venvs and pypcode
# are one ABI. (glibc still couples the native binaries -- build on the OLDEST target glibc, or use
# the CONTAINER image which escapes that too; see docs/23.)
venv_py=""
for c in "$V"/*-venv/pyvenv.cfg; do
  [ -f "$c" ] || continue
  venv_py="$(sed -n 's/^version *= *\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' "$c" | head -1)"
  [ -n "$venv_py" ] && break
done
[ -n "$venv_py" ] || venv_py="$(ls -d "$V"/*-venv/lib/python3.* 2>/dev/null | sed -n 's#.*/python\(3\.[0-9][0-9]*\)$#\1#p' | head -1)"
host_py="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || true)"
if [ -n "$venv_py" ] && [ "$venv_py" != "$host_py" ]; then
  die "toolchain venvs are Python $venv_py but this build host runs ${host_py:-unknown}. Run make-runnable on a Python $venv_py host so the vendored interpreter, the venvs and pypcode share one ABI (or rebuild the toolchain bundle here)."
fi
PYV="${venv_py:-$host_py}"
[ -n "$PYV" ] || die "cannot determine a Python version to vendor"
PYBIN="$(command -v "python$PYV" 2>/dev/null || command -v python3)"; PYBIN="$(readlink -f "$PYBIN")"
STDLIB="$("$PYBIN" -c 'import sysconfig;print(sysconfig.get_path("stdlib"))')"
TUB="$V/toolchain/usr/bin"; TUL="$V/toolchain/usr/lib"; mkdir -p "$TUB" "$TUL"
install -m0755 "$PYBIN" "$TUB/python$PYV"
ln -sf "python$PYV" "$TUB/python3"; ln -sf "python$PYV" "$TUB/python"
rm -rf "$TUL/python$PYV"; cp -a "$STDLIB" "$TUL/python$PYV"          # stdlib incl lib-dynload
"$PYBIN" - "$TUL" <<'PYEOF'                                          # libpython shared object
import sys, sysconfig, glob, os, shutil
dst = sys.argv[1]
libdir = sysconfig.get_config_var("LIBDIR") or "/usr/lib"
mult = sysconfig.get_config_var("MULTIARCH") or ""
names = {n for n in (sysconfig.get_config_var("LDLIBRARY"), sysconfig.get_config_var("INSTSONAME")) if n}
for base in {libdir, os.path.join(libdir, mult) if mult else libdir}:
    for n in names:
        for f in glob.glob(os.path.join(base, n + "*")):
            try: shutil.copy2(f, dst)
            except OSError: pass
PYEOF
# Find libpython by a RELATIVE ($ORIGIN) rpath so the interpreter -- and the engine venvs that
# symlink to it -- load it with NO global LD_LIBRARY_PATH (which would leak onto other tools).
# Resolved from the real binary's location, so it survives both relocation and the venv symlinks.
if command -v patchelf >/dev/null 2>&1; then
  patchelf --set-rpath '$ORIGIN/../lib:$ORIGIN/../lib/x86_64-linux-gnu' "$TUB/python$PYV" 2>/dev/null \
    || echo "  WARN: patchelf failed; venv pythons will rely on RUN.sh's LD_LIBRARY_PATH"
else
  echo "  NOTE: no patchelf; the interpreter finds libpython via RUN.sh's LD_LIBRARY_PATH instead"
fi
printf '  vendored Python %s + stdlib (%s); venvs are repointed at RUN time by vendorenv\n' \
  "$PYV" "$(du -sh "$TUL/python$PYV" 2>/dev/null | cut -f1)"

say "sanitising the tree (make the archive extract cleanly, drop desktop/i18n bloat)"
# 1) Unicode-named venv symlinks (a CPython easter egg: bin/𝜋thon -> python3). A non-ASCII path
#    makes `unzip` prompt or mangle it under a C/POSIX locale, which reads as a hang. The venv
#    still works through its normal python3 link, so just remove these.
find "$V" -name '*thon' -type l 2>/dev/null | while IFS= read -r l; do
  case "$(basename "$l")" in python|python3|python3.*) : ;; *) rm -f "$l" ;; esac
done
find "$V" -depth -type l ! -name 'python' ! -name 'python3' ! -name 'python3.*' \
  -exec sh -c 'LC_ALL=C printf "%s\n" "$1" | grep -qP "[^\x00-\x7f]" && rm -f "$1"' _ {} \; 2>/dev/null || true
# 2) Desktop / audio / i18n / doc bloat that lykos never touches (headless RE tools only). This
#    also removes the ONLY duplicate paths in the archive -- ALSA ucm2 configs stored twice --
#    which are what made `unzip` stop and prompt "replace? [y]". rizin/qemu/gdb/wine data stays.
TC="$V/toolchain/usr/share"
for d in alsa sounds icons fonts themes backgrounds pixmaps applications mime X11 \
         locale doc man man-db info help gnome gtk-doc bug metainfo appdata; do
  rm -rf "$TC/$d" 2>/dev/null || true
done
# 2b) dpkg/apt package-management tooling (the Dpkg perl modules + apt data). Pulled in as a
#     transitive dependency of some packaged tool, but lykos is a headless RE pipeline and never
#     shells out to dpkg/apt -- and this tree of many tiny .pm files is what the user saw scroll
#     past (and mis-extract) right beside the Unicode venv links during a slow unzip. Drop it.
rm -rf "$TC/perl5/Dpkg" "$TC/perl5/Dpkg.pm" "$TC/dpkg" "$TC/apt" 2>/dev/null || true
find "$V/toolchain/usr/bin" -maxdepth 1 -name 'dpkg*' -o -name 'apt*' 2>/dev/null \
  | while IFS= read -r f; do rm -f "$f" 2>/dev/null || true; done
# 2c) BUILD-ONLY toolchains lykos never runs. The pipeline compiles uploaded source ONLY
#     natively (x86_64 ASan/UBSan, ingest.py) and EXECUTES foreign-arch binaries under qemu-user
#     (sandbox.py) -- it never cross-compiles, and PoCs/exploits are input BYTES replayed in the
#     sandbox, not compiled code. So the cross/PE COMPILERS go while qemu-<arch> and every arch's
#     RUNTIME libs (usr/<triple>/lib -- what qemu needs to run a dynamically-linked guest) STAY.
#     This is the bulk of the bundle (~6.7GB): keeping it only let the laptop run `make arch-gate`,
#     a CI self-test, which is not analysis. Verified nothing in the bundle links libLLVM.
TCU="$V/toolchain/usr"
#   (a) cross-compiler backends + their support libs (native usr/libexec/gcc/x86_64 stays)
rm -rf "$TCU/libexec/gcc-cross" "$TCU/lib/gcc-cross" 2>/dev/null || true
#   (b) per-arch cross driver + LTO binaries under bin/. x86_64-linux-gnu-* IS the native
#       compiler and must survive EXCEPT its lto-dump; lto-dump is never invoked (drop it for
#       every arch). Match symlinks too (-type l): the cross lto-dumps are symlinks to their
#       -NN target, and -type f alone left them behind.
find "$TCU/bin" -maxdepth 1 \( -type f -o -type l \) 2>/dev/null | while IFS= read -r f; do
  b="$(basename "$f")"
  case "$b" in *lto-dump*) rm -f "$f"; continue ;; esac    # never invoked, any arch incl native
  case "$b" in x86_64-linux-gnu-*) continue ;; esac        # native toolchain -- keep the rest
  case "$b" in
    *-linux-gnu-gcc|*-linux-gnu-gcc-*|*-linux-gnu-g++|*-linux-gnu-cpp|*-linux-gnu-gfortran|\
    *-linux-gnu-gccgo|*-linux-gnueabihf-gcc|*-linux-gnueabihf-gcc-*|*-linux-gnueabihf-g++|\
    *-linux-gnueabihf-cpp|*-linux-gnueabihf-gfortran) rm -f "$f" ;;
  esac
done
#   (c) cross sysroot HEADERS (compile-only); usr/<triple>/lib runtime is kept
for d in "$TCU"/*-linux-gnu "$TCU"/*-linux-gnueabihf; do
  [ -d "$d" ] || continue
  case "$(basename "$d")" in x86_64-linux-gnu) : ;; *) rm -rf "$d/include" 2>/dev/null || true ;; esac
done
#   (d) MinGW Windows cross toolchain -- builds PE fixtures only (Wine still RUNS PE binaries)
rm -rf "$TCU/lib/gcc/x86_64-w64-mingw32" "$TCU/x86_64-w64-mingw32" "$TCU/share/mingw-w64" 2>/dev/null || true
find "$TCU/bin" -maxdepth 1 -name '*-w64-mingw32-*' -exec rm -f {} + 2>/dev/null || true
#   (e) LLVM/clang -- only a FALLBACK compiler (native gcc preferred everywhere); nothing links it
rm -rf "$TCU/lib/llvm-21" 2>/dev/null || true
# LLVM/clang C++ dev HEADERS (compile-only). Do NOT touch the rest of usr/include -- the native
# gcc needs the C headers to compile uploaded source.
rm -rf "$TCU/include/llvm-21" "$TCU/include/clang" "$TCU/include/clang-c" \
       "$TCU/include/lld" "$TCU/include/lldb" "$TCU/include/mlir" "$TCU/include/polly" 2>/dev/null || true
find "$TCU/lib/x86_64-linux-gnu" -maxdepth 1 \( -name 'libLLVM*' -o -name 'libclang*' \) -exec rm -f {} + 2>/dev/null || true
find "$TCU/bin" -maxdepth 1 \( -name 'clang*' -o -name 'llvm*' -o -name 'llc' -o -name 'opt' \
  -o -name 'lli' -o -name 'ld.lld' -o -name 'lld*' -o -name 'wasm-ld' \) -exec rm -f {} + 2>/dev/null || true
#   (f) Node.js -- only the `make gui` JS test harness uses it; the web console is served by the
#       Python API from static files. Nothing in the analysis path runs node.
find "$TCU/bin" -maxdepth 1 \( -name 'node' -o -name 'nodejs' \) -exec rm -f {} + 2>/dev/null || true
find "$TCU/lib" -name 'libnode.so*' -exec rm -f {} + 2>/dev/null || true
#   Guard: the native compiler and the foreign-exec substrate MUST survive the trim, or the
#   bundle is silently broken. Fail the build loudly if any did not.
for need in \
    "$TCU/libexec/gcc/x86_64-linux-gnu" "$TCU/bin/rizin" "$TCU/bin/qemu-aarch64" \
    "$TCU/aarch64-linux-gnu/lib" "$TCU/bin/wine"; do
  ls -d "$need" >/dev/null 2>&1 || ls "$need"* >/dev/null 2>&1 || die "trim removed a REQUIRED path: $need"
done
ls "$TCU"/bin/x86_64-linux-gnu-gcc* >/dev/null 2>&1 || die "trim removed the native x86_64 gcc"
# 3) Belt-and-braces: fail loudly if any duplicate path survived (a dup = an interactive prompt).
dups="$(cd "$STAGE" && find lykos -printf '%p\n' | sort | uniq -d | head)"
[ -z "$dups" ] || { echo "WARN: duplicate archive paths remain:"; echo "$dups"; }
printf '  vendor/ is now %s\n' "$(du -sh "$V" | cut -f1)"

say "generating relocatable scoped wrappers"
# reuse setup.sh's generator so there is one implementation of the wrapper contract
eval "$(sed -n '/^gen_wrappers() {/,/^}/p' "$ROOT/packaging/setup-toolchain.sh")"
gen_wrappers "$V/toolchain"

say "launcher + quickstart"
cat > "$APP/RUN.sh" <<'EOF'
#!/usr/bin/env sh
# Unzip-and-run launcher. Serves the lykos console on http://127.0.0.1:8787 (loopback only).
# Everything runs in place from ./vendor -- no install, nothing touched on this machine.
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"
# Prefer the bundle's OWN Python -- it matches the pypcode wheel and the engine venvs, so the
# analysis works regardless of what python3 (if any) the laptop has. Fall back to the system
# python3 only if this bundle was built without a vendored interpreter.
py="$here/vendor/toolchain/usr/bin/python3"
if [ -x "$py" ]; then
  ld="$here/vendor/toolchain/usr/lib:$here/vendor/toolchain/usr/lib/x86_64-linux-gnu"
  export LD_LIBRARY_PATH="$ld${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
else
  py=python3
fi
# stdin < /dev/null: no analysis tool can then block reading an inherited pipe/terminal.
exec env PYTHONPATH="$here/core" "$py" -m lykos serve --http 127.0.0.1:8787 \
     --case-store "$here/.cases" --workers 2 < /dev/null
EOF
chmod +x "$APP/RUN.sh"
cat > "$APP/RUN-HERE-FIRST.txt" <<'EOF'
lykos -- air-gapped, unzip-and-run. No installation. Nothing is written outside this folder.

  1. You already unzipped this (use `unzip -o` if it prompts). Everything is inside ./vendor.
  2. Check what this host can do:   PYTHONPATH=core python3 -m lykos doctor
  3. Run it:                        ./RUN.sh      (or: make run)
     Then open http://127.0.0.1:8787 in a browser on this machine.

The analysis tools (rizin, gdb, qemu, wine, afl++, the cross-compilers, the JVM, ...) live
under vendor/toolchain and run through relocatable wrappers, so they use ONLY the bundle's own
libraries -- your laptop's libraries are never replaced or relinked. See docs/23-airgap-install.md.
EOF

say "zipping the single runnable package"
STAMP="$(date +%Y%m%d)"; ARCH="$(uname -m)"
OUT="$DIST/lykos-airgapped-$STAMP-$ARCH.zip"
rm -f "$OUT"
( cd "$STAGE" && zip -q -r -y "$OUT" lykos )   # -y: store symlinks as symlinks (venvs, libs)
( cd "$DIST" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256" )

say "done"
printf '  %s (%s)\n' "$OUT" "$(du -h "$OUT" | cut -f1)"
cat "$OUT.sha256" | sed 's/^/  /'
cat <<EOF

On the air-gapped laptop (verify, then unzip and run -- nothing is installed):
  sha256sum -c $(basename "$OUT").sha256
  unzip -o $(basename "$OUT")     # -o = never prompt; extracts non-interactively
  cd lykos && ./RUN.sh
EOF
