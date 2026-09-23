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

# afl-qemu-trace (per-guest coverage emulators) and symqemu are built SEPARATELY from the base
# toolchain collection (per-arch / heavy source builds), so a bundle may predate them. Let a caller
# inject already-built ones via LYKOS_AFLQEMU_DIR / LYKOS_SYMQEMU_DIR; they land in the same place
# the bundle would carry them, so the vendoring below is unchanged.
if [ -n "${LYKOS_AFLQEMU_DIR:-}" ] && [ -n "$(ls -A "$LYKOS_AFLQEMU_DIR" 2>/dev/null)" ]; then
  mkdir -p "$BUN/afl-qemu"; cp -a "$LYKOS_AFLQEMU_DIR"/. "$BUN/afl-qemu/"
  say "injected afl-qemu-trace from $LYKOS_AFLQEMU_DIR"
fi
if [ -n "${LYKOS_SYMQEMU_DIR:-}" ] && [ -n "$(ls -A "$LYKOS_SYMQEMU_DIR" 2>/dev/null)" ]; then
  mkdir -p "$BUN/extras/symqemu"; cp -a "$LYKOS_SYMQEMU_DIR"/. "$BUN/extras/symqemu/"
  say "injected symqemu from $LYKOS_SYMQEMU_DIR"
fi

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
[ -n "$host_py" ] || die "no python3 on the build host to vendor"
# The pypcode wheel is ABI-locked TOO (and the venvs routinely fail to build, so venv_py can be
# empty). Derive the minor pypcode was built for from its extension tag (cpython-3XY) and require
# every ABI-locked component that IS present to match the host python we are about to vendor --
# otherwise `import pypcode`/angr/unicorn fails on the laptop, the very bug this feature prevents.
pysite_py=""
_pyso="$(ls "$V"/pysite/pypcode/*.so 2>/dev/null | head -1)"
[ -n "$_pyso" ] && pysite_py="$(printf '%s' "$_pyso" | sed -n 's/.*cpython-3\([0-9][0-9]*\).*/3.\1/p')"
for pair in "engine venvs:$venv_py" "the pypcode wheel:$pysite_py"; do
  what="${pair%%:*}"; ver="${pair#*:}"
  if [ -n "$ver" ] && [ "$ver" != "$host_py" ]; then
    die "$what are Python $ver but this build host runs $host_py. Run make-runnable on a Python $ver host (or rebuild the toolchain bundle here) so the vendored interpreter, the venvs and the pypcode wheel share one ABI."
  fi
done
PYV="$host_py"
PYBIN="$(command -v "python$PYV" 2>/dev/null || command -v python3)"; PYBIN="$(readlink -f "$PYBIN")"
MULTIARCH="$("$PYBIN" -c 'import sysconfig;print(sysconfig.get_config_var("MULTIARCH") or "")')"
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
# patchelf is REQUIRED for this path: it gives the interpreter AND its stdlib C-extensions an
# $ORIGIN-relative rpath into the bundle's own libs, so the whole vendored Python is self-contained
# with NO global LD_LIBRARY_PATH (which would leak the bundle's libraries onto every other tool the
# server spawns). Without it the venv engines and half the stdlib fail off the RUN.sh path -- refuse
# to ship a bundle that only half-works. Arch-neutral: the multiarch triple is derived, not assumed.
command -v patchelf >/dev/null 2>&1 || die "patchelf is required to vendor a self-contained Python (apt-get install patchelf)"
_ma="${MULTIARCH:+:\$ORIGIN/../lib/$MULTIARCH}"
patchelf --set-rpath "\$ORIGIN/../lib$_ma" "$TUB/python$PYV" || die "patchelf failed on the interpreter"
# stdlib C-extensions (_ssl, _ctypes, _sqlite3, _lzma, ...) link libssl/libffi/liblzma from the
# bundle -- point them there relative to their own location so no LD_LIBRARY_PATH is needed.
_dma="${MULTIARCH:+:\$ORIGIN/../../$MULTIARCH}"
for so in "$TUL/python$PYV"/lib-dynload/*.so; do
  [ -f "$so" ] && { patchelf --set-rpath "\$ORIGIN/../..$_dma" "$so" 2>/dev/null || true; }
done
# Prove the vendored interpreter works with NO help from the host and NO global LD path -- import
# the stdlib modules lykos and the engines rely on. Fail the build NOW, not on the air-gapped
# laptop, if the apt closure is missing a non-glibc dependency (libffi/libssl/liblzma/...).
env -i HOME=/tmp PATH=/usr/bin:/bin "$TUB/python$PYV" - <<'PYCHK' \
  || die "vendored Python failed its self-contained import smoke-test -- a non-glibc dependency is missing from the toolchain tree (libffi/libssl/liblzma/...); add it to the toolchain package list and rebuild the bundle"
import sys
for m in ("ctypes", "ssl", "sqlite3", "lzma", "bz2", "hashlib", "zlib", "socket", "json", "struct"):
    __import__(m)
print("  vendored python self-check OK (no LD_LIBRARY_PATH):", sys.version.split()[0])
PYCHK
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
# THIS build host's native GNU triple (x86_64-linux-gnu, aarch64-linux-gnu, ...). The trim keeps
# the native compiler and mispoints nothing when the build host is not x86_64.
NATIVE_TRIPLE="$(gcc -dumpmachine 2>/dev/null || echo x86_64-linux-gnu)"
#   (a) cross-compiler backends + their support libs (native usr/libexec/gcc/<native> stays)
rm -rf "$TCU/libexec/gcc-cross" "$TCU/lib/gcc-cross" 2>/dev/null || true
#   (b) per-arch cross driver + LTO binaries under bin/. x86_64-linux-gnu-* IS the native
#       compiler and must survive EXCEPT its lto-dump; lto-dump is never invoked (drop it for
#       every arch). Match symlinks too (-type l): the cross lto-dumps are symlinks to their
#       -NN target, and -type f alone left them behind.
find "$TCU/bin" -maxdepth 1 \( -type f -o -type l \) 2>/dev/null | while IFS= read -r f; do
  b="$(basename "$f")"
  case "$b" in *lto-dump*) rm -f "$f"; continue ;; esac    # never invoked, any arch incl native
  case "$b" in "${NATIVE_TRIPLE}"-*) continue ;; esac      # native toolchain -- keep the rest
  case "$b" in
    *-linux-gnu-gcc|*-linux-gnu-gcc-*|*-linux-gnu-g++|*-linux-gnu-cpp|*-linux-gnu-gfortran|\
    *-linux-gnu-gccgo|*-linux-gnueabihf-gcc|*-linux-gnueabihf-gcc-*|*-linux-gnueabihf-g++|\
    *-linux-gnueabihf-cpp|*-linux-gnueabihf-gfortran) rm -f "$f" ;;
  esac
done
#   (c) cross sysroot HEADERS (compile-only); usr/<triple>/lib runtime is kept
for d in "$TCU"/*-linux-gnu "$TCU"/*-linux-gnueabihf; do
  [ -d "$d" ] || continue
  case "$(basename "$d")" in "$NATIVE_TRIPLE") : ;; *) rm -rf "$d/include" 2>/dev/null || true ;; esac
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
find "$TCU/lib/$NATIVE_TRIPLE" -maxdepth 1 \( -name 'libLLVM*' -o -name 'libclang*' \) -exec rm -f {} + 2>/dev/null || true
find "$TCU/bin" -maxdepth 1 \( -name 'clang*' -o -name 'llvm*' -o -name 'llc' -o -name 'opt' \
  -o -name 'lli' -o -name 'ld.lld' -o -name 'lld*' -o -name 'wasm-ld' \) -exec rm -f {} + 2>/dev/null || true
#   (f) Node.js -- only the `make gui` JS test harness uses it; the web console is served by the
#       Python API from static files. Nothing in the analysis path runs node.
find "$TCU/bin" -maxdepth 1 \( -name 'node' -o -name 'nodejs' \) -exec rm -f {} + 2>/dev/null || true
find "$TCU/lib" -name 'libnode.so*' -exec rm -f {} + 2>/dev/null || true
#   Guard: the native compiler and the foreign-exec substrate MUST survive the trim, or the
#   bundle is silently broken. Fail the build loudly if any did not.
for need in \
    "$TCU/libexec/gcc/$NATIVE_TRIPLE" "$TCU/bin/rizin" "$TCU/bin/qemu-aarch64" \
    "$TCU/aarch64-linux-gnu/lib" "$TCU/bin/wine"; do
  ls -d "$need" >/dev/null 2>&1 || ls "$need"* >/dev/null 2>&1 || die "trim removed a REQUIRED path: $need"
done
ls "$TCU"/bin/"$NATIVE_TRIPLE"-gcc* >/dev/null 2>&1 || die "trim removed the native ($NATIVE_TRIPLE) gcc"
# 3) The real duplicate-path check runs AFTER zipping, against the archive itself (a filesystem
#    tree cannot hold the same path twice, so the old find|uniq here could never fire). See below.
printf '  vendor/ is now %s\n' "$(du -sh "$V" | cut -f1)"

# ---- SELF-CONTAINMENT: vendor the full transitive shared-library closure of every bundled ELF ----
# The trim above (and whatever the toolchain tarball happened to include) can leave the bundle short
# a library a bundled tool needs -- libexpat.so.1 / libsqlite3.so.0 for Python, libglib/libpixman for
# afl-qemu-trace, and so on. The build host HAS those system-wide, so the interpreter smoke-test above
# passes while the bundle is actually INCOMPLETE; the gap only shows on a lean air-gapped laptop as
# "python3: libexpat.so.1: cannot open shared object file" or a REQUIRED tool reading "-- not found --".
# This walks every ELF in the bundle, resolves its NEEDED libraries on THIS host (ldd is transitive),
# and copies any non-glibc one that is not already vendored into the multiarch lib dir -- which both
# the interpreter's rpath ($ORIGIN/../lib/<ma>) and the tool wrappers' LD_LIBRARY_PATH already point
# at. glibc itself stays the one documented coupling (build on the oldest target glibc). Idempotent.
say "vendoring the shared-library closure (self-containment)"
# The closure pass is best-effort (any lib it cannot copy is simply skipped) and its inner tests --
# `grep -q ELF`, `find|grep -q`, `cp && echo` -- return non-zero as normal control flow. Under the
# script's `set -e` the first non-ELF file would abort the WHOLE build (it did: only libtinfo copied,
# no zip produced). Disable errexit for this block and restore it after.
set +e
CLOSDIR="$V/toolchain/usr/lib/${MULTIARCH:-x86_64-linux-gnu}"; mkdir -p "$CLOSDIR"
# An index of what the bundle ALREADY has, by soname basename -- built once, checked in O(1) with a
# hash, and updated as we copy. (The old per-lib `find` over a 4 GB tree was O(elfs x libs x tree)
# and crawled.) Everything runs with errexit OFF so a non-ELF file or an empty grep is normal flow.
HAVE="$STAGE/.closure_have"
find "$V" -type f \( -name '*.so' -o -name '*.so.*' \) -printf '%f\n' 2>/dev/null | sort -u > "$HAVE"
_is_core_lib() { case "$1" in \
  libc.so*|libm.so*|libdl.so*|libpthread.so*|librt.so*|libresolv.so*|libutil.so*|libnsl.so*|\
  ld-linux*|linux-vdso*|libgcc_s.so*|libcrypt.so*) return 0 ;; *) return 1 ;; esac ; }
_vendor_needed_of() {                                  # copy the not-yet-bundled NEEDED libs of $1
  ldd "$1" 2>/dev/null | awk '/=> \//{print $3}' | while IFS= read -r lib; do
    [ -f "$lib" ] || continue
    b="$(basename "$lib")"
    _is_core_lib "$b" && continue
    grep -qxF "$b" "$HAVE" 2>/dev/null && continue      # already vendored somewhere
    if cp -aL "$lib" "$CLOSDIR/" 2>/dev/null; then printf '%s\n' "$b" >> "$HAVE"; echo "  + $b"; fi
  done
}
# pass 1: satisfy the interpreter, every toolchain/vendor .so, and the tool binaries + wrappers
{ find "$V" -type f \( -name '*.so' -o -name '*.so.*' \) 2>/dev/null
  find "$V/toolchain/usr/bin" "$V/toolchain/usr/local/bin" "$V/toolchain/.wrappers" \
       -maxdepth 1 -type f 2>/dev/null ; } | sort -u | while IFS= read -r elf; do
  if head -c4 "$elf" 2>/dev/null | grep -q ELF; then _vendor_needed_of "$elf"; fi
done
# passes 2-3: satisfy the libraries the earlier passes just added (their own transitive deps)
for _p in 2 3; do
  find "$CLOSDIR" -maxdepth 1 -type f -name '*.so*' 2>/dev/null | while IFS= read -r so; do
    _vendor_needed_of "$so"
  done
done
set -e                                                 # closure pass done -- restore errexit
printf '  closure vendored; vendor/ is now %s\n' "$(du -sh "$V" | cut -f1)"

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
# analysis works regardless of what python3 (if any) the laptop has. It finds its libraries through
# an $ORIGIN rpath (set at build time), so NO LD_LIBRARY_PATH is exported here -- the bundle's
# libraries stay private to the bundle's tools and never leak onto anything else the server spawns.
# Fall back to the system python3 only if this bundle was built without a vendored interpreter.
py="$here/vendor/toolchain/usr/bin/python3"
[ -x "$py" ] || py=python3
# LYKOS_VENDOR is set EXPLICITLY rather than left to auto-detection: the vendored engines --
# pypcode above all -- live under vendor/pysite, and if that directory is not put on sys.path the
# P-Code memory-safety detectors go dark and `doctor` reports pypcode "missing" even though it is
# right there. Auto-detection from __file__/cwd proved fragile across laptops (symlinked paths,
# odd mounts), so we name the directory outright. This one variable also gives the tool locators
# vendor/toolchain, so no separate LYKOS_TOOLCHAIN is needed.
# stdin < /dev/null: no analysis tool can then block reading an inherited pipe/terminal.
exec env PYTHONPATH="$here/core" LYKOS_VENDOR="$here/vendor" "$py" -m lykos serve \
     --http 127.0.0.1:8787 --case-store "$here/.cases" --workers 2 < /dev/null
EOF
chmod +x "$APP/RUN.sh"
# A doctor that uses the SAME interpreter and vendored path RUN.sh does -- running `python3 -m lykos
# doctor` with the laptop's own python (as the notes used to say) finds none of the vendored engines
# and always reports pypcode missing. This wrapper is the correct invocation, in one command.
cat > "$APP/DOCTOR.sh" <<'EOF'
#!/usr/bin/env sh
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"
py="$here/vendor/toolchain/usr/bin/python3"
[ -x "$py" ] || py=python3
exec env PYTHONPATH="$here/core" LYKOS_VENDOR="$here/vendor" "$py" -m lykos doctor "$@" < /dev/null
EOF
chmod +x "$APP/DOCTOR.sh"
cat > "$APP/RUN-HERE-FIRST.txt" <<'EOF'
lykos -- air-gapped, unzip-and-run. No installation. Nothing is written outside this folder.

  1. You already unzipped this (use `unzip -o` if it prompts). Everything is inside ./vendor.
  2. Check what this host can do:   ./DOCTOR.sh
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
# A DUPLICATE PATH inside the zip makes `unzip` stop and prompt "replace? [y]" -- which reads as a
# hang on the air-gapped laptop. Check the ARCHIVE (not the staging tree, which cannot hold a dup)
# and fail the build so a prompting bundle never ships.
if command -v zipinfo >/dev/null 2>&1; then
  zdups="$(zipinfo -1 "$OUT" | sort | uniq -d | head)"
  [ -z "$zdups" ] || { echo "duplicate paths in the archive:"; echo "$zdups"; die "the zip has duplicate paths -- unzip would prompt on the laptop; fix the sanitise step"; }
fi
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
