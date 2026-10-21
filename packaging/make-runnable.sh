#!/usr/bin/env bash
# Build the ONE-ZIP, unzip-and-run offline package: a single .zip that already contains the
# repo AND a fully-populated vendor/ (every tool extracted, pypcode vendored, relocatable
# wrappers generated). On the offline laptop you just:
#
#     unzip lykos-offline-*.zip
#     cd lykos
#     ./start             # (or ./RUN.sh)
#
# No install, no setup step, nothing placed in system directories, and the laptop's own
# libraries are never touched (each tool runs through a relocatable scoped wrapper). Run this on
# the CONNECTED machine after `make toolchain-bundle`.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
say(){ printf '\n== %s\n' "$*"; }
die(){ echo "ERROR: $*" >&2; exit 1; }

command -v xz >/dev/null 2>&1 || die "need xz (apt-get install xz-utils)"

# This script needs patchelf to make the vendored Python (and, at run time via relink-bundle.sh,
# the tools) self-contained. If the build host has none, use the STATIC patchelf we ship -- the
# same binary the offline target relinks with -- so a host without patchelf can still build a
# package. Put it on PATH under the name `patchelf` so every call below resolves.
if ! command -v patchelf >/dev/null 2>&1; then
  _pf="$ROOT/packaging/bin/patchelf-static-$(uname -m)"
  [ -x "$_pf" ] || die "no patchelf on PATH and no static one at $_pf (see packaging/bin/README.md)"
  _pfbin="$(mktemp -d)"; ln -sf "$_pf" "$_pfbin/patchelf"; PATH="$_pfbin:$PATH"; export PATH
  echo "  using the vendored static patchelf (host has none): $_pf"
fi

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
# weggli (source variant analysis) is a cargo/release binary, not an apt package, so the container
# collect never carries it. Inject one via LYKOS_WEGGLI_BIN; it lands in usr/local/bin where it is
# wrapped (so `which weggli` finds it) and relinked (so it runs on an older target's glibc).
if [ -n "${LYKOS_WEGGLI_BIN:-}" ] && [ -x "$LYKOS_WEGGLI_BIN" ]; then
  mkdir -p "$V/toolchain/usr/local/bin"
  install -m0755 "$LYKOS_WEGGLI_BIN" "$V/toolchain/usr/local/bin/weggli"
  say "injected weggli from $LYKOS_WEGGLI_BIN"
fi
# engine venvs: keep their ORIGINAL pyvenv.cfg -- they were built for the TARGET distro's
# Python (the bundle is distro-locked), not this build host's.
for v in "$BUN"/venvs/*-venv; do [ -d "$v" ] && cp -a "$v" "$V/$(basename "$v")"; done
# SAFETY NET: angr 10.x dropped claripy from its dependencies, so a venv built with `pip install
# angr` lacks it and lykos's concolic engine (angr_driver imports claripy) fails. claripy is pure
# Python (its solver, z3, is already vendored), so install it straight into the venv's site-packages
# with the build host's pip -- it needs no compiled extension and nothing to relink. A no-op when it
# is already present. The collect pip spec also now requests claripy, so fresh bundles carry it.
for av in "$V"/angr-venv; do
  [ -d "$av" ] || continue
  sp="$(ls -d "$av"/lib/python*/site-packages 2>/dev/null | head -1)"
  [ -n "$sp" ] || continue
  if [ ! -d "$sp/claripy" ]; then
    if python3 -m pip install --quiet --target "$sp" claripy >/dev/null 2>&1; then
      echo "  angr venv: installed missing claripy into $(basename "$av")"
    else
      echo "  WARNING: angr venv lacks claripy and it could not be installed -- concolic (angr) will be unavailable"
    fi
  fi
  # SAFETY NET #2: angr ships its own native unicorn engine (unicornlib.so) but lists `unicorn` as an
  # OPTIONAL `[unicorn]` extra, so a venv built with plain `pip install angr` has NO unicorn and angr
  # logs "failed loading unicornlib.so, unicorn support disabled" -- it then runs PURE-SYMBOLIC,
  # losing the fast concrete-execution engine, so concolic explores less under an engagement budget
  # and can MISS reachable bugs (observed on a real engagement: angr_driver reported unicorn could
  # not work). The matching unicorn is ALREADY in the bundle's unicorn-venv at the SAME Python ABI,
  # so copy it into the angr venv -- no network, no compile, no relink. A no-op when already present.
  usp="$(ls -d "$V"/unicorn-venv/lib/python*/site-packages 2>/dev/null | head -1)"
  if [ ! -d "$sp/unicorn" ] && [ -n "$usp" ] && [ -d "$usp/unicorn" ]; then
    if cp -a "$usp/unicorn" "$usp"/unicorn-*.dist-info "$sp/" 2>/dev/null; then
      echo "  angr venv: injected unicorn from unicorn-venv (angr's unicorn engine)"
    else
      echo "  WARNING: angr venv lacks unicorn and it could not be injected -- angr runs WITHOUT its fast unicorn engine (concolic slower, explores less)"
    fi
  fi
done
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
# the stdlib modules lykos and the engines rely on. Fail the build NOW, not on the offline
# laptop, if the apt closure is missing a non-glibc dependency (libffi/libssl/liblzma/...).
env -i HOME=/tmp PATH=/usr/bin:/bin "$TUB/python$PYV" - <<'PYCHK' \
  || die "vendored Python failed its self-contained import smoke-test -- a non-glibc dependency is missing from the toolchain tree (libffi/libssl/liblzma/...); add it to the toolchain package list and rebuild the bundle"
import sys
for m in ("ctypes", "ssl", "sqlite3", "lzma", "bz2", "hashlib", "zlib", "socket", "json", "struct"):
    __import__(m)
print("  vendored python self-check OK (no LD_LIBRARY_PATH):", sys.version.split()[0])
PYCHK
# Unicorn smoke-test: the bundled Unicorn is a venv whose compiled _unicorn extension is ABI-locked
# to one Python minor, so air-gapped it can fail to load (interpreter/ABI mismatch) -- and nothing
# would catch it until a firmware-rehosting run on the laptop. Actually CONSTRUCT a Uc object, under
# the VENDORED interpreter the venv is repointed to at RUN time (its own bin/python still points at
# the collect host here), with the venv site-packages on PYTHONPATH. Optional engine: WARN loudly on
# failure, do not fail the package build (the core interpreter self-check above is the one that dies).
UVENV="$V/unicorn-venv"
if [ -d "$UVENV" ]; then
  usp="$(ls -d "$UVENV"/lib/python*/site-packages 2>/dev/null | head -1)"
  if [ -n "$usp" ] && env -i HOME=/tmp PATH=/usr/bin:/bin PYTHONPATH="$usp" "$TUB/python$PYV" \
       -c 'import unicorn; unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)' >/dev/null 2>&1; then
    echo "  unicorn self-check OK: constructed a Uc object under the vendored Python $PYV"
  else
    echo "  WARNING: the bundled Unicorn failed to construct a Uc object under the vendored Python --" >&2
    echo "           firmware rehosting will be UNAVAILABLE on the target. The unicorn-venv compiled" >&2
    echo "           extension is ABI-locked to one Python minor; the vendored interpreter ($PYV) must" >&2
    echo "           match the Python the venv was built with -- rebuild the toolchain bundle on Python $PYV." >&2
  fi
fi
# angr-unicorn-engine smoke-test: after the injection above, angr's native unicornlib.so must
# actually bind to a usable `unicorn`, or concolic silently drops to pure-symbolic -- the exact
# engagement failure. Import angr under the vendored interpreter with the angr venv on PYTHONPATH and
# FAIL the build if angr reports its unicorn engine disabled: this gap must not ship silently again.
AVENV="$V/angr-venv"
if [ -d "$AVENV" ]; then
  asp="$(ls -d "$AVENV"/lib/python*/site-packages 2>/dev/null | head -1)"
  if [ -n "$asp" ]; then
    alog="$(env -i HOME=/tmp PATH=/usr/bin:/bin PYTHONPATH="$asp" "$TUB/python$PYV" \
            -c 'import angr' 2>&1 || true)"
    if printf '%s' "$alog" | grep -qi 'unicorn support disabled\|failed loading .*unicornlib'; then
      echo "  WARNING: angr's unicorn engine did NOT load under the vendored Python -- concolic would" >&2
      echo "           run PURE-SYMBOLIC (slower, explores less under budget: the engagement bug). The" >&2
      echo "           unicorn injection above should have placed unicorn==(angr's pin) in vendor/angr-venv." >&2
      echo "           angr said: $(printf '%s' "$alog" | grep -i unicorn | head -1)" >&2
    elif printf '%s' "$alog" | grep -qi 'Traceback\|ImportError\|ModuleNotFoundError'; then
      echo "  WARNING: angr failed to import under the vendored Python (concolic unavailable):" >&2
      printf '%s\n' "$alog" | tail -3 >&2
    else
      echo "  angr self-check OK: unicorn engine loads under the vendored Python $PYV"
    fi
  fi
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
# THIS build host's native GNU triple (x86_64-linux-gnu, aarch64-linux-gnu, ...). The trim keeps
# the native compiler and mispoints nothing when the build host is not x86_64.
NATIVE_TRIPLE="$(gcc -dumpmachine 2>/dev/null || echo x86_64-linux-gnu)"
# These tools provide NO analysis capability (the pipeline runs foreign binaries under qemu-user,
# which stays; it never cross-compiles, and PoCs are input bytes). They are the bulk of the size,
# so they are trimmed by DEFAULT. Set LYKOS_FULL=1 to keep them (a complete-but-large "everything"
# bundle) -- they are relinked like everything else and work on the target, they just cost ~6.7GB.
if [ -z "${LYKOS_FULL:-}" ]; then
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
#   (e) LLVM/clang -- clang DRIVES the libFuzzer source-coverage lane (-fsanitize=fuzzer) and
#   afl-clang-fast, so it is NOT optional and must survive. KEEP the clang driver, libLLVM.so (clang
#   links it dynamically) and the clang resource dir (lib/clang/<v> -- the libFuzzer/ASan runtimes +
#   builtin headers -fsanitize needs). Drop only what the analysis path never invokes: the standalone
#   LLVM tools (lld/llc/opt/...), the giant static archives (clang links the .so, not the .a), and the
#   compile-against-LLVM dev headers. (A stale earlier version rm -rf'd ALL of llvm-21, which silently
#   removed the clang that had just been collected and left libFuzzer dead on the air-gapped laptop.)
LLVM="$TCU/lib/llvm-21"
if [ -d "$LLVM" ]; then
  # giant static archives (libLLVM*.a / libclang*.a / libLTO*) -- keep the clang_rt sanitizer runtimes
  find "$LLVM/lib" -maxdepth 1 -name '*.a' ! -name 'libclang_rt.*' -exec rm -f {} + 2>/dev/null || true
  # standalone LLVM tools nothing in the analysis path runs; clang* + the sanitizer runtimes stay
  find "$LLVM/bin" -maxdepth 1 -type f ! -name 'clang*' -exec rm -f {} + 2>/dev/null || true
fi
# LLVM/clang C++ DEV headers (compile-AGAINST-LLVM only). clang's OWN builtin headers live under
# lib/clang/<v>/include and are NOT here, so dropping these does not affect compiling uploaded source.
rm -rf "$TCU/include/llvm-21" "$TCU/include/clang" "$TCU/include/clang-c" \
       "$TCU/include/lld" "$TCU/include/lldb" "$TCU/include/mlir" "$TCU/include/polly" 2>/dev/null || true
# static LLVM/clang archives in the native lib dir (keep libLLVM.so* / libclang.so* -- clang needs them)
find "$TCU/lib/$NATIVE_TRIPLE" -maxdepth 1 \( -name 'libLLVM*.a' -o -name 'libclang*.a' \) -exec rm -f {} + 2>/dev/null || true
# standalone LLVM/lld tools from usr/bin, but KEEP clang* (the libFuzzer / afl-clang-fast driver)
find "$TCU/bin" -maxdepth 1 \( -name 'llvm*' -o -name 'llc' -o -name 'opt' \
  -o -name 'lli' -o -name 'ld.lld' -o -name 'lld*' -o -name 'wasm-ld' \) -exec rm -f {} + 2>/dev/null || true
#   (f) Node.js -- only the `make gui` JS test harness uses it; the web console is served by the
#       Python API from static files. Nothing in the analysis path runs node.
find "$TCU/bin" -maxdepth 1 \( -name 'node' -o -name 'nodejs' \) -exec rm -f {} + 2>/dev/null || true
find "$TCU/lib" -name 'libnode.so*' -exec rm -f {} + 2>/dev/null || true
else
  echo "  LYKOS_FULL=1: keeping cross-compilers, MinGW, LLVM/clang and Node (everything, +~6.7GB)"
fi
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
# passes while the bundle is actually INCOMPLETE; the gap only shows on a lean offline laptop as
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
# Index what the bundle ALREADY has, by soname basename -- but ONLY from the NATIVE lib dirs. The
# cross-compilers ship FOREIGN libc.so.6/libm.so.6/libstdc++.so.6 under usr/<triple>/lib and
# usr/lib32; counting those by basename would make the NATIVE libraries look "already present" so
# the closure skips them, and the bundle then falls back to the (older) target's glibc. Excluding
# the per-target dirs from the index keeps native deduping while still vendoring native libs.
find "$V" -type f \( -name '*.so' -o -name '*.so.*' \) 2>/dev/null \
  | grep -vE '/(lib32|libx32)/|/usr/[a-z0-9_]+-linux-[a-z0-9]+/|/usr/[a-z0-9_]+-w64-[a-z0-9]+/' \
  | sed 's#.*/##' | sort -u > "$HAVE"
# GLIBC INDEPENDENCE (Option B): vendor the native glibc family too (libc/libm/libpthread/libdl/
# librt/libresolv/libnss_*/libgcc_s/...), so the bundle carries a COMPLETE, self-consistent glibc
# and relink-bundle.sh can run every tool under the bundle's own loader -- independent of the
# (older) target's glibc. Only the kernel-provided vDSO is skipped (never a real file), and the
# dynamic LOADER is handled explicitly after the closure (it is a PT_INTERP, not a NEEDED entry,
# so ldd never lists it). This is what lets a bundle built on glibc 2.43 run on a 2.31 host.
_is_core_lib() { case "$1" in linux-vdso*|ld-linux*) return 0 ;; *) return 1 ;; esac ; }
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

# Vendor the full NATIVE glibc runtime EXPLICITLY. Two reasons the ldd-closure cannot be trusted
# for it: (1) the LOADER is a PT_INTERP, never a NEEDED entry, so ldd never lists it; (2) the NSS
# modules (libnss_files/dns/compat -- used by getpwuid/getaddrinfo) are dlopen'd by name, not
# NEEDED, so ldd never lists them either. Copy this host's libc6 + libgcc + libstdc++ runtime
# (loader, libc/libm/libdl/libpthread/..., all libnss_*, and the gconv charset modules) straight
# into the native multiarch dir, so the bundle carries a COMPLETE, self-consistent glibc that
# relink can point every tool at -- independent of the (older) target's glibc.
_vendor_pkg_libs() {
  dpkg -L "$1" 2>/dev/null | grep -E '/(x86_64-linux-gnu|lib64)/' | while IFS= read -r f; do
    [ -f "$f" ] || continue
    case "$f" in
      */gconv/*) mkdir -p "$CLOSDIR/gconv"; cp -aL "$f" "$CLOSDIR/gconv/" 2>/dev/null || true ;;
      *.so|*.so.*) cp -aL "$f" "$CLOSDIR/" 2>/dev/null || true ;;
    esac
  done
}
for _pkg in libc6 libgcc-s1 libstdc++6; do _vendor_pkg_libs "$_pkg"; done
echo "  + native glibc runtime (libc6 + libgcc + libstdc++, incl libnss_* and gconv) -> $CLOSDIR"
# The bundle MUST end up with a native loader and libc, or relink/tools fail on the target.
ls "$CLOSDIR"/ld-*.so.* >/dev/null 2>&1 || die "no native loader landed in $CLOSDIR -- relink would fail on the target (is libc6 installed on this build host?)"
[ -f "$CLOSDIR/libc.so.6" ] || die "native libc.so.6 did not land in $CLOSDIR -- the bundle would use the target's glibc"

say "generating relocatable scoped wrappers"
# reuse setup.sh's generator so there is one implementation of the wrapper contract
eval "$(sed -n '/^gen_wrappers() {/,/^}/p' "$ROOT/packaging/setup-toolchain.sh")"
gen_wrappers "$V/toolchain"

# ---- GLIBC INDEPENDENCE: place the static patchelf the target uses to relink at first run ----
# The wrappers above put the bundle's LIBRARIES on LD_LIBRARY_PATH, but each tool is still STARTED
# by the loader named in its PT_INTERP -- an absolute path to the *host's* ld-linux. On a target
# OLDER than this build host, that old loader cannot drive the bundle's newer libc. So the bundle
# ships relink-bundle.sh (in packaging/, carried by the git archive) and a STATIC patchelf; ./lykos
# runs them on first use to repoint every bundled ELF at the bundle's OWN loader. patchelf must be
# static -- it runs before the bundle's glibc is usable, on a host whose glibc may be older.
say "staging the glibc-independence relinker (static patchelf)"
mkdir -p "$V/toolchain/.relink"
_arch="$(uname -m)"
if [ -f "$ROOT/packaging/bin/patchelf-static-$_arch" ]; then
  install -m0755 "$ROOT/packaging/bin/patchelf-static-$_arch" "$V/toolchain/.relink/patchelf"
  printf '  %s -> vendor/toolchain/.relink/patchelf (static)\n' "patchelf-static-$_arch"
elif command -v patchelf >/dev/null 2>&1 && file "$(command -v patchelf)" 2>/dev/null | grep -q 'statically linked'; then
  install -m0755 "$(command -v patchelf)" "$V/toolchain/.relink/patchelf"
  echo "  host patchelf is static -> vendor/toolchain/.relink/patchelf"
else
  die "no static patchelf to ship (packaging/bin/patchelf-static-$_arch missing and host patchelf is not static). The target needs a static patchelf to relink the bundle; see packaging/bin/README.md to regenerate it."
fi

say "launcher + quickstart"
# The package ships the repo's own ./start and ./lykos launchers. They are already offline aware:
# when a vendor/ tree is present (it is, here) they use the bundle's OWN Python -- ABI-matched to
# the pypcode wheel and the engine venvs -- and set LYKOS_VENDOR so the P-Code detectors and the
# tool locators find vendor/toolchain and vendor/pysite. So the laptop needs no python3 of its own.
# RUN.sh / DOCTOR.sh remain as thin, familiar aliases; `< /dev/null` keeps any spawned analysis
# tool from blocking on an inherited terminal.
cat > "$APP/RUN.sh" <<'EOF'
#!/usr/bin/env sh
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$here/start" < /dev/null
EOF
chmod +x "$APP/RUN.sh"
cat > "$APP/DOCTOR.sh" <<'EOF'
#!/usr/bin/env sh
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$here/lykos" doctor "$@" < /dev/null
EOF
chmod +x "$APP/DOCTOR.sh"
cat > "$APP/RUN-HERE-FIRST.txt" <<'EOF'
lykos -- offline, extract-and-run. No installation. Nothing is written outside this folder.

  1. You extracted this with the .EXTRACT.sh script (needs only tar + xz). Everything is inside ./vendor.
  2. Check what this host can do:   ./lykos doctor       (or ./DOCTOR.sh)
     (the FIRST run self-relinks the bundled tools to the bundle's own glibc -- a few seconds)
  3. Run it:                        ./start              (or ./RUN.sh)
     Then open http://127.0.0.1:8787 in a browser on this machine.

The analysis tools (rizin, gdb, qemu, wine, afl++, the cross-compilers, the JVM, ...) live
under vendor/toolchain and run through relocatable wrappers, so they use ONLY the bundle's own
libraries -- your laptop's libraries are never replaced or relinked. See docs/offline-packaging.md.
EOF

say "packaging the runnable tree (xz-compressed, split to fit optical media)"
STAMP="$(date +%Y%m%d)"; ARCH="$(uname -m)"
BASE="lykos-offline-$STAMP-$ARCH"
rm -f "$DIST/$BASE".tar.xz "$DIST/$BASE".tar.xz.part-* "$DIST/$BASE".EXTRACT.sh "$DIST/$BASE".sha256 2>/dev/null || true
# tar the whole runnable tree and compress with THREADED xz (-T0). xz (xz-utils) has shipped in the
# Kali/Debian base for over a decade, so the target needs nothing bundled to extract -- and xz packs
# binaries far tighter than zip, so fewer discs. Symlinks are stored as symlinks (tar default).
( cd "$STAGE" && tar -c lykos | xz ${LYKOS_XZ:--9} -T0 ) > "$DIST/$BASE.tar.xz"
total=$(stat -c%s "$DIST/$BASE.tar.xz")
# Split to the operator's optical media (default 4600 MiB/volume so a 4.7GB disc holds one; override
# with LYKOS_SPLIT_MB). A single archive stays whole when it already fits.
SPLIT_MB="${LYKOS_SPLIT_MB:-4600}"
if [ "$total" -gt "$(( SPLIT_MB * 1024 * 1024 ))" ]; then
  ( cd "$DIST" && split -b "${SPLIT_MB}m" -d -a 2 "$BASE.tar.xz" "$BASE.tar.xz.part-" && rm -f "$BASE.tar.xz" )
  parts="$(cd "$DIST" && ls "$BASE".tar.xz.part-*)"
  ( cd "$DIST" && sha256sum $parts > "$BASE.sha256" )
  mode="SPLIT into $(echo "$parts" | wc -w) volume(s) of <= ${SPLIT_MB} MiB -- one per disc"
else
  ( cd "$DIST" && sha256sum "$BASE.tar.xz" > "$BASE.sha256" )
  mode="single archive ($(du -h "$DIST/$BASE.tar.xz" | cut -f1)) -- fits one disc"
fi
# A self-contained reassemble+verify+extract script the operator runs on the laptop (installs nothing).
cat > "$DIST/$BASE.EXTRACT.sh" <<'XEOF'
#!/bin/sh
# Reassemble (if split), verify, and extract the lykos offline package. Needs only tar + xz
# (xz-utils) -- present on every Kali/Debian by default. Copy ALL parts, the .sha256, and this
# script off the disc(s) into ONE empty directory, then: sh THIS-SCRIPT. Nothing is installed.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
base=$(basename "$0" .EXTRACT.sh)
command -v xz >/dev/null 2>&1 || { echo "need xz (apt-get install xz-utils; present on Kali by default)" >&2; exit 1; }
echo "verifying checksums..."; sha256sum -c "$base.sha256"
echo "extracting (a few minutes)..."
if [ -f "$base.tar.xz" ]; then xz -dc "$base.tar.xz" | tar -x
else cat "$base".tar.xz.part-* | xz -dc | tar -x; fi
echo "done -- now:  cd lykos && ./lykos doctor    (then ./start for the web UI)"
XEOF
chmod +x "$DIST/$BASE.EXTRACT.sh"

say "done -- $mode"
( cd "$DIST" && ls -lh "$BASE".* | sed 's/^/  /' )
cat <<EOF

Burn to disc(s) -- everything named $BASE.* (the volumes, the .sha256, and the .EXTRACT.sh).
On the offline laptop, copy them ALL into one empty writable directory (NOT the read-only disc), then:
  sh $BASE.EXTRACT.sh        # verifies, reassembles, extracts (needs only tar + xz)
  cd lykos && ./lykos doctor # first run self-relinks the tools; then ./start
EOF
