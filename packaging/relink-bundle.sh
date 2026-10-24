#!/bin/sh
# relink-bundle.sh -- make every bundled ELF GLIBC-INDEPENDENT, so a bundle built on a newer
# host (e.g. Kali rolling, glibc 2.43) runs on a somewhat-OLDER target (glibc ~2.31+) with no
# installation and no capability loss. Pure POSIX shell + a STATIC patchelf, so it needs neither
# glibc nor python to run -- it is what runs BEFORE the bundle's own python can.
#
# WHY. The tool wrappers put the bundle's libraries on LD_LIBRARY_PATH, but a dynamically-linked
# ELF is still started by the loader named in its PT_INTERP -- an absolute path like
# /lib64/ld-linux-x86-64.so.2, which resolves to the *host's* (older) loader. An old loader
# driving the bundle's newer libc aborts with `version GLIBC_2.4x not found` or segfaults. The
# fix is to repoint every bundled ELF's interpreter at the bundle's OWN loader and give it an
# rpath into the bundle's own libs, so parent tools AND the children they exec (gcc -> cc1/as/ld,
# wine's helpers, Ghidra's java) all run under one self-consistent, bundle-private glibc.
#
# The loader itself is NEVER patched -- patchelf-ing ld-linux corrupts it (it would segfault with
# no output). It is copied as-is and named by absolute path in everyone else's PT_INTERP.
#
# Idempotent: it records the absolute root it relinked for in a stamp. A second run is a no-op;
# if the folder was MOVED (the stamped root no longer matches), it relinks again for the new path.
# A re-relink is MOVE-SAFE: a tool already fronted by a loader-wrapper (gcc's cc1 -- see pass 2) is
# RE-POINTED at the new root, never wrapped a second time; rpaths are rebuilt (stale old-root
# entries dropped, not stacked); and debris from an interrupted run (*.relinktmp) is cleared first.
set -eu

# ---- locate the vendor tree (arg 1, or next to this script, or $LYKOS_VENDOR) ----
VENDOR="${1:-${LYKOS_VENDOR:-}}"
if [ -z "$VENDOR" ]; then
  here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
  if [ -d "$here/../vendor" ]; then VENDOR=$(CDPATH= cd -- "$here/../vendor" && pwd); fi
fi
[ -n "$VENDOR" ] && [ -d "$VENDOR" ] || { echo "relink: no vendor/ dir (pass it as arg 1)" >&2; exit 2; }
TC="$VENDOR/toolchain"
[ -d "$TC" ] || { echo "relink: no vendor/toolchain tree -- nothing to relink (host-PATH bundle)"; exit 0; }

# ---- the bundle's NATIVE dynamic loader (match THIS host's arch) ----
# The bundle also carries FOREIGN loaders (ld-linux-armhf, ld-linux-aarch64, ...) that belong to
# the cross-compilers and run only under qemu -- they must NEVER be chosen as the host loader, or
# every native tool gets an interpreter for the wrong CPU ("Accessing a corrupted shared library").
# So we pick the loader NAME for this machine and search only the NATIVE lib dirs (usr/lib/<ma>,
# lib64, ...), never the per-target usr/<triple>/lib dirs the cross loaders live in.
case "$(uname -m)" in
  x86_64)        WANTLD=ld-linux-x86-64.so.2 ;;
  aarch64)       WANTLD=ld-linux-aarch64.so.1 ;;
  armv7l|armv6l) WANTLD=ld-linux-armhf.so.3 ;;
  i386|i486|i586|i686) WANTLD=ld-linux.so.2 ;;
  riscv64)       WANTLD=ld-linux-riscv64-lp64d.so.1 ;;
  ppc64le)       WANTLD=ld64.so.2 ;;
  s390x)         WANTLD=ld64.so.1 ;;
  *)             WANTLD="" ;;
esac
LD=""
if [ -n "$WANTLD" ]; then
  for c in "$TC"/usr/lib/*-linux-gnu/"$WANTLD" "$TC"/usr/lib64/"$WANTLD" "$TC"/lib64/"$WANTLD" \
           "$TC"/lib/*-linux-gnu/"$WANTLD" "$TC"/usr/lib/"$WANTLD" "$TC"/lib/"$WANTLD"; do
    [ -f "$c" ] && { LD="$c"; break; }
  done
fi
if [ -z "$LD" ]; then
  echo "relink: no NATIVE loader (${WANTLD:-ld-linux for $(uname -m)}) found in the bundle's native lib dirs under $TC -- the bundle is missing its own glibc, cannot make it self-contained" >&2
  exit 3
fi

# ---- a static patchelf: bundled under .relink/, else on PATH ----
PATCHELF=""
for c in "$TC"/.relink/patchelf "$VENDOR"/.relink/patchelf; do
  [ -x "$c" ] && { PATCHELF="$c"; break; }
done
[ -z "$PATCHELF" ] && command -v patchelf >/dev/null 2>&1 && PATCHELF=patchelf
[ -n "$PATCHELF" ] || { echo "relink: no patchelf (expected a static one at $TC/.relink/patchelf)" >&2; exit 4; }

# ---- idempotency stamp: skip when already relinked for THIS absolute root ----
ROOT=$(CDPATH= cd -- "$VENDOR" && pwd)
# Compare against the ABSOLUTE loader path -- the same value written to the stamp below. Comparing
# the raw "$LD" (relative whenever vendor/ was passed as a relative path) never matched, so every
# launch re-relinked the whole bundle in place.
LDREAL=$(CDPATH= cd -- "$(dirname "$LD")" && pwd)/$(basename "$LD")
STAMP="$TC/.relink/relinked-for"
if [ -f "$STAMP" ] && [ "$(cat "$STAMP" 2>/dev/null)" = "$ROOT::$LDREAL" ]; then
  exit 0
fi
# The root a PREVIOUS relink baked into rpaths/wrappers (the folder has since moved), so its now-dead
# entries are dropped rather than stacked in front of the original rpath on every move.
OLDROOT=""
if [ -f "$STAMP" ]; then
  OLDROOT=$(sed -n '1s/::.*$//p' "$STAMP" 2>/dev/null || true)
  [ "$OLDROOT" = "$ROOT" ] && OLDROOT=""
fi

# ---- the absolute bundle library directories every patched ELF gets as rpath ----
# Covers the multiarch and plain lib dirs under the toolchain AND the vendored python/venv libs,
# so a child exec'd WITHOUT LD_LIBRARY_PATH (cc1, collect2, ...) still resolves the bundle's libs.
RPATH=""
for d in "$TC"/usr/lib/*-linux-gnu "$TC"/usr/lib "$TC"/usr/local/lib "$TC"/lib/*-linux-gnu \
         "$TC"/lib "$TC"/usr/lib64 "$TC"/lib64 "$VENDOR"/symqemu; do
  [ -d "$d" ] || continue
  ad=$(CDPATH= cd -- "$d" && pwd)
  case ":$RPATH:" in *":$ad:"*) ;; *) RPATH="${RPATH:+$RPATH:}$ad" ;; esac
done
# symqemu is built SEPARATELY (build-symqemu.sh) and ships its OWN runtime lib (libSymCCRtShared.so)
# beside its binary; it ALSO needs the toolchain's glib/pixman. Its dir is added to RPATH above so
# the former resolves, and it is added to the walk below so symqemu-x86_64 + its .so get the full
# bundle rpath -- without this, symqemu-x86_64 died offline with "libSymCCRtShared.so / libglib-2.0
# cannot open shared object file" and symbolic-qemu was silently unavailable on the laptop.

mkdir -p "$TC/.relink"

# _rpath CUR -> the rpath to set: the bundle RPATH first, then CUR's entries that are neither already
# in RPATH nor under the OLD (pre-move) root. Rebuilding (instead of prefixing) keeps a re-relink
# after a move from accumulating P1:P0:... dead entries -- and keeps the result stable, so a second
# run on the same root changes nothing.
_rpath() {
  _out="$RPATH"
  _rest="$1"
  while [ -n "$_rest" ]; do
    case "$_rest" in *:*) _e=${_rest%%:*}; _rest=${_rest#*:} ;; *) _e=$_rest; _rest="" ;; esac
    [ -n "$_e" ] || continue
    case ":$_out:" in *":$_e:"*) continue ;; esac
    if [ -n "$OLDROOT" ]; then
      case "$_e" in "$OLDROOT"|"$OLDROOT"/*) continue ;; esac
    fi
    _out="$_out:$_e"
  done
  printf '%s' "$_out"
}

# _write_wrapper F -- front the pristine "$F.real" with a loader-wrapper (bundle loader + libs).
WRAPMARK='# lykos loader-wrapper:'
_write_wrapper() {
  { printf '#!/bin/sh\n'
    printf '%s patchelf corrupts this binary (0.19.1 large-ELF bug), so the\n' "$WRAPMARK"
    printf '# PRISTINE copy beside it is run through the bundle loader with the bundle library path.\n'
    printf 'exec "%s" --library-path "%s" "%s.real" "$@"\n' "$LDREAL" "$RPATH" "$1"
  } > "$1.wraptmp" && chmod 0755 "$1.wraptmp" && mv -f "$1.wraptmp" "$1"
}
_is_wrapper() {  # $1 is a loader-wrapper this script wrote (small text file carrying the marker)
  [ -f "$1" ] || return 1
  [ "$(od -An -N2 -c "$1" 2>/dev/null | tr -d ' \n')" = "#!" ] || return 1
  grep -q "^$WRAPMARK" "$1" 2>/dev/null
}

# Make the loader reachable at its STANDARD interpreter path under the toolchain root. The bundle's
# gcc/clang are relocated with `--sysroot=<toolchain>` (see the compiler wrappers), and ld then
# checks that the OUTPUT binary's interpreter (/lib64/ld-linux-* on x86-64, /lib/ld-* elsewhere)
# exists UNDER the sysroot at LINK time -- failing with "cannot find /lib64/ld-linux-... inside
# <toolchain>" when the apt collect omitted the /lib64 usrmerge symlink. Recreate it -> the real
# loader so compiling uploaded source / PoC harnesses / libFuzzer targets works offline.
_lbn=$(basename "$LDREAL")
for _ldir in "$TC/lib64" "$TC/lib"; do
  # never replace the REAL loader with a link to itself (it may live in lib64/ or lib/ itself, or
  # reach it through a usrmerge symlink); a stale link from before a move IS replaced.
  [ -e "$_ldir/$_lbn" ] && [ ! -L "$_ldir/$_lbn" ] && continue
  [ -e "$_ldir/$_lbn" ] && [ "$_ldir/$_lbn" -ef "$LDREAL" ] && continue
  mkdir -p "$_ldir" 2>/dev/null && ln -sf "$LDREAL" "$_ldir/$_lbn" 2>/dev/null || true
done

# the roots to walk: the toolchain tree always, plus any vendored python venvs / pysite present
set -- "$TC"
for extra in "$VENDOR"/*-venv "$VENDOR"/pysite "$VENDOR"/symqemu; do
  [ -d "$extra" ] && set -- "$@" "$extra"
done

echo "relink: making the bundle glibc-independent (loader: ${LDREAL#"$ROOT"/})"
rm -f "$TC/.relink/.count"; : > "$TC/.relink/.count"
# TWO PASSES over every regular file, patching the ELF ones. Shared libraries are relinked FIRST,
# then executables -- because an executable is validated below by asking the bundle loader to resolve
# it, and that resolution loads the exe's NEEDED .so. If those .so are not relinked yet when the exe
# is validated, the validation spuriously fails and the exe gets WRAPPERED -- which breaks a compiler
# that re-execs its own frontend: clang runs `<self> -cc1`, and under a loader-wrapper (`ld-linux
# <clang>`) /proc/self/exe is ld-linux, so it runs `ld-linux -cc1` -> "cannot open shared object".
# Relinking the .so first (e.g. libLLVM.so, which clang NEEDs) lets clang validate cleanly and be
# PATCHED, not wrappered. The pipe puts each loop in a subshell, so the running count lives in a file.
#
# A STATICALLY LINKED / static-PIE binary (no PT_INTERP and no NEEDED libs) is self-contained and is
# NEVER touched: `--set-rpath` rewrites its program headers and breaks the self-relocation a static-PIE
# does at startup -> SIGSEGV before main. That silently corrupted EVERY vendored qemu-user (static-PIE)
# [measured 2026-10-20: pristine qemu-aarch64 0/5 SIGSEGV; after --set-rpath 8/8]. A .so has no
# interpreter but DOES list NEEDED libs, so it still gets the rpath (pass 1).
_elf() {  # shared skip-checks: prints nothing, returns 0 if $1 is a bundle ELF we may relink
  case "$1" in */.relink/*) return 1 ;; esac
  [ "$(od -An -N4 -tx1 "$1" 2>/dev/null | tr -d ' \n')" = "7f454c46" ] || return 1
  [ "$(CDPATH= cd -- "$(dirname "$1")" && pwd)/$(basename "$1")" = "$LDREAL" ] && return 1
  return 0
}

# ---- pass 0: debris from an interrupted run, and RE-POINT existing loader-wrappers ----
# A *.relinktmp is a half-patched copy (the run died mid-patch): it is not a tool, and walking it as
# one would wrap/patch garbage. A `X.real` beside a lykos loader-wrapper `X` is a PRISTINE binary
# that patchelf is known to corrupt: on a re-relink (the folder MOVED) the old wrapper names the OLD
# root's loader + paths and is dead. It must be REWRITTEN for the new root -- NOT patched again,
# which would corrupt it, and NOT wrapped again (X.real.real), which left X pointing at a path that
# no longer exists: gcc's cc1 then failed and the bundle could not compile offline after a move.
# A `X.real` whose wrapper never got written (interrupted between the mv and the write) is
# re-wrapped too.
find "$@" -type f -name '*.relinktmp' 2>/dev/null | while IFS= read -r f; do rm -f "$f"; done
find "$@" -type f -name '*.wraptmp' 2>/dev/null | while IFS= read -r f; do rm -f "$f"; done
# HEAL a bundle an older relink already damaged on a move: X (wrapper, dead root) -> X.real (a 2nd
# wrapper) -> X.real.real (the pristine ELF). Restore the pristine binary to X.real; the loop below
# then rewrites X for this root.
find "$@" -type f -name '*.real.real' 2>/dev/null | while IFS= read -r r2; do
  _elf "$r2" || continue
  mid=${r2%.real}
  top=${mid%.real}
  if _is_wrapper "$mid" && { [ ! -e "$top" ] || _is_wrapper "$top"; }; then
    mv -f "$r2" "$mid"
  fi
done
find "$@" -type f -name '*.real' 2>/dev/null | while IFS= read -r r; do
  _elf "$r" || continue
  w=${r%.real}
  if [ ! -e "$w" ] || _is_wrapper "$w"; then
    _write_wrapper "$w"
    printf 'x' >> "$TC/.relink/.count"
  fi
done

# ---- pass 1: shared libraries (no interpreter, but NEEDED libs) -> rpath in place ----
find "$@" -type f 2>/dev/null | while IFS= read -r f; do
  _elf "$f" || continue
  "$PATCHELF" --print-interpreter "$f" >/dev/null 2>&1 && continue       # has interp -> exe (pass 2)
  [ -z "$("$PATCHELF" --print-needed "$f" 2>/dev/null)" ] && continue    # no needed -> static, skip
  cur=$("$PATCHELF" --print-rpath "$f" 2>/dev/null || true)
  want=$(_rpath "$cur")
  [ "$cur" = "$want" ] || "$PATCHELF" --set-rpath "$want" "$f" 2>/dev/null || true
  printf 'x' >> "$TC/.relink/.count"
done

# ---- pass 2: dynamic executables -> repoint interpreter + rpath, on a COPY, validated ----
# patchelf 0.19.1 CORRUPTS some large binaries (gcc's 42MB cc1 segfaults the loader after
# --set-interpreter). So patch a copy, verify the bundle loader still resolves it, and adopt it only
# if sound; if the patch corrupts it, keep the PRISTINE binary + front it with a loader-wrapper.
find "$@" -type f 2>/dev/null | while IFS= read -r f; do
  _elf "$f" || continue
  "$PATCHELF" --print-interpreter "$f" >/dev/null 2>&1 || continue        # no interp -> not an exe
  case "$f" in *.real) _is_wrapper "${f%.real}" && continue ;; esac      # pristine; pass 0 re-pointed it
  tmp="$f.relinktmp"
  if cp -p "$f" "$tmp" 2>/dev/null; then
    "$PATCHELF" --set-interpreter "$LDREAL" "$tmp" 2>/dev/null || true
    curx=$("$PATCHELF" --print-rpath "$tmp" 2>/dev/null || true)
    wantx=$(_rpath "$curx")
    [ "$curx" = "$wantx" ] || "$PATCHELF" --set-rpath "$wantx" "$tmp" 2>/dev/null || true
    if "$LDREAL" --list "$tmp" >/dev/null 2>&1; then
      mv -f "$tmp" "$f"                             # patched binary is sound -- adopt it
    else
      rm -f "$tmp"                                  # patchelf corrupted it -- wrapper the pristine one
      mv -f "$f" "$f.real"
      _write_wrapper "$f"
    fi
  fi
  printf 'x' >> "$TC/.relink/.count"
done

patched=$(wc -c < "$TC/.relink/.count" 2>/dev/null | tr -d ' '); rm -f "$TC/.relink/.count"
printf '%s::%s\n' "$ROOT" "$LDREAL" > "$STAMP"
echo "relink: done -- ${patched:-0} ELF file(s) now run under the bundle's own glibc (nothing installed)"
