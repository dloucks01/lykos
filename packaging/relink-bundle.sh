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
STAMP="$TC/.relink/relinked-for"
if [ -f "$STAMP" ] && [ "$(cat "$STAMP" 2>/dev/null)" = "$ROOT::$LD" ]; then
  exit 0
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

LDREAL=$(CDPATH= cd -- "$(dirname "$LD")" && pwd)/$(basename "$LD")
mkdir -p "$TC/.relink"

# the roots to walk: the toolchain tree always, plus any vendored python venvs / pysite present
set -- "$TC"
for extra in "$VENDOR"/*-venv "$VENDOR"/pysite "$VENDOR"/symqemu; do
  [ -d "$extra" ] && set -- "$@" "$extra"
done

echo "relink: making the bundle glibc-independent (loader: ${LDREAL#"$ROOT"/})"
rm -f "$TC/.relink/.count"; : > "$TC/.relink/.count"
# Walk every regular file and patch the ELF ones. The pipe puts the loop in a subshell, so the
# running count is kept in a file rather than a variable. Bundle paths contain no newlines.
find "$@" -type f 2>/dev/null | while IFS= read -r f; do
  # never touch our own tooling dir (the static patchelf lives there)
  case "$f" in */.relink/*) continue ;; esac
  # cheap one-process ELF magic check (7f 45 4c 46)
  [ "$(od -An -N4 -tx1 "$f" 2>/dev/null | tr -d ' \n')" = "7f454c46" ] || continue
  # never touch the loader itself (patchelf-ing ld-linux corrupts it)
  [ "$(CDPATH= cd -- "$(dirname "$f")" && pwd)/$(basename "$f")" = "$LDREAL" ] && continue
  # A STATICALLY LINKED / static-PIE executable (no PT_INTERP and no NEEDED libraries) is already
  # self-contained: it carries its own startup and has no glibc dependency to repoint. patchelf must
  # NOT touch it -- `--set-rpath` rewrites the program headers and breaks the self-relocation a
  # static-PIE performs at startup, so the binary then SIGSEGVs before main. This silently corrupted
  # EVERY vendored qemu-user (they ship static-PIE): on an air-gapped host with no system qemu to
  # fall back to, all cross-arch analysis/exploitation died with SIGSEGV **[measured 2026-10-20:
  # pristine qemu-aarch64 0/5 SIGSEGV; the same binary after --set-rpath 8/8]**. A shared library
  # (.so) also has no interpreter but DOES list NEEDED libraries, so it still needs the rpath below
  # and is NOT skipped here.
  has_interp=no; "$PATCHELF" --print-interpreter "$f" >/dev/null 2>&1 && has_interp=yes
  if [ "$has_interp" = no ] && [ -z "$("$PATCHELF" --print-needed "$f" 2>/dev/null)" ]; then
    continue
  fi
  # dynamic exe / PIE -> repoint its interpreter at the bundle loader (.so have none)
  if [ "$has_interp" = yes ]; then
    "$PATCHELF" --set-interpreter "$LDREAL" "$f" 2>/dev/null || true
  fi
  # give it (exe or .so) an rpath into the bundle libs, ahead of anything it already had, so a
  # child exec'd without LD_LIBRARY_PATH still resolves the bundle's libraries
  cur=$("$PATCHELF" --print-rpath "$f" 2>/dev/null || true)
  case "$cur" in
    "$RPATH"|"$RPATH":*) ;;                       # already leads with ours
    "") "$PATCHELF" --set-rpath "$RPATH" "$f" 2>/dev/null || true ;;
    *)  "$PATCHELF" --set-rpath "$RPATH:$cur" "$f" 2>/dev/null || true ;;
  esac
  printf 'x' >> "$TC/.relink/.count"
done

patched=$(wc -c < "$TC/.relink/.count" 2>/dev/null | tr -d ' '); rm -f "$TC/.relink/.count"
printf '%s::%s\n' "$ROOT" "$LDREAL" > "$STAMP"
echo "relink: done -- ${patched:-0} ELF file(s) now run under the bundle's own glibc (nothing installed)"
