#!/usr/bin/env bash
# Place the offline toolchain bundle so lykos runs it IN PLACE. Run this ON the offline
# workstation, from the directory the bundle was extracted into. Needs no network, no root,
# and installs NOTHING into the system: it moves the extracted tree under the repo's vendor/
# directory, where lykos finds every engine on its own PATH and vendor search.
#
# Verifies first, places second, and finishes by running `lykos doctor` so the outcome is a
# capability report rather than a claim that it worked.
#
# INTEGRITY SCOPE: SHA256SUMS is an UNSIGNED manifest, so verification proves the bundle is
# not CORRUPTED (bit-rot, a truncated transfer) and that no file it lists was altered or added.
# It does NOT prove authenticity: an attacker who can rewrite the whole bundle can rewrite
# SHA256SUMS to match. Treat the checksum as corruption-resistance, and carry the bundle over a
# trusted channel. (Future step: sign SHA256SUMS and verify the signature here.)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LYKOS_ROOT="${LYKOS_ROOT:-}"

say(){ printf '\n== %s\n' "$*"; }
die(){ echo "ERROR: $*" >&2; exit 1; }

say "verifying the bundle"
[ -f "$HERE/SHA256SUMS" ] || die "no SHA256SUMS -- this is not a lykos toolchain bundle"
( cd "$HERE" && sha256sum --quiet -c SHA256SUMS ) \
  || die "checksum mismatch: the bundle is corrupt (a listed file was altered or truncated)"
# `sha256sum -c` only checks the files it LISTS; a file added to the bundle passes silently and
# would then be swept up when the toolchain/ tree is copied wholesale below. So also require the
# set of files present to equal the set the manifest names -- an unlisted file (one an attacker
# added to ride along) is refused, not placed.
#
# This is a COUNT, not a filename diff: sha256sum -c above already proved every listed file is
# present and unaltered, so listed is a subset of present; equal cardinality then means equal
# sets. Counting is deliberate -- sha256sum backslash-escapes any path with an odd character
# (e.g. the systemd `\x2d...` .slice units the toolchain pulls in), and parsing those names back
# out of SHA256SUMS is exactly what a naive `sed | comm` gets wrong, rejecting a good bundle.
listed=$(grep -c . "$HERE/SHA256SUMS")
present=$(cd "$HERE" && find . -type f ! -name SHA256SUMS | wc -l)
if [ "$listed" -ne "$present" ]; then
  # counts differ -> something is present that is not named in SHA256SUMS (or vice-versa).
  # best-effort list for the message, tolerant of escaped (\-prefixed) manifest lines.
  extra="$(cd "$HERE" && comm -13 \
    <(sed -E 's/^\\//; s/^[0-9a-f]{64} [ *]//' SHA256SUMS | sort) \
    <(find . -type f ! -name SHA256SUMS | sort) 2>/dev/null || true)"
  die "bundle has files not named in SHA256SUMS (manifest lists $listed, bundle has $present) \
-- refusing (corruption or tampering):
$(printf '%s\n' "$extra" | sed 's/^/    /')"
fi
echo "  ok -- $listed files, no extras"
[ -f "$HERE/manifest/BUNDLE.txt" ] && sed 's/^/  /' "$HERE/manifest/BUNDLE.txt"

if [ "${1:-}" = "--verify-only" ]; then
  echo; echo "verify-only: nothing placed."; exit 0
fi

# Where vendor/ should live. The documented flow is LYKOS_ROOT=$PWD from a checkout; failing
# that, place beside a checkout we can find, else into ./vendor and tell the operator to point
# LYKOS_VENDOR at it. NOTHING goes into a system directory.
if [ -n "$LYKOS_ROOT" ]; then
  DEST="$LYKOS_ROOT/vendor"
elif [ -d "$HERE/../core/lykos" ]; then
  DEST="$(cd "$HERE/.." && pwd)/vendor"
else
  DEST="$PWD/vendor"
  echo
  echo "note: no lykos checkout found next to the bundle. Placing under $DEST --"
  echo "      run lykos with LYKOS_VENDOR=$DEST, or re-run with LYKOS_ROOT=<your checkout>."
fi
mkdir -p "$DEST"
say "placing the toolchain under $DEST (no install, no root)"

# A vendored tool runs with ONLY the bundle's own libraries -- never the laptop's, and never on
# a process-wide search path that would relink the laptop's own binaries. The mechanism is one
# wrapper per vendored executable: it sets LD_LIBRARY_PATH for that single process and execs the
# real binary. lykos puts this .wrappers dir (not the raw bin dirs) first on PATH.
gen_wrappers() {
  tc="$1"; wdir="$tc/.wrappers"
  rm -rf "$wdir"; mkdir -p "$wdir"
  # RELOCATABLE: each wrapper resolves the toolchain root from its OWN location at run time, so
  # the whole tree can be unzipped anywhere and just run -- no absolute paths baked in.
  #
  # The wrapper does NOT set LD_LIBRARY_PATH. Glibc-independence comes from relink-bundle.sh, which
  # gives every bundled ELF its own loader + rpath into the bundle libs. A process-wide
  # LD_LIBRARY_PATH here would be not just redundant but HARMFUL: a tool fronted by a #!/bin/sh
  # script (valgrind, wine-stable, ...) runs that script under the HOST /bin/sh, and an exported
  # LD_LIBRARY_PATH pointing at the bundle's newer libc would make the host loader try to load it
  # for /bin/sh -- the exact old-loader-vs-new-libc crash. So the wrapper is a pure, relocatable
  # exec; the bundle's libraries stay private to the bundle's own (relinked) ELFs.
  n=0
  for bindir in "$tc"/usr/local/bin "$tc"/usr/bin "$tc"/usr/sbin "$tc"/bin "$tc"/sbin; do
    [ -d "$bindir" ] || continue
    for real in "$bindir"/*; do
      [ -f "$real" ] && [ -x "$real" ] || continue
      name="$(basename "$real")"
      [ -e "$wdir/$name" ] && continue                # first bin dir wins on a name clash
      relreal=${real#"$tc"/}
      # COMPILER DRIVERS get `--sysroot=<toolchain root>` injected. gcc/clang were configured
      # --prefix=/usr, so their specs reference system-absolute lib/header/loader paths
      # (/usr/lib/x86_64-linux-gnu/libc_nonshared.a, /lib64/ld-linux-...) that do not exist in the
      # relocated bundle -- without --sysroot, compiling uploaded source / PoC harnesses / libFuzzer
      # targets fails offline with "cannot find ...". The bundle keeps only the NATIVE compiler
      # (cross-compilers are pruned in make-runnable), so one sysroot is always correct. Matches
      # real drivers only -- never gcc-ar / gcc-nm / gcc-ranlib / cpp / gcov.
      is_cc=0
      case "$name" in
        gcc|g++|cc|c++|clang|clang++) is_cc=1 ;;
        gcc-[0-9]*|g++-[0-9]*|clang-[0-9]*|clang++-[0-9]*) is_cc=1 ;;
        *-gcc|*-g++|*-cc|*-c++|*-clang|*-clang++) is_cc=1 ;;
        *-gcc-[0-9]*|*-g++-[0-9]*|*-clang-[0-9]*|*-clang++-[0-9]*) is_cc=1 ;;
      esac
      { printf '#!/bin/sh\n'
        printf '# lykos relocatable wrapper: resolves the bundle root from its own location and\n'
        printf '# execs the real tool, which relink-bundle.sh already made glibc-self-contained.\n'
        printf '# No LD_LIBRARY_PATH -- see gen_wrappers in setup-toolchain.sh for why.\n'
        printf 'r=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)\n'
        if [ "$is_cc" = 1 ]; then
          printf '# compiler driver: relocate its /usr-prefixed lib/header search into the bundle with\n'
          printf '# --sysroot, and -B so it finds the bundle ld/as/collect2 (clang execs a bare "ld"\n'
          printf '# via posix_spawn and otherwise fails "unable to execute command: No such file").\n'
          printf 'exec "$r/%s" --sysroot="$r" -B"$r/usr/bin" "$@"\n' "$relreal"
        else
          printf 'exec "$r/%s" "$@"\n' "$relreal"
        fi
      } > "$wdir/$name"
      chmod +x "$wdir/$name"
      n=$((n+1))
    done
  done
  echo "  generated $n relocatable tool wrappers in $wdir (glibc-independence via relink, not LD_LIBRARY_PATH)"
}

# 1. The extracted, relocatable prefix the apt-sourced engines run from (bwrap, gdb, qemu-*,
#    gcc, wine, java, ...). Only its .wrappers dir goes on lykos's PATH.
if [ -d "$HERE/toolchain" ]; then
  rm -rf "${DEST:?}/toolchain"
  cp -a "$HERE/toolchain" "$DEST/toolchain"
  echo "  toolchain -> $DEST/toolchain ($(du -sh "$DEST/toolchain" | cut -f1))"
else
  echo "  no toolchain/ tree in this bundle -- host PATH tools only"
fi

# 2. Per-guest afl-qemu-trace emulators: into the vendored tree, not a system bin.
if [ -n "$(ls -A "$HERE/afl-qemu" 2>/dev/null)" ]; then
  mkdir -p "$DEST/toolchain/usr/local/bin"
  for f in "$HERE"/afl-qemu/*; do
    install -m 0755 "$f" "$DEST/toolchain/usr/local/bin/" && echo "  $(basename "$f")"
  done
fi

# Generate the scoped wrappers over whatever is now in the tree (including the afl-qemu copies).
[ -d "$DEST/toolchain" ] && gen_wrappers "$DEST/toolchain"

# 3. The Python engine venvs (angr, Unicorn). A venv records the interpreter it was built
#    against; repoint it at this host's python3 and confirm it actually runs.
say "placing python engine venvs"
if [ -n "$(ls -A "$HERE/venvs" 2>/dev/null)" ]; then
  for v in "$HERE"/venvs/*-venv; do
    [ -d "$v" ] || continue
    name="$(basename "$v")"
    rm -rf "${DEST:?}/$name"
    cp -a "$v" "$DEST/$name"
    # Point the venv at the BUNDLE's own python (self-sufficient: no dependency on whatever
    # python3 the target happens to have, or whether it has one at all). Fall back to a host
    # python only when the bundle carries none. vendorenv also repoints venvs to the vendored
    # interpreter at RUN time, so this keeps the two consistent rather than at odds.
    if [ -f "$DEST/$name/pyvenv.cfg" ]; then
      _vpy="$(ls -d "$DEST"/toolchain/usr/bin/python3.[0-9]* 2>/dev/null | sort -V | tail -1)"
      [ -n "$_vpy" ] || _vpy="$DEST/toolchain/usr/bin/python3"
      if [ -x "$_vpy" ]; then _vhome="$(dirname "$_vpy")"; else _vhome="$(dirname "$(command -v python3)")"; fi
      sed -i "s|^home = .*|home = $_vhome|" "$DEST/$name/pyvenv.cfg"
    fi
    if "$DEST/$name/bin/python" -c "import sys" 2>/dev/null; then
      echo "  $name -> $DEST/$name"
    else
      echo "  WARNING: $name does not run here (built for a different Python); that engine"
      echo "           will be unavailable. Rebuild it on a matching host."
    fi
  done
else
  echo "  none in this bundle"
fi

# 3b. Vendored Python site (pypcode = Ghidra P-Code IR, no JVM). lykos puts vendor/pysite on
#     sys.path at startup so the native RE backend can `import pypcode` in-place. It is a
#     compiled wheel built against the bundle's Python; verify it imports on this host.
if [ -d "$HERE/pysite" ] && [ -n "$(ls -A "$HERE/pysite" 2>/dev/null)" ]; then
  rm -rf "${DEST:?}/pysite"
  cp -a "$HERE/pysite" "$DEST/pysite"
  if PYTHONPATH="$DEST/pysite" python3 -c "import pypcode" 2>/dev/null; then
    echo "  pysite (pypcode) -> $DEST/pysite"
  else
    echo "  WARNING: vendored pypcode does not import here (built for a different Python)."
    echo "           The native backend will decompile but P-Code memory-safety detection"
    echo "           degrades. Rebuild the bundle on a host whose Python matches this one."
  fi
fi

# 4. Non-apt engines staged under extras/ -- Ghidra above all (a REQUIRED engine, and a
#    package only on Kali). locate_ghidra() finds <vendor>/ghidra/support/analyzeHeadless and
#    locate_symqemu() finds <vendor>/symqemu/symqemu-<arch>, so a copy here needs no config.
say "placing bundled engines (extras)"
if [ -d "$HERE/extras" ] && [ -n "$(ls -A "$HERE/extras" 2>/dev/null)" ]; then
  for g in "$HERE"/extras/ghidra/*/; do
    [ -d "$g" ] || continue
    rm -rf "${DEST:?}/ghidra"; cp -a "$g" "$DEST/ghidra"
    echo "  ghidra -> $DEST/ghidra"
    [ -d "$DEST/ghidra/support" ] || echo "  WARNING: $DEST/ghidra has no support/ dir -- locator may not find it"
  done
  if [ -d "$HERE/extras/symqemu" ] && [ -n "$(ls -A "$HERE/extras/symqemu" 2>/dev/null)" ]; then
    mkdir -p "$DEST/symqemu"; cp -a "$HERE"/extras/symqemu/* "$DEST/symqemu/"
    echo "  symqemu -> $DEST/symqemu"
  fi
  for d in "$HERE"/extras/*/; do
    [ -d "$d" ] || continue
    key="$(basename "$d")"
    case "$key" in ghidra|symqemu) continue ;; esac
    rm -rf "$DEST/$key"; cp -a "$d" "$DEST/$key"; echo "  $key -> $DEST/$key"
  done
else
  echo "  none in this bundle"
  # Ghidra is REQUIRED. If it is neither an extras/ copy nor inside the extracted toolchain,
  # do not stay silent -- disassembly and the whole static half depend on it.
  if [ ! -d "$HERE/toolchain" ] || [ -z "$(find "$HERE/toolchain" -iname 'analyzeHeadless' 2>/dev/null | head -1)" ]; then
    echo "  WARNING: Ghidra (a REQUIRED engine) is neither in extras/ nor in the toolchain tree."
    echo "           Disassembly and detection will be unavailable until it is present:"
    echo "           unpack a Ghidra release into $DEST/ghidra, or rebuild the bundle on an"
    echo "           image/host that provides it."
  fi
fi

say "capability report"
if [ -n "$LYKOS_ROOT" ] && [ -d "$LYKOS_ROOT/core" ]; then
  PYTHONPATH="$LYKOS_ROOT/core" LYKOS_VENDOR="$DEST" python3 -m lykos doctor || true
elif [ -d "$HERE/../core/lykos" ]; then
  PYTHONPATH="$(cd "$HERE/.." && pwd)/core" LYKOS_VENDOR="$DEST" python3 -m lykos doctor || true
else
  echo "  run this from your lykos checkout to see it:"
  echo "    ./lykos doctor"
fi

cat <<EOF

Done -- nothing was installed. The toolchain runs in place from $DEST.
Anything still marked MISS names its own fallback line.

Next:
  cd <your lykos checkout>
  make test        # the suite; stages whose tool is absent skip, and say so
  ./start          # serve the UI on 127.0.0.1:8787
EOF
