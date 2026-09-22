#!/usr/bin/env bash
# Assemble the sneakernet "burn" package under dist/burn: the repo snapshot, the toolchain
# bundle, the runbook + quickstart, a top-level checksum manifest, and one combined .zip to
# carry them all. Run on the CONNECTED machine, after `make toolchain-bundle`.
#
# The repo snapshot is cut from the CURRENT WORKING TREE (tracked + new files, honouring
# .gitignore) via a throwaway git index -- so an in-progress fix rides along without a commit,
# and neither HEAD nor the branch nor the real index is touched. Commit when you are ready; the
# burn package does not require it.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"; BURN="$DIST/burn"
say(){ printf '\n== %s\n' "$*"; }
die(){ echo "ERROR: $*" >&2; exit 1; }

command -v zip >/dev/null 2>&1 || die "need zip to build the combined archive (apt-get install zip)"

# newest toolchain bundle in dist/
TC="$(ls -1t "$DIST"/lykos-toolchain-*.tar.zst 2>/dev/null | head -1 || true)"
[ -n "$TC" ] || die "no toolchain bundle in dist/ -- run 'make toolchain-bundle' first"
[ -f "$TC.sha256" ] || die "missing $TC.sha256 (the collector writes it)"
TCB="$(basename "$TC")"

say "repo snapshot from the working tree (no commit)"
REPO="$DIST/lykos-repo.tar.gz"
tmpidx="$(mktemp)"; trap 'rm -f "$tmpidx"' EXIT
cp "$ROOT/.git/index" "$tmpidx" 2>/dev/null || : > "$tmpidx"
GIT_INDEX_FILE="$tmpidx" git -C "$ROOT" add -A
tree="$(GIT_INDEX_FILE="$tmpidx" git -C "$ROOT" write-tree)"
commit="$(git -C "$ROOT" commit-tree "$tree" -m 'burn snapshot (working tree)')"
git -C "$ROOT" archive --format=tar.gz --prefix=lykos/ -o "$REPO" "$commit"
( cd "$DIST" && sha256sum lykos-repo.tar.gz > lykos-repo.tar.gz.sha256 )
printf '  %s (%s)\n' "$REPO" "$(du -h "$REPO" | cut -f1)"

say "staging dist/burn"
rm -rf "$BURN"; mkdir -p "$BURN"
cp "$ROOT/docs/23-airgap-install.md" "$BURN/AIRGAP-INSTALL.md"
cp "$ROOT/QUICKSTART.md" "$BURN/QUICKSTART.md"
cp "$REPO" "$TC" "$BURN/"
# Regenerate the per-file sidecars with BARE filenames, so `sha256sum -c <file>.sha256` works
# when run from inside dist/burn (a copied sidecar can carry a dist/ or absolute path).
( cd "$BURN" && sha256sum lykos-repo.tar.gz > lykos-repo.tar.gz.sha256 && sha256sum "$TCB" > "$TCB.sha256" )

# Top-level manifest over the primary payload files (not the .sha256 sidecars). This is the
# integrity check for the burn as a whole; each tarball also carries its own .sha256.
( cd "$BURN" && sha256sum QUICKSTART.md lykos-repo.tar.gz "$TCB" AIRGAP-INSTALL.md > SHA256SUMS )

say "combined archive"
( cd "$BURN" && zip -q -X lykos_copy.zip \
    AIRGAP-INSTALL.md lykos-repo.tar.gz lykos-repo.tar.gz.sha256 \
    "$TCB" "$TCB.sha256" QUICKSTART.md SHA256SUMS )

say "burn package ready in $BURN"
ls -la "$BURN"
echo
echo "Verify on arrival (air-gapped side), then follow AIRGAP-INSTALL.md:"
echo "  sha256sum -c SHA256SUMS"
echo "Nothing is installed: the toolchain runs in place from the repo's vendor/ (see the runbook)."
