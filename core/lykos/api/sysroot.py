"""Operator-uploaded target libraries ("sysroots") -- the GUI's answer to LYKOS_QEMU_SYSROOT.

A foreign-arch or old-glibc target only runs under afl-qemu / concolic / the sandbox against ITS
OWN loader and .so files (QEMU_LD_PREFIX). The CLI points LYKOS_QEMU_SYSROOT at a directory; a
browser must never name a server path, so instead the operator uploads an ARCHIVE (.tar, .tar.gz,
.tar.xz, .tar.bz2, .zip) of the target's lib dirs or a firmware-rootfs subset. It is:

  * stored content-addressed in the case (artifact kind `operator-sysroot`) and recorded in the
    case's event log (`operator.sysroot` add/remove), exactly like operator seeds;
  * extracted ONCE into `<store>/sysroots/<case>/<sha>/` with tar's "data" filter -- no member
    outside the root, no device/fifo nodes, no setuid bits -- under file-count and size caps;
    an absolute symlink (`/lib/libc.so.6`, common in a rootfs) is re-rooted to point inside the
    sysroot, which is what QEMU_LD_PREFIX means by it; a link that still escapes is skipped;
  * referenced by an autopilot start as `overrides.sysroot_sha` and resolved HERE, server side,
    to the extracted directory (re-extracted from the stored archive if that dir is missing, e.g.
    after a case import). Nothing from the browser is ever used as a path.
"""
from __future__ import annotations

import hashlib
import os
import posixpath
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path

#: Largest archive accepted (the upload body).
MAX_ARCHIVE_BYTES = 512 << 20
#: Largest total extracted size (header-declared for tar, counted while writing for zip).
MAX_EXTRACTED_BYTES = 2 << 30
#: Most archive members (files + dirs + links).
MAX_MEMBERS = 50_000
#: Sysroots per case.
MAX_CASE_SYSROOTS = 8
SYSROOT_EVENT = "operator.sysroot"
SYSROOT_KIND = "operator-sysroot"
_DIRNAME = "sysroots"
_SAFE_ID = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
#: A lone top-level directory with one of these names IS the rootfs layout, not a wrapper.
_ROOT_NAMES = {"lib", "lib32", "lib64", "usr", "etc", "bin", "sbin", "opt"}
_LOADER = re.compile(r"^(ld-.*\.so.*|ld\.so.*|ld64\.so.*|ld-linux.*|ld-musl-.*|ld-uClibc.*)$")


class SysrootError(ValueError):
    """The archive is refused (unsafe, too big, unreadable). The message is operator-facing."""


# --------------------------------------------------------------------------- the case's set
def case_sysroots(conn, case_id: str) -> list[dict]:
    """The case's current sysroots, folded from its `operator.sysroot` add/remove events."""
    from ..db.dao import EventDAO
    out: dict = {}
    for p in EventDAO(conn).payloads_of_type(SYSROOT_EVENT, case_id=case_id):
        sha = p.get("sha256")
        if not isinstance(sha, str):
            continue
        if p.get("action") == "remove":
            out.pop(sha, None)
        else:
            out[sha] = {k: p.get(k) for k in ("sha256", "name", "size", "files", "bytes",
                                              "lib_dirs", "loaders", "base", "skipped")}
    return list(out.values())


def sysroot_dir(store_dir, case_id: str, sha: str) -> Path:
    """Where a case's sysroot is extracted. Both ids are validated: they become path parts."""
    if not _SAFE_ID.match(str(case_id)) or not _SHA.match(str(sha)):
        raise SysrootError("bad case id or sysroot hash")
    return Path(store_dir) / _DIRNAME / case_id / sha


def staging_parent(store_dir, case_id: str) -> Path:
    if not _SAFE_ID.match(str(case_id)):
        raise SysrootError("bad case id")
    d = Path(store_dir) / _DIRNAME / case_id
    d.mkdir(parents=True, exist_ok=True)
    return d


# --------------------------------------------------------------------------- extraction
def _clean_name(name: str) -> str:
    """An archive member name as a root-relative posix path ('' for the root itself). A name
    that climbs out of the root is refused -- that archive is hostile or broken either way."""
    n = name.replace("\\", "/")
    if re.match(r"^[A-Za-z]:", n):
        raise SysrootError(f"archive member has a drive path: {name[:120]!r}")
    parts = []
    for p in n.split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            raise SysrootError(f"archive member escapes the root: {name[:120]!r}")
        parts.append(p)
    return "/".join(parts)


def _reroot_link(member_name: str, target: str) -> str | None:
    """A symlink target as seen from inside the sysroot. An ABSOLUTE target means the guest's root
    (QEMU_LD_PREFIX semantics) and is rewritten relative to the link's own directory; a relative
    one is kept. None when a relative target climbs above the root (the link is skipped)."""
    parent = posixpath.dirname(_clean_name(member_name))
    if target.startswith("/"):
        absolute = posixpath.normpath("/" + target.lstrip("/"))     # "/.." is "/" for the guest too
        return posixpath.relpath(absolute, "/" + parent) if parent else (absolute.lstrip("/") or ".")
    depth = 0
    for p in (parent.split("/") if parent else []) + target.split("/"):
        if p in ("", "."):
            continue
        depth = depth - 1 if p == ".." else depth + 1
        if depth < 0:
            return None
    return target


def _inside(root: Path, p: Path) -> bool:
    rr = os.path.realpath(root)
    rp = os.path.realpath(p)
    return rp == rr or rp.startswith(rr + os.sep)


def _extract_tar(archive: Path, dest: Path) -> int:
    try:
        tf = tarfile.open(archive, "r:*")
    except (tarfile.TarError, OSError, EOFError) as e:
        raise SysrootError(f"not a readable tar archive: {e}") from None
    skipped = 0
    with tf:
        try:
            members = []
            total = 0
            for m in tf:
                members.append(m)
                if len(members) > MAX_MEMBERS:
                    raise SysrootError(f"archive has more than {MAX_MEMBERS} members")
                if m.isreg():
                    total += m.size
                    if total > MAX_EXTRACTED_BYTES:
                        raise SysrootError(f"archive expands past {MAX_EXTRACTED_BYTES >> 20} MiB")
        except (tarfile.TarError, EOFError, OSError) as e:
            raise SysrootError(f"corrupt tar archive: {e}") from None

        def _filter(member, path):
            nonlocal skipped
            _clean_name(member.name)                     # traversal in a NAME: refuse the archive
            if member.ischr() or member.isblk() or member.isfifo() or member.issparse():
                skipped += 1                             # rootfs /dev nodes: never extracted
                return None
            if member.issym():
                link = _reroot_link(member.name, member.linkname)
                if link is None:
                    skipped += 1
                    return None
                if link != member.linkname:
                    member = member.replace(linkname=link, deep=False)
            try:
                return tarfile.data_filter(member, path)
            except (tarfile.AbsoluteLinkError, tarfile.LinkOutsideDestinationError):
                skipped += 1                             # a link that escapes: skipped, not followed
                return None
            except tarfile.FilterError as e:
                raise SysrootError(f"unsafe archive member {member.name[:120]!r}: {e}") from None

        try:
            tf.extractall(dest, members=members, filter=_filter)
        except SysrootError:
            raise
        except (tarfile.TarError, OSError, EOFError) as e:
            raise SysrootError(f"extraction failed: {e}") from None
    return skipped


def _extract_zip(archive: Path, dest: Path) -> int:
    try:
        zf = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as e:
        raise SysrootError(f"not a readable zip archive: {e}") from None
    skipped = 0
    written = 0
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            raise SysrootError(f"archive has more than {MAX_MEMBERS} members")
        for zi in infos:
            rel = _clean_name(zi.filename)
            if not rel:
                continue
            out = dest / rel
            mode = (zi.external_attr >> 16) & 0xFFFF
            ftype = stat.S_IFMT(mode)
            if zi.is_dir() or ftype == stat.S_IFDIR:
                if not _inside(dest, out.parent):
                    skipped += 1
                    continue
                out.mkdir(parents=True, exist_ok=True)
                continue
            if ftype and ftype not in (stat.S_IFREG, stat.S_IFLNK):
                skipped += 1                             # device / fifo / socket entries
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            if not _inside(dest, out.parent):
                skipped += 1                             # parent is a link that leaves the root
                continue
            if ftype == stat.S_IFLNK:
                target = zf.read(zi)[:4096].decode("utf-8", "replace")
                link = _reroot_link(rel, target)
                if link is None or os.path.lexists(out):
                    skipped += 1
                    continue
                os.symlink(link, out)
                if not _inside(dest, out):
                    os.unlink(out)
                    skipped += 1
                continue
            if os.path.lexists(out):
                if out.is_symlink() or out.is_dir():
                    skipped += 1                         # never write THROUGH a link
                    continue
                out.unlink()
            try:
                with zf.open(zi) as src, open(out, "xb") as dst:
                    while True:
                        chunk = src.read(1 << 20)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > MAX_EXTRACTED_BYTES:
                            raise SysrootError(
                                f"archive expands past {MAX_EXTRACTED_BYTES >> 20} MiB")
                        dst.write(chunk)
            except (zipfile.BadZipFile, OSError, RuntimeError, EOFError) as e:
                raise SysrootError(f"extraction failed on {rel[:120]!r}: {e}") from None
            perm = mode & 0o755 if mode & 0o777 else 0o644
            os.chmod(out, perm | 0o400)
    return skipped


def _is_zip(path: Path) -> bool:
    with open(path, "rb") as fh:
        head = fh.read(4)
    return head in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def describe(root: Path) -> dict:
    """What the extracted tree holds, for the operator: file/byte counts, the lib dirs the sandbox
    will use, and the dynamic loaders found (a sysroot without one cannot start a dynamic guest)."""
    from ..analyze.dynamic.sandbox import _sysroot_lib_dirs
    files = size = 0
    for dp, dns, fns in os.walk(root):
        for fn in fns:
            try:
                st = os.lstat(os.path.join(dp, fn))
            except OSError:
                continue
            files += 1
            if stat.S_ISREG(st.st_mode):
                size += st.st_size
    libs = [Path(d) for d in _sysroot_lib_dirs(root)]
    rel_libs = sorted({(posixpath.relpath(d.as_posix(), root.as_posix()) if d != root else ".")
                       for d in libs})
    loaders = []
    for d in libs:
        try:
            for e in sorted(os.listdir(d)):
                if _LOADER.match(e):
                    rel = posixpath.relpath((d / e).as_posix(), root.as_posix())
                    if rel not in loaders:
                        loaders.append(rel)
        except OSError:
            continue
    return {"files": files, "bytes": size, "lib_dirs": rel_libs[:24], "loaders": loaders[:12]}


def _pick_base(top: Path) -> str:
    """'' when the extracted tree is itself the root; the name of a lone wrapper directory
    (`rootfs/`, `target-libs/`) otherwise, so `rootfs/lib/...` works like `lib/...`."""
    try:
        entries = list(top.iterdir())
    except OSError:
        return ""
    if len(entries) == 1:
        e = entries[0]
        if e.is_dir() and not e.is_symlink() and e.name not in _ROOT_NAMES:
            return e.name
    return ""


def extract(archive: Path, dest: Path) -> dict:
    """Extract `archive` into the NEW directory `dest` (made here). Atomic: it is extracted into a
    sibling staging dir and renamed into place only when complete, so a refused or failed archive
    leaves nothing behind. Returns describe() + {base, skipped}. Raises SysrootError."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".extract-", dir=dest.parent))
    try:
        top = stage / "root"
        top.mkdir()
        skipped = _extract_zip(archive, top) if _is_zip(archive) else _extract_tar(archive, top)
        if not any(top.iterdir()):
            raise SysrootError("the archive is empty")
        base = _pick_base(top)
        info = describe(top / base if base else top)
        info.update(base=base, skipped=skipped)
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        os.rename(top, dest)
        return info
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve(store_dir, content, conn, case_id: str, sha) -> tuple:
    """`overrides.sysroot_sha` -> (directory, None) or (None, error). Only a sysroot uploaded into
    THIS case resolves; its dir is re-extracted from the stored archive when missing."""
    if not isinstance(sha, str) or not _SHA.match(sha.lower()):
        return None, "overrides.sysroot_sha must be the hash of a sysroot uploaded into this case"
    sha = sha.lower()
    rec = next((x for x in case_sysroots(conn, case_id) if x["sha256"] == sha), None)
    if rec is None:
        return None, f"sysroot {sha[:12]} is not in this case"
    try:
        d = sysroot_dir(store_dir, case_id, sha)
    except SysrootError as e:
        return None, str(e)
    if not d.is_dir():
        arch = content.path(sha)
        if not arch.is_file():
            return None, f"sysroot {sha[:12]} is missing from the case store"
        try:
            extract(arch, d)
        except SysrootError as e:
            return None, f"sysroot {sha[:12]} could not be re-extracted: {e}"
    base = rec.get("base") or ""
    root = d / base if base and _SAFE_ID.match(base) else d
    if not root.is_dir() or not _inside(d, root):
        return None, f"sysroot {sha[:12]} has no usable root"
    return str(root), None
