"""Target libraries ("sysroots") from the GUI without a server path (api/sysroot.py + api/ops.py).

  * an uploaded .tar/.tar.gz/.zip is extracted ONCE into the case, listed with what it holds
    (lib dirs, loaders), and removable;
  * extraction is safe: a member that climbs out of the root refuses the archive, a symlink that
    escapes is skipped (never followed), device nodes are never created, size caps hold, and an
    absolute symlink is re-rooted INSIDE the sysroot (QEMU_LD_PREFIX semantics);
  * the autopilot takes `overrides.sysroot_sha` (resolved server side to the extracted dir, passed
    on as `sysroot`), refuses an unknown hash, and still drops a raw `sysroot` path.
"""
from __future__ import annotations

import http.client
import io
import json
import os
import socket
import tarfile
import time
import zipfile

import pytest
from lykos.api import sysroot as sr
from lykos.api.server import serve, shutdown


@pytest.fixture
def api(tmp_path):
    sock = str(tmp_path / "s.sock")
    servers, pool = serve(tmp_path / "cs", sock, workers=1, block=False)
    for _ in range(200):
        if os.path.exists(sock):
            break
        time.sleep(0.02)
    try:
        yield sock, tmp_path / "cs"
    finally:
        shutdown(servers, pool)


class _UDS(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost")
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self._path)


def _req(sock, method, url, body=None, headers=None):
    c = _UDS(sock)
    try:
        c.request(method, url, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        try:
            return r.status, json.loads(data) if data else None
        except ValueError:
            return r.status, data
    finally:
        c.close()


def _jreq(sock, method, url, obj=None):
    body = json.dumps(obj).encode() if obj is not None else None
    return _req(sock, method, url, body,
                {"Content-Type": "application/json"} if obj is not None else {})


def _case(sock, cs):
    from lykos.casestore import CaseStore
    _st, case = _jreq(sock, "POST", "/cases", {"name": "sysroot"})
    st = CaseStore.open(cs)
    try:
        st.targets.upsert(case["id"], "t.bin", "ab" * 32, file_type="elf", arch="aarch64")
        st.conn.commit()
    finally:
        st.close()
    return case["id"]


def _tar(entries, mode="w:gz"):
    """entries: (name, kind, data/linkname) with kind in file|dir|sym|hard|chr|fifo."""
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode=mode) as tf:
        for name, kind, val in entries:
            ti = tarfile.TarInfo(name)
            if kind == "file":
                ti.size = len(val)
                ti.mode = 0o755
                tf.addfile(ti, io.BytesIO(val))
                continue
            ti.type = {"dir": tarfile.DIRTYPE, "sym": tarfile.SYMTYPE, "hard": tarfile.LNKTYPE,
                       "chr": tarfile.CHRTYPE, "fifo": tarfile.FIFOTYPE}[kind]
            if kind in ("sym", "hard"):
                ti.linkname = val
            tf.addfile(ti)
    return bio.getvalue()


def _up(sock, cid, data, name="libs.tar.gz"):
    return _req(sock, "POST", f"/cases/{cid}/sysroots", data,
                {"Content-Type": "application/octet-stream", "X-Filename": name})


GOOD = [("lib", "dir", None),
        ("lib/ld-linux-aarch64.so.1", "file", b"\x7fELF-loader"),
        ("lib/libc.so.6", "file", b"\x7fELF-libc"),
        ("usr/lib/libz.so.1", "sym", "/lib/libc.so.6"),          # absolute: re-rooted
        ("dev/null", "chr", None),                                # a rootfs device node: skipped
        ("run/fifo", "fifo", None)]


# --------------------------------------------------------------------------- upload / list / remove
def test_upload_extracts_once_lists_and_removes(api):
    sock, cs = api
    cid = _case(sock, cs)
    code, rec = _up(sock, cid, _tar(GOOD), "../../etc/rootfs.tar.gz")
    assert code == 201, rec
    assert rec["name"] == "rootfs.tar.gz"                       # display name only, basename
    assert rec["loaders"] == ["lib/ld-linux-aarch64.so.1"]
    assert "lib" in rec["lib_dirs"] and "usr/lib" in rec["lib_dirs"]
    assert rec["skipped"] == 2                                  # the chr + fifo nodes
    root = sr.sysroot_dir(cs, cid, rec["sha256"])
    assert (root / "lib/libc.so.6").read_bytes() == b"\x7fELF-libc"
    link = root / "usr/lib/libz.so.1"
    assert link.is_symlink() and os.readlink(link) == "../../lib/libc.so.6"
    assert link.resolve() == (root / "lib/libc.so.6").resolve()  # inside, not the host's /lib
    assert not (root / "dev/null").exists() and not (root / "run/fifo").exists()
    # the archive itself is in the case store (re-extractable after an import)
    from lykos.casestore import ContentStore
    assert ContentStore(cs).path(rec["sha256"]).is_file()
    _c, lst = _jreq(sock, "GET", f"/cases/{cid}/sysroots")
    assert [x["sha256"] for x in lst["sysroots"]] == [rec["sha256"]]
    assert lst["max_bytes"] == sr.MAX_ARCHIVE_BYTES
    # the same archive again is the same sysroot, not a second one
    code, again = _up(sock, cid, _tar(GOOD))
    assert code == 200 and again["sha256"] == rec["sha256"]
    assert len(_jreq(sock, "GET", f"/cases/{cid}/sysroots")[1]["sysroots"]) == 1
    # remove: event + extracted dir
    assert _req(sock, "DELETE", f"/cases/{cid}/sysroots/{rec['sha256']}")[0] == 200
    assert _jreq(sock, "GET", f"/cases/{cid}/sysroots")[1]["sysroots"] == []
    assert not root.exists()
    assert _req(sock, "DELETE", f"/cases/{cid}/sysroots/{rec['sha256']}")[0] == 404
    assert _req(sock, "GET", "/cases/nope/sysroots")[0] == 404
    assert _up(sock, "nope", _tar(GOOD))[0] == 404


def test_a_lone_wrapper_directory_is_the_root(api):
    sock, cs = api
    cid = _case(sock, cs)
    code, rec = _up(sock, cid, _tar([("rootfs/lib/ld-linux-aarch64.so.1", "file", b"L"),
                                     ("rootfs/lib/libc.so.6", "file", b"C")]))
    assert code == 201 and rec["base"] == "rootfs" and rec["loaders"] == ["lib/ld-linux-aarch64.so.1"]


def test_zip_archives_are_accepted(api):
    sock, cs = api
    cid = _case(sock, cs)
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("lib/ld-musl-mips.so.1", b"L")
        zf.writestr("lib/libc.so", b"C")
    code, rec = _up(sock, cid, bio.getvalue(), "libs.zip")
    assert code == 201, rec
    assert rec["loaders"] == ["lib/ld-musl-mips.so.1"]
    assert (sr.sysroot_dir(cs, cid, rec["sha256"]) / "lib/libc.so").read_bytes() == b"C"


# --------------------------------------------------------------------------- extraction safety
@pytest.mark.parametrize("evil", ["../escape.so", "lib/../../escape.so", "/../../escape.so"])
def test_a_member_outside_the_root_refuses_the_whole_archive(api, evil):
    sock, cs = api
    cid = _case(sock, cs)
    code, err = _up(sock, cid, _tar([("lib/libc.so.6", "file", b"C"), (evil, "file", b"X")]))
    assert code == 400 and "refused" in err["error"]
    assert _jreq(sock, "GET", f"/cases/{cid}/sysroots")[1]["sysroots"] == []
    assert not list(cs.rglob("escape.so")) and not (cs.parent / "escape.so").exists()
    # nothing half-extracted is left behind
    assert not [p for p in (cs / "sysroots" / cid).iterdir() if not p.name.startswith(".")]


def test_a_symlink_escape_is_skipped_and_never_written_through(api, tmp_path):
    sock, cs = api
    cid = _case(sock, cs)
    outside = tmp_path / "outside"
    outside.mkdir()
    code, rec = _up(sock, cid, _tar([("lib/libc.so.6", "file", b"C"),
                                     ("esc", "sym", "../../../../../../" + str(outside).lstrip("/")),
                                     ("esc/pwn", "file", b"PWNED"),
                                     ("hl", "hard", "../../etc/passwd")]))
    assert code == 201, rec
    assert rec["skipped"] >= 2
    assert not (outside / "pwn").exists()
    root = sr.sysroot_dir(cs, cid, rec["sha256"])
    assert not (root / "esc").is_symlink() and not (root / "hl").exists()


def test_zip_traversal_is_refused(api):
    sock, cs = api
    cid = _case(sock, cs)
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("lib/libc.so", b"C")
        zf.writestr("../../zip-escape.so", b"X")
    code, err = _up(sock, cid, bio.getvalue(), "evil.zip")
    assert code == 400 and "escapes the root" in err["error"]
    assert not list(cs.parent.rglob("zip-escape.so"))


def test_size_caps(api, monkeypatch):
    sock, cs = api
    cid = _case(sock, cs)
    monkeypatch.setattr(sr, "MAX_EXTRACTED_BYTES", 1000)
    code, err = _up(sock, cid, _tar([("lib/big.so", "file", b"\0" * 5000)]))
    assert code == 400 and "expands past" in err["error"]          # a bomb is refused pre-write
    monkeypatch.setattr(sr, "MAX_MEMBERS", 3)
    code, err = _up(sock, cid, _tar([(f"lib/{i}.so", "file", b"x") for i in range(5)]))
    assert code == 400 and "members" in err["error"]
    monkeypatch.setattr(sr, "MAX_ARCHIVE_BYTES", 100)
    code, _e = _up(sock, cid, os.urandom(200_000))
    assert code == 413
    assert _up(sock, cid, b"")[0] == 400
    assert _up(sock, cid, b"definitely not an archive")[0] == 400
    assert _jreq(sock, "GET", f"/cases/{cid}/sysroots")[1]["sysroots"] == []


def test_reroot_link_unit():
    assert sr._reroot_link("lib/libc.so.6", "/lib/libc-2.31.so") == "libc-2.31.so"
    assert sr._reroot_link("usr/lib/a", "../../lib/x") == "../../lib/x"
    assert sr._reroot_link("lib/a", "../../etc") is None           # climbs above the root
    assert sr._reroot_link("lib/a", "/../../etc/passwd") == "../etc/passwd"   # "/.." is "/"


# --------------------------------------------------------------------------- autopilot resolution
def _capture_autopilot(monkeypatch):
    from lykos.analyze import orchestrate
    seen = {}

    def fake(case_dir, cid, target_ids, status, stop, secs, over, *a, **k):
        seen["over"] = over
        status["state"] = "done"
    monkeypatch.setattr(orchestrate, "run_case_autopilot", fake)
    return seen


def _wait_done(sock, cid):
    for _ in range(100):
        if not _jreq(sock, "GET", f"/cases/{cid}/autopilot")[1].get("running"):
            return
        time.sleep(0.02)


def test_autopilot_resolves_sysroot_sha_server_side(api, monkeypatch):
    sock, cs = api
    cid = _case(sock, cs)
    seen = _capture_autopilot(monkeypatch)
    code, err = _jreq(sock, "POST", f"/cases/{cid}/autopilot",
                      {"overrides": {"sysroot_sha": "0" * 64}})
    assert code == 400 and "not in this case" in err["error"]
    code, err = _jreq(sock, "POST", f"/cases/{cid}/autopilot",
                      {"overrides": {"sysroot_sha": "/etc"}})
    assert code == 400 and "hash" in err["error"]
    assert "over" not in seen                                       # refused before any run
    code, rec = _up(sock, cid, _tar(GOOD))
    assert code == 201
    # the sha resolves to the extracted dir; a raw browser path alongside it is ignored
    code, ok = _jreq(sock, "POST", f"/cases/{cid}/autopilot",
                     {"overrides": {"sysroot_sha": rec["sha256"].upper(), "sysroot": "/"}})
    assert code == 202, ok
    _wait_done(sock, cid)
    assert seen["over"]["sysroot"] == str(sr.sysroot_dir(cs, cid, rec["sha256"]))
    assert "sysroot_sha" not in seen["over"]
    # a raw path ALONE is still dropped (the CLI-only rule)
    seen.clear()
    code, _ok = _jreq(sock, "POST", f"/cases/{cid}/autopilot", {"overrides": {"sysroot": "/"}})
    assert code == 202
    _wait_done(sock, cid)
    assert "sysroot" not in (seen["over"] or {})


def test_a_missing_extraction_is_rebuilt_from_the_stored_archive(api, monkeypatch):
    import shutil
    sock, cs = api
    cid = _case(sock, cs)
    code, rec = _up(sock, cid, _tar([("rootfs/lib/libc.so.6", "file", b"C")]))
    assert code == 201
    d = sr.sysroot_dir(cs, cid, rec["sha256"])
    shutil.rmtree(d)                                                # e.g. after a case import
    seen = _capture_autopilot(monkeypatch)
    code, _ok = _jreq(sock, "POST", f"/cases/{cid}/autopilot",
                      {"overrides": {"sysroot_sha": rec["sha256"]}})
    assert code == 202
    _wait_done(sock, cid)
    assert seen["over"]["sysroot"] == str(d / "rootfs")
    assert (d / "rootfs/lib/libc.so.6").read_bytes() == b"C"
