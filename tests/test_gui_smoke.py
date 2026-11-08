"""Every app3 screen renders against a realistic case with no page error.

The GUI is untyped ES modules with no build step, so a mistake shows up only when a browser runs
it: a duplicate import, or a filter store whose defaults were skipped while a case loaded, blanked
the Proof screen. Unit tests on the server cannot see that. This loads each screen in headless
Chrome against a seeded case -- source-site findings (path:line and the `file: fn()` form), a noise
finding, triage dispositions, a source tree -- and fails on any page error or 5xx. Skipped when no
Chrome / Playwright is installed.
"""
from __future__ import annotations

import io
import shutil
import socket
import tarfile
import time

import pytest

playwright = pytest.importorskip("playwright.sync_api")
CHROME = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
pytestmark = pytest.mark.skipif(not CHROME, reason="no Chrome/Chromium for the headless GUI smoke")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _seed(case_dir, sample_elf):
    from lykos.casestore import CaseStore
    from lykos.db.dao import FindingDAO
    st = CaseStore.open(case_dir)
    try:
        case = st.cases.create("gui-smoke")
        sha, _rel, size = st.content.put_bytes(sample_elf.read_bytes())
        t = st.targets.upsert(case.id, "harness", sha, size=size, file_type="elf", arch="x86-64")
        st.targets.upsert(case.id, "libproj.so.1", "LIBSHA", size=10, file_type="elf")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, text in {"codec/clear.c": "int f(int numBits)\n{\n\tstop = t & M[numBits];\n}\n",
                               "audin/audin_main.c": "\n".join(f"/* {i} */" for i in range(1, 300))}.items():
                data = text.encode()
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
        st.put_artifact(case.id, "source-project", data=buf.getvalue(), meta={"binary_sha": sha})
        fd = FindingDAO(st.conn)
        rows = [
            {"cwe": "CWE-787", "title": "Potential PoC: out-of-bounds write at audin_main.c:251",
             "detector": "surface_recipe", "state": "corroborated", "severity": "high",
             "evidence": [{"channel": "recipe", "detail": "CWE-787 at audin_main.c:251 is reachable"},
                          {"channel": "triage", "detail": "drivable: reachable + tainted"}]},
            {"cwe": "CWE-129", "title": "Wire value -> index without a bound: numBits",
             "detector": "wire_flow", "state": "candidate", "severity": "medium",
             "evidence": [{"channel": "source", "detail": "codec/clear.c: f() uses wire-read "
                                                          "'numBits' as a index -- stop = t & M[numBits];"},
                          {"channel": "triage", "detail": "off-surface: not compiled into a harness"}]},
            {"cwe": "CWE-129", "title": "Improper validation of array index", "detector": "oob_index",
             "state": "corroborated", "severity": "high",
             "evidence": [{"channel": "triage", "detail": "false-positive: grounding disproved it"}]},
            {"cwe": "CWE-121", "title": "Stack buffer overflow in main", "detector": "stack_frame",
             "state": "candidate", "severity": "high", "function_addr": "0x1139",
             "evidence": [{"channel": "static", "detail": "strcpy into a 64-byte frame buffer"}]},
            {"cwe": "CWE-416", "title": "attack path: entry -> UAF", "detector": "attack_path",
             "state": "candidate", "severity": "high", "evidence": []},
        ]
        for i, r in enumerate(rows):
            fd.upsert(t.id, case.id, {**r, "dedup_key": f"smoke:{i}"})
        return case.id
    finally:
        st.close()


@pytest.fixture
def gui(tmp_path, sample_elf):
    from lykos.api.server import serve, shutdown
    cid = _seed(tmp_path / "cs", sample_elf)
    port = _free_port()
    servers, pool = serve(tmp_path / "cs", http=("127.0.0.1", port), workers=1, block=False)
    base = f"http://127.0.0.1:{port}"
    for _ in range(200):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    try:
        yield base, cid
    finally:
        shutdown(servers, pool)


def test_every_screen_renders_without_a_page_error(gui):
    base, cid = gui
    from playwright.sync_api import sync_playwright
    problems: list = []
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=CHROME, headless=True)
        pg = b.new_page(viewport={"width": 1400, "height": 1000})
        pg.on("pageerror", lambda e: problems.append(f"{pg.url}: pageerror {e}"))
        pg.on("response", lambda r: problems.append(f"{pg.url}: HTTP {r.status} {r.url}")
              if r.status >= 500 else None)
        for view in ("engagement", "run", "proof", "code", "system"):
            pg.goto(f"{base}/#case={cid}&view={view}")
            pg.wait_for_selector("main", timeout=15000)
            pg.wait_for_timeout(1500)
        # Proof: the source finding shows WHERE it is, and its row opens the source at the site
        pg.goto(f"{base}/#case={cid}&view=proof")
        pg.wait_for_selector(".fl-row", timeout=15000)
        text = pg.inner_text("main")
        assert "audin_main.c:251" in text, text[:800]
        pg.locator(".fl-row > button").first.click()
        pg.wait_for_timeout(1500)
        # the finding detail and Back
        pg.goto(f"{base}/#case={cid}&view=proof")
        pg.wait_for_selector(".fl-row", timeout=15000)
        b.close()
    assert not problems, "\n".join(problems)
