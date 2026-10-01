"""Phase 3 — offline component/CVE fingerprinting: version comparison, scan+match, and the
cve_scan stage turning embedded version banners into CVE findings (no execution)."""
import pytest
from lykos.analyze import register
from lykos.analyze.fingerprint import db, enqueue_cve_scan, scan
from lykos.analyze.ingest import ingest
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


def test_version_compare_handles_letters_and_padding():
    assert db.vcmp("1.2.11", "1.2.12") < 0
    assert db.vcmp("1.0.2k", "1.0.2") > 0          # letter suffix > no suffix
    assert db.vcmp("1.0.1g", "1.0.1f") > 0
    assert db.vcmp("1.35.0", "1.34.0") > 0
    assert db.vcmp("1.2.12", "1.2.12") == 0
    assert db.vcmp("2018.76", "2018.75") > 0


def test_affected_ranges_or_and_and():
    cve = {"ranges": [{"ge": "1.0.1", "lt": "1.0.1g"}, {"ge": "1.0.2", "lt": "1.0.2h"}]}
    assert db.affected("1.0.1f", cve)              # first range
    assert db.affected("1.0.2a", cve)              # second range
    assert not db.affected("1.0.1g", cve)          # patched
    assert not db.affected("1.1.0", cve)


def test_scan_detects_banners_and_matches_cves():
    blob = (b"...junk... OpenSSL 1.0.1f 6 Jan 2014 ...\x00"
            b"deflate 1.2.8 Copyright ...\x00 BusyBox v1.20.0 (2019) multi-call ...")
    detected = scan.scan(blob)
    libs = {(d["library"], d["version"]) for d in detected}
    assert ("openssl", "1.0.1f") in libs
    assert ("zlib", "1.2.8") in libs
    assert ("busybox", "1.20.0") in libs
    cves = {m["cve"] for m in scan.match(detected)}
    assert "CVE-2014-0160" in cves                 # Heartbleed on openssl 1.0.1f
    assert "CVE-2018-25032" in cves                # zlib 1.2.8 < 1.2.12


def test_scan_version_range_filtering():
    # Version-range filtering must exclude vulns that only affect OLDER releases: a current
    # OpenSSL 3.x is not Heartbleed (CVE-2014-0160, a 1.0.1 bug) however complete the DB is.
    detected = scan.scan(b"OpenSSL 3.0.7 stuff")
    assert ("openssl", "3.0.7") in {(d["library"], d["version"]) for d in detected}
    cves = {m["cve"] for m in scan.match(detected)}
    assert "CVE-2014-0160" not in cves             # Heartbleed only affects 1.0.1
    assert "CVE-2014-0224" not in cves             # CCS injection, <=1.0.1g


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=30, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_cve_stage_creates_findings(store, case, pool, tmp_path):
    f = tmp_path / "fw.bin"
    f.write_bytes(b"header OpenSSL 1.0.1f build\x00 BusyBox v1.20.0 \x00 padding" * 4)
    target = ingest(store, case.id, f)
    q = JobQueue(store.conn)
    run = enqueue_cve_scan(q, target)
    assert pool.wait_idle(30) and q.runs.get(run.id).status == "done"
    finds = [x for x in FindingDAO(store.conn).list_by_target(target.id)
             if x.detector == "cve_fingerprint"]
    cwes = " ".join(x.title for x in finds)
    assert "CVE-2014-0160" in cwes and "busybox 1.20.0" in cwes.lower()
