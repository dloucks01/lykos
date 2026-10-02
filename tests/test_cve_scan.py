"""Component fingerprinting and CVE matching.

Version comparison is the whole capability: a wrong answer here does not fail loudly, it
reports the wrong CVE list for a real library. Claiming a patched build is vulnerable wastes
an analyst's day; missing a vulnerable one is worse. openssl's letter suffixes (1.0.1g),
zero-padded parts (1.0.2 vs 1.0.10) and range boundaries are exactly where that goes wrong,
and the boundaries are inclusive on one side and exclusive on the other by design.
"""
from __future__ import annotations

import pytest
from lykos.analyze.fingerprint import db, scan

# ---- version ordering --------------------------------------------------------------------

@pytest.mark.parametrize("a,b", [
    ("1.0.1", "1.0.2"),
    ("1.0.2", "1.0.10"),            # numeric, not lexicographic: "10" > "2"
    ("1.0.1f", "1.0.1g"),           # letter suffix breaks the tie
    ("1.0.1", "1.0.1a"),            # no suffix sorts before any suffix
    ("1.9.0", "1.10.0"),
    ("2018.76", "2019.1"),
    ("1.2", "1.2.1"),               # a missing part is zero, not "greater"
])
def test_a_version_orders_before_a_later_one(a, b):
    assert db.vcmp(a, b) < 0, f"{a} should sort before {b}"
    assert db.vcmp(b, a) > 0


@pytest.mark.parametrize("v", ["1.0.1", "1.0.1g", "2018.76", "1.2.11"])
def test_a_version_equals_itself(v):
    assert db.vcmp(v, v) == 0


def test_trailing_zero_parts_do_not_change_the_ordering():
    """1.2 and 1.2.0 are the same release; treating one as older silently shifts every range
    boundary that names it."""
    assert db.vcmp("1.2", "1.2.0") == 0
    assert db.vcmp("1.0", "1.0.0.0") == 0


# ---- range boundaries --------------------------------------------------------------------

def test_a_half_open_range_includes_its_lower_bound_and_excludes_its_upper():
    """`ge 1.0.1, lt 1.0.1g` is how a fixed-in advisory is written: the first affected release
    is IN and the fix is OUT. An off-by-one at either end mislabels a real build."""
    r = {"ge": "1.0.1", "lt": "1.0.1g"}
    assert db.in_range("1.0.1", r), "the first affected version was excluded"
    assert db.in_range("1.0.1f", r)
    assert not db.in_range("1.0.1g", r), "the fixed version was reported as affected"
    assert not db.in_range("1.0.0", r)
    assert not db.in_range("1.0.2", r)


def test_every_bound_in_a_range_must_hold():
    r = {"ge": "1.0", "lt": "2.0"}
    assert db.in_range("1.5", r)
    assert not db.in_range("0.9", r)
    assert not db.in_range("2.0", r)


def test_an_exact_match_range_matches_only_itself():
    r = {"eq": "1.2.11"}
    assert db.in_range("1.2.11", r)
    assert not db.in_range("1.2.12", r) and not db.in_range("1.2.10", r)


def test_a_cve_hits_if_any_of_its_ranges_does():
    """Ranges are OR'd: one CVE can affect two separate release lines."""
    cve = {"ranges": [{"ge": "1.0", "lt": "1.1"}, {"ge": "2.0", "lt": "2.1"}]}
    assert db.affected("1.0.5", cve)
    assert db.affected("2.0.5", cve)
    assert not db.affected("1.5", cve)


def test_a_cve_with_no_ranges_affects_nothing():
    """An entry with no bounds must not silently match every version in the world."""
    assert not db.affected("1.0", {"ranges": []})
    assert not db.affected("1.0", {})


# ---- the shipped database itself ---------------------------------------------------------

def test_every_shipped_cve_is_well_formed():
    """A malformed entry is inert and invisible: it simply never matches, and nothing says so."""
    from core.lykos.analyze.fingerprint import source_scan
    # Libraries detected from a vendored SOURCE header (version #defines) rather than a binary
    # banner -- an empty binary-pattern list is correct for these.
    src_detected = {lib for lib, _ in source_scan._HEADER_MACROS}
    src_detected |= {lib for lib, _ in source_scan._COMBINED_MACROS}
    src_detected |= {lib for lib, _, _ in source_scan._ABI_MACROS}      # ABI-version headers (libwebp)
    comps = scan._components()
    assert comps, "no components shipped at all"
    for lib, spec in comps.items():
        # A bare key is a C library detected by a BINARY version banner, so it needs a pattern --
        # UNLESS it is detected from a source header instead (src_detected). An "ecosystem:name"
        # key is matched from a source manifest by name, so an empty patterns list is fine for it.
        manifest_keyed = ":" in lib
        if not manifest_keyed and lib not in src_detected:
            assert spec.get("patterns"), f"{lib} has no detection pattern (banner or source header)"
        for cve in spec.get("cves", []):
            # A vuln id is usually CVE-*, but OSV also carries GHSA-*/RUSTSEC-*/PYSEC-* advisory
            # ids where no CVE was assigned; any non-empty id is a valid reference.
            assert cve.get("id"), (lib, cve)
            assert cve.get("ranges"), f"{lib} {cve.get('id')} can never match: no ranges"
            assert cve.get("cwe", "").startswith("CWE-"), (lib, cve)
            assert cve.get("severity") in ("low", "medium", "high", "critical"), (lib, cve)
            if not manifest_keyed:        # curated C-lib entries always carry a summary to show
                assert cve.get("summary"), f"{lib} {cve.get('id')} has no summary to show"
            for r in cve["ranges"]:
                assert set(r) <= {"eq", "lt", "le", "gt", "ge"}, (lib, cve["id"], r)
                assert r, f"{lib} {cve['id']} has an empty range that matches everything"


def test_every_shipped_pattern_captures_a_version():
    """The pattern has to yield the version group the matcher compares; one that matches the
    banner but captures nothing detects the library and then reports no CVEs for it."""
    import re
    for lib, spec in scan._components().items():
        for pat in spec["patterns"]:
            assert re.compile(pat).groups >= 1, f"{lib}: {pat!r} captures no version"


# ---- detection over a blob ---------------------------------------------------------------

def test_a_vulnerable_banner_is_detected_and_matched():
    blob = b"\x00\x01padding OpenSSL 1.0.1f 6 Jan 2014\x00more padding"
    detected, matches = scan.scan_and_match(blob)
    assert any(d["library"] == "openssl" and d["version"] == "1.0.1f" for d in detected)
    assert any(m["cve"] == "CVE-2014-0160" for m in matches), \
        "Heartbleed was not reported for an affected OpenSSL"


def test_a_patched_banner_is_detected_and_NOT_matched():
    """The negative matters as much: reporting Heartbleed against a fixed build is how a tool
    loses an analyst's trust."""
    blob = b"OpenSSL 1.0.1u  22 Sep 2016"
    detected, matches = scan.scan_and_match(blob)
    assert any(d["library"] == "openssl" for d in detected)
    assert not any(m["cve"] == "CVE-2014-0160" for m in matches)


def test_a_blob_with_no_component_banners_detects_nothing():
    detected, matches = scan.scan_and_match(b"\x7fELF" + b"\x00" * 4096)
    assert detected == [] and matches == []


def test_an_empty_blob_is_handled():
    assert scan.scan_and_match(b"") == ([], [])


def test_the_scan_is_capped_for_a_large_firmware_image():
    """A multi-hundred-megabyte image must not be scanned end to end on every run."""
    assert scan._MAX > 0
    big = b"\x00" * (scan._MAX + 1024) + b"OpenSSL 1.0.1f x"
    detected, _m = scan.scan_and_match(big)
    assert detected == [], "the scan read past its own cap"


def test_every_match_carries_what_the_operator_needs_to_act():
    blob = b"OpenSSL 1.0.1f 6 Jan 2014"
    _d, matches = scan.scan_and_match(blob)
    assert matches
    for m in matches:
        for k in ("library", "version", "cve", "cwe", "severity", "summary", "evidence"):
            assert m.get(k), f"match is missing {k}: {m}"
        assert m["version"] in m["evidence"], \
            "the evidence does not contain the banner the version came from"


def test_the_sqlite_sourceid_banner_detects_and_matches():
    """SQLite embeds `3.x.y <40-hex sourceid>`. This pattern had no capture group, and `scan`
    skips any pattern that matches without one -- so it contributed nothing and SQLite CVEs
    only ever fired on the rarer literal "SQLite version" text."""
    blob = b"\x00padding 3.27.2 " + b"a" * 40 + b"\x00tail"
    detected, matches = scan.scan_and_match(blob)
    assert any(d["library"] == "sqlite" and d["version"] == "3.27.2" for d in detected)
    assert {m["cve"] for m in matches} >= {"CVE-2019-5018"}


def test_the_matcher_respects_a_cve_upper_bound():
    """Range precision: a version at/above a CVE's fixed version must NOT match THAT CVE.
    (We assert per-CVE rather than "no matches at all": with the full NVD C-library feed a
    mid-range SQLite legitimately matches newer CVEs, so a blanket no-match assertion would be
    testing stale coverage, not the range logic.)"""
    # CVE-2019-5018 is fixed in 3.28.0.
    before = [m["cve"] for m in scan.match([{"library": "sqlite", "version": "3.27.2",
                                             "evidence": "3.27.2"}])]
    after = [m["cve"] for m in scan.match([{"library": "sqlite", "version": "3.28.0",
                                            "evidence": "3.28.0"}])]
    assert "CVE-2019-5018" in before
    assert "CVE-2019-5018" not in after, "a version at the fix still matched the CVE"


def test_no_open_ended_upward_range_is_shipped():
    """An open-ended-UPWARD range ({ge}/{gt} with no upper bound and no eq) matches every future
    version forever -- a false-positive factory. The NVD-CPE ingest drops these; none may ship."""
    comps = scan._components()
    for lib, spec in comps.items():
        for cve in spec["cves"]:
            for r in cve["ranges"]:
                assert {"le", "lt", "eq"} & set(r), \
                    f"{lib} {cve['id']} has an open-ended-upward range {r}"


def test_a_modern_sqlite_library_is_a_KNOWN_detection_gap():
    """Documenting a limitation rather than believing it is covered.

    Modern SQLite stores the version as a standalone `3.46.1` string and the sourceid
    separately as `<date> <40-hex>`, so neither shipped pattern matches a current
    libsqlite3.so. A bare `(3\\.\\d+\\.\\d+)` pattern WOULD match it -- and would also match
    any other component's version in a firmware image, which is how "PAT" came to match
    "MAX_PATHS" and a transport-stream model got handed to an XML parser. Detecting nothing
    is recoverable; attributing another library's version to SQLite is not.

    If this stops being true -- a tighter anchor is found, or a `requires` marker is added --
    this test should be replaced by one asserting the detection, not deleted.
    """
    modern = b"\x00sqlite3_libversion\x00" + b"3.46.1\x00" + b"\x00" * 32 \
        + b"2024-08-13 09:16:08 " + b"c" * 40
    detected, _m = scan.scan_and_match(modern)
    assert not [d for d in detected if d["library"] == "sqlite"], (
        "modern SQLite is now detected -- good; replace this test with a positive one")
