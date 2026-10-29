"""Build-dependency pre-flight: read a source project's OWN build declarations and check each
against this host, so the gaps are a checklist staged BEFORE the box goes offline -- not a silent
build failure that costs the whole binary/dynamic capability for that target.

The parsers are tested as pure functions (deterministic); scan_dependencies is tested end-to-end
with the host probes monkeypatched, so present/missing classification does not depend on whatever
dev libraries happen to be installed on the machine running the suite.
"""
from pathlib import Path

from lykos.analyze import dep_preflight as DP

# ---- parsers (pure, deterministic) ----

def test_parse_cmake_find_package_and_pkg_modules():
    body = """
    cmake_minimum_required(VERSION 3.10)
    find_package(OpenSSL REQUIRED)          # a comment
    find_package(PkgConfig REQUIRED)        # must be ignored -- it is not a dependency
    find_package(ZLIB)
    pkg_check_modules(DEPS REQUIRED glib-2.0 >= 2.40 gio-2.0)
    find_library(M_LIB NAMES m REQUIRED)
    check_include_file("sys/epoll.h" HAVE_EPOLL)
    """
    out = DP._parse_cmake(body)
    kinds = {(k, n) for k, n, _ in out}
    assert ("cmake-package", "OpenSSL") in kinds
    assert ("cmake-package", "ZLIB") in kinds
    assert not any(n.lower() == "pkgconfig" for _, n in kinds)      # PkgConfig dropped
    assert ("pkg-config", "glib-2.0") in kinds and ("pkg-config", "gio-2.0") in kinds
    assert not any(n == "2.40" for _, n in kinds)                   # version is not a module
    assert ("library", "m") in kinds
    assert ("header", "sys/epoll.h") in kinds


def test_parse_autotools_lib_header_and_pkg():
    body = """
    AC_CHECK_LIB([ssl], [SSL_new])
    AC_CHECK_LIB(z, deflate)
    AC_CHECK_HEADERS([openssl/ssl.h zlib.h unistd.h])
    PKG_CHECK_MODULES([LIBXML], [libxml-2.0 >= 2.9])
    """
    out = DP._parse_autotools(body)
    s = {(k, n) for k, n, _ in out}
    assert ("library", "ssl") in s and ("library", "z") in s
    assert ("header", "openssl/ssl.h") in s and ("header", "zlib.h") in s
    assert ("pkg-config", "libxml-2.0") in s
    assert not any(n == "2.9" for _, n in s)


def test_parse_pc_requires():
    out = DP._parse_pc("Name: foo\nRequires: glib-2.0 >= 2.0\nRequires.private: zlib libssl\n")
    s = {n for _, n, _ in out}
    assert "glib-2.0" in s and "zlib" in s and "libssl" in s


def test_include_scan_only_flags_known_library_headers(tmp_path):
    (tmp_path / "a.c").write_text(
        '#include <stdio.h>\n#include <openssl/ssl.h>\n#include "local.h"\n'
        '#include <my_internal/config.h>\n')
    # a vendored copy must be ignored -- its includes are not the project's own deps
    ven = tmp_path / "third_party"
    ven.mkdir()
    (ven / "x.c").write_text("#include <png.h>\n")
    out = DP._scan_includes(tmp_path)
    names = {n for _, n, _ in out}
    assert names == {"openssl/ssl.h"}                               # stdlib/internal/vendored dropped


# ---- end-to-end, with host probes stubbed ----

def _cmake_project(tmp_path: Path) -> Path:
    (tmp_path / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.10)\n"
        "find_package(OpenSSL REQUIRED)\n"
        "find_package(ZLIB REQUIRED)\n"
        "pkg_check_modules(X REQUIRED libxml-2.0)\n")
    (tmp_path / "main.c").write_text("#include <curl/curl.h>\nint main(){return 0;}\n")
    return tmp_path


def test_scan_classifies_present_missing_and_unknown(tmp_path, monkeypatch):
    root = _cmake_project(tmp_path)
    # Stub the host: openssl + curl header present, zlib header absent, libxml pkg-config absent,
    # and an UNMAPPED find_package would be unknown (not exercised here; all three are mapped).
    present_headers = {"openssl/ssl.h", "curl/curl.h"}
    monkeypatch.setattr(DP, "_header_present", lambda h: h in present_headers)
    monkeypatch.setattr(DP, "_pkgconfig_present", lambda m: False)
    monkeypatch.setattr(DP, "_library_present", lambda n: True)

    pf = DP.scan_dependencies(root)
    assert pf["schema"] == DP.SCHEMA and pf["build_system"] == "cmake"
    by_name = {r["name"]: r for r in pf["requirements"]}
    assert by_name["OpenSSL"]["present"] is True                    # find_package -> header ok
    assert by_name["ZLIB"]["present"] is False                      # find_package -> header absent
    assert by_name["libxml-2.0"]["present"] is False                # pkg-config says no
    assert by_name["curl/curl.h"]["present"] is True                # include scan, header present
    miss = {r["name"] for r in pf["missing"]}
    assert "ZLIB" in miss and "libxml-2.0" in miss and "OpenSSL" not in miss


def test_unmapped_cmake_package_is_unknown_not_missing(tmp_path, monkeypatch):
    (tmp_path / "CMakeLists.txt").write_text("find_package(SomeExoticLib REQUIRED)\n")
    monkeypatch.setattr(DP, "_header_present", lambda h: False)
    monkeypatch.setattr(DP, "_pkgconfig_present", lambda m: None)
    pf = DP.scan_dependencies(root=tmp_path, scan_includes=False)
    r = next(r for r in pf["requirements"] if r["name"] == "SomeExoticLib")
    assert r["present"] is None                                     # never a false "missing"
    assert r in pf["unknown"] and r not in pf["missing"]


def test_missing_tokens_includes_hint_and_toolchain(tmp_path, monkeypatch):
    root = _cmake_project(tmp_path)
    monkeypatch.setattr(DP, "_header_present", lambda h: False)
    monkeypatch.setattr(DP, "_pkgconfig_present", lambda m: False)
    monkeypatch.setattr(DP, "_library_present", lambda n: False)
    monkeypatch.setattr(DP.shutil, "which", lambda name: None)      # no cmake/make either
    monkeypatch.setattr(DP, "_cc", lambda: None)
    monkeypatch.setattr(DP, "_have_pkgconfig", lambda: False)
    pf = DP.scan_dependencies(root)
    toks = DP.missing_tokens(pf)
    assert any("ZLIB (zlib1g-dev)" == t for t in toks)              # hint attached
    assert "cmake" in toks and "cc" in toks                         # missing build tools listed


def test_format_report_is_actionable(tmp_path, monkeypatch):
    root = _cmake_project(tmp_path)
    monkeypatch.setattr(DP, "_header_present", lambda h: h == "openssl/ssl.h")
    monkeypatch.setattr(DP, "_pkgconfig_present", lambda m: False)
    monkeypatch.setattr(DP, "_library_present", lambda n: True)
    txt = DP.format_report(DP.scan_dependencies(root))
    assert "pre-flight" in txt and "MISSING" in txt
    assert "libxml2-dev" in txt or "zlib1g-dev" in txt              # a package hint appears


def test_build_system_detection(tmp_path):
    assert DP._detect_build_system(tmp_path) == "plain"
    (tmp_path / "configure").write_text("#!/bin/sh\n")
    assert DP._detect_build_system(tmp_path) == "autotools"
    (tmp_path / "CMakeLists.txt").write_text("")
    assert DP._detect_build_system(tmp_path) == "cmake"             # cmake wins when both present
