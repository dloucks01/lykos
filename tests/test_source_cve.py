"""Source-side CVE detection: parsing dependency manifests and vendored headers.

A source project declares its dependency versions in files that never survive into the compiled
binary, so this parser is the only channel that sees them. Each parser must pull the right
(library-key, version) -- the key has to match the offline DB's keying ("<ecosystem>:<name>" for
manifests, a bare library name for a vendored C header) or the match silently finds nothing.
"""
from __future__ import annotations

from pathlib import Path

from lykos.analyze.fingerprint import source_scan


def _tree(tmp_path, files: dict) -> Path:
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp_path


def _by_lib(detected):
    return {d["library"]: d["version"] for d in detected}


def test_requirements_txt_takes_only_exact_pins(tmp_path):
    """A `>=`/`~=` spec is a range, not a version we can match a CVE against; only `==` pins do."""
    root = _tree(tmp_path, {"requirements.txt":
                            "Jinja2==2.10\nflask>=1.0\nrequests==2.19.1\n# a comment\n"})
    got = _by_lib(source_scan.parse_source_tree(root))
    assert got.get("pypi:jinja2") == "2.10"
    assert got.get("pypi:requests") == "2.19.1"
    assert "pypi:flask" not in got                 # unpinned range -> skipped


def test_requirements_name_is_normalised(tmp_path):
    """PyPI treats '-', '_' and '.' as equivalent; the key must normalise so it hits the DB."""
    root = _tree(tmp_path, {"requirements.txt": "Foo_Bar.Baz==1.0.0\n"})
    assert "pypi:foo-bar-baz" in _by_lib(source_scan.parse_source_tree(root))


def test_go_mod_require_block_and_single_line(tmp_path):
    root = _tree(tmp_path, {"go.mod":
                            "module example.com/app\n\n"
                            "require (\n\tgolang.org/x/text v0.3.0\n\tgolang.org/x/net v0.1.0\n)\n"
                            "require golang.org/x/crypto v0.17.0\n"})
    got = _by_lib(source_scan.parse_source_tree(root))
    assert got.get("go:golang.org/x/text") == "0.3.0"
    assert got.get("go:golang.org/x/net") == "0.1.0"
    assert got.get("go:golang.org/x/crypto") == "0.17.0"


def test_package_lock_v3_exact_versions(tmp_path):
    root = _tree(tmp_path, {"package-lock.json": """
    {"name":"app","lockfileVersion":3,"packages":{
       "":{"name":"app"},
       "node_modules/lodash":{"version":"4.17.4"},
       "node_modules/minimist":{"version":"1.2.0"}}}"""})
    got = _by_lib(source_scan.parse_source_tree(root))
    assert got.get("npm:lodash") == "4.17.4"
    assert got.get("npm:minimist") == "1.2.0"


def test_package_json_strips_range_operator(tmp_path):
    root = _tree(tmp_path, {"package.json":
                            '{"dependencies":{"lodash":"^4.17.4"},'
                            '"devDependencies":{"minimist":"~1.2.0"}}'})
    got = _by_lib(source_scan.parse_source_tree(root))
    assert got.get("npm:lodash") == "4.17.4"
    assert got.get("npm:minimist") == "1.2.0"


def test_cargo_lock_packages(tmp_path):
    root = _tree(tmp_path, {"Cargo.lock":
                            '[[package]]\nname = "time"\nversion = "0.2.23"\n\n'
                            '[[package]]\nname = "openssl"\nversion = "0.10.0"\n'})
    got = _by_lib(source_scan.parse_source_tree(root))
    assert got.get("crates:time") == "0.2.23"
    assert got.get("crates:openssl") == "0.10.0"


def test_vendored_zlib_header_version(tmp_path):
    """A vendored zlib keyed as the bare 'zlib' so it hits the curated C-library DB, not an
    'ecosystem:name' key."""
    root = _tree(tmp_path, {"third_party/zlib/zlib.h":
                            '/* header */\n#define ZLIB_VERSION "1.2.11"\n#define ZLIB_VERNUM 0x12b0\n'})
    got = _by_lib(source_scan.parse_source_tree(root))
    assert got.get("zlib") == "1.2.11"


def test_vendored_openssl_header_version(tmp_path):
    root = _tree(tmp_path, {"deps/openssl/opensslv.h":
                            '#define OPENSSL_VERSION_TEXT "OpenSSL 1.0.1 14 Mar 2012"\n'})
    assert _by_lib(source_scan.parse_source_tree(root)).get("openssl") == "1.0.1"


def test_vendored_freertos_kernel_version(tmp_path):
    """FreeRTOS keyed off the kernel version #define; the trailing '+' (dev build) is stripped."""
    root = _tree(tmp_path, {"kernel/include/task.h":
                            '#define tskKERNEL_VERSION_NUMBER   "V11.1.0+"\n'})
    assert _by_lib(source_scan.parse_source_tree(root)).get("freertos") == "11.1.0"


def test_lwip_version_from_separate_major_minor_revision_macros(tmp_path):
    """lwIP spells its version as three numeric #defines in lwip/init.h, not one string."""
    root = _tree(tmp_path, {"lwip/src/include/lwip/init.h":
                            "#define LWIP_VERSION_MAJOR 2\n#define LWIP_VERSION_MINOR 1\n"
                            "#define LWIP_VERSION_REVISION 3\n"})
    assert _by_lib(source_scan.parse_source_tree(root)).get("lwip") == "2.1.3"


def test_header_macros_disambiguate_a_generic_version_h(tmp_path):
    """mbedTLS and wolfSSL both ship a file called version.h; detection keys off the MACRO it
    contains, not the filename, so each resolves to the right library."""
    root = _tree(tmp_path, {
        "a/mbedtls/version.h": '#define MBEDTLS_VERSION_STRING "2.16.0"\n',
        "b/wolfssl/version.h": '#define LIBWOLFSSL_VERSION_STRING "4.0.0"\n'})
    got = _by_lib(source_scan.parse_source_tree(root))
    assert got.get("mbedtls") == "2.16.0"
    assert got.get("wolfssl") == "4.0.0"


def test_a_malformed_manifest_is_skipped_not_fatal(tmp_path):
    root = _tree(tmp_path, {"package-lock.json": "{not valid json",
                            "requirements.txt": "Jinja2==2.10\n"})
    # the broken lockfile must not take the whole parse down
    assert _by_lib(source_scan.parse_source_tree(root)).get("pypi:jinja2") == "2.10"


def test_an_empty_tree_detects_nothing(tmp_path):
    assert source_scan.parse_source_tree(tmp_path) == []


# ---- exploit-class hinting ---------------------------------------------------------------

def test_exploit_hint_maps_memory_corruption_to_a_strategy():
    from lykos.analyze.fingerprint import db
    assert db.exploit_hint("CWE-787")[1] == "rop"
    assert db.exploit_hint("CWE-416")[1] == "heap"
    assert db.exploit_hint("CWE-134")[1] == "format"


def test_exploit_hint_is_none_for_a_non_memory_class_and_unmapped():
    from lykos.analyze.fingerprint import db
    assert db.exploit_hint("CWE-78")[1] is None        # command injection: no binary strategy
    assert db.exploit_hint("CWE-9999") is None          # unmapped


def test_exploit_evidence_carries_the_honest_caveat():
    from lykos.analyze.fingerprint import scan
    ev = scan.exploit_evidence("CWE-121")
    assert ev and ev[0]["channel"] == "exploit"
    # it must NEVER claim a PoC exists -- only that a reproducer is still needed
    assert "still required" in ev[0]["detail"]
    assert scan.exploit_evidence("CWE-9999") == []


def test_libwebp_abi_version_maps_to_a_release_and_matches_its_cve(tmp_path):
    """libwebp exposes only WEBP_DECODER_ABI_VERSION, no dotted release -- doc 30 P4.3. The ABI
    number maps (operator-extensible table) to the earliest release carrying it, so a CVE range
    check fires across the window the ABI covers. 0x0209 -> ~1.3.0, which CVE-2023-4863 (< 1.3.2)
    hits; the match is flagged ABI-approximate."""
    from lykos.analyze.fingerprint import scan
    root = _tree(tmp_path, {"src/webp/decode.h":
                            "#ifndef WEBP_DECODE_H\n#define WEBP_DECODER_ABI_VERSION 0x0209\n#endif\n"})
    hits = {h["library"]: h for h in source_scan.parse_source_tree(root)}
    assert "libwebp" in hits
    assert hits["libwebp"]["version"] == "1.3.0"
    assert "ABI-approximate" in hits["libwebp"]["evidence"]
    matched = {m.get("cve") or m.get("id") for m in scan.match(
        [{"library": "libwebp", "name": "libwebp", "version": hits["libwebp"]["version"],
          "evidence": hits["libwebp"]["evidence"]}])}
    assert "CVE-2023-4863" in matched
    # the fixed release (same ABI, so still 1.3.0-approximate) is why the flag says "verify": a
    # true 1.3.2 is clear, and the curated range excludes it.
    assert not scan.match([{"library": "libwebp", "name": "libwebp", "version": "1.3.2"}])
