"""CVE-depth additions (2026-10): three verified binary version banners (gnutls/xz/bzip2), four
more source-manifest ecosystems (Maven/Composer/RubyGems/Pub), and two more format-level
weaponization triggers (libtiff/libwebp). The banner regexes and manifest parsers are detection
logic (no hand-entered CVE version ranges — those come from the OSV feed); the triggers are
input generators the cve_poc stage records only on a real fault."""
from lykos.analyze.fingerprint import scan, source_scan
from lykos.analyze.poc import cve_triggers as T


# ------------------------------------------------------------------- D1: binary banners
def test_new_banners_detect_component_and_version():
    blob = (b"junk\x00Enabled GnuTLS 3.8.13 logging...\x00"
            b"xz (XZ Utils) 5.6.0\x00"
            b"BZ2 version string: 1.0.8, 13-Jul-2019\x00")
    detected, _ = scan.scan_and_match(blob)
    got = {d["library"]: d["version"] for d in detected}
    assert got.get("gnutls") == "3.8.13"
    assert got.get("xz") == "5.6.0"
    assert got.get("bzip2") == "1.0.8"


def test_bzip2_banner_needs_the_date_anchor():
    # a plain "1.2.3" with no ", DD-Mon-YYYY" tail must NOT be read as bzip2 (that anchor is the
    # whole point of the low-FP pattern)
    detected, _ = scan.scan_and_match(b"some lib 1.2.3 here\x00")
    assert "bzip2" not in {d["library"] for d in detected}


# ------------------------------------------------------------------- D3: source manifests
def test_parse_pom_maven_coordinates():
    pom = ("<project><dependencies>"
           "<dependency><groupId>org.apache.logging.log4j</groupId>"
           "<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>"
           "<dependency><groupId>com.x</groupId><artifactId>y</artifactId>"
           "<version>${y.ver}</version></dependency>"
           "</dependencies></project>")
    out = source_scan._parse_pom(pom)
    assert ("maven:org.apache.logging.log4j:log4j-core",
            "org.apache.logging.log4j:log4j-core", "2.14.1") in out
    assert all("${" not in nm and v != "${y.ver}" for _, nm, v in out)   # property version skipped


def test_parse_composer_lock_runtime_and_dev():
    data = ('{"packages":[{"name":"symfony/http-kernel","version":"v4.4.1"}],'
            '"packages-dev":[{"name":"phpunit/phpunit","version":"9.5.0"}]}')
    out = source_scan._parse_composer_lock(data)
    assert ("packagist:symfony/http-kernel", "symfony/http-kernel", "4.4.1") in out   # 'v' stripped
    assert ("packagist:phpunit/phpunit", "phpunit/phpunit", "9.5.0") in out


def test_parse_gemfile_lock_specs_only():
    lock = ("GEM\n  remote: https://rubygems.org/\n  specs:\n"
            "    actionpack (6.1.4.1)\n    nokogiri (1.11.0)\n"
            "PLATFORMS\n  ruby\n")
    out = source_scan._parse_gemfile_lock(lock)
    assert ("rubygems:actionpack", "actionpack", "6.1.4.1") in out
    assert ("rubygems:nokogiri", "nokogiri", "1.11.0") in out
    assert all("remote" not in nm for _, nm, _ in out)


def test_parse_pubspec_lock_versions():
    lock = ('packages:\n  http:\n    dependency: "direct main"\n    version: "0.13.4"\n'
            '  path:\n    dependency: transitive\n    version: "1.8.0"\n'
            'sdks:\n  dart: ">=2.12.0"\n')
    out = source_scan._parse_pubspec_lock(lock)
    assert ("pub:http", "http", "0.13.4") in out
    assert ("pub:path", "path", "1.8.0") in out


def test_new_manifests_are_registered():
    for f in ("pom.xml", "composer.lock", "Gemfile.lock", "pubspec.lock"):
        assert f in source_scan._MANIFEST_PARSERS


def test_source_eco_keys_split_for_osv_query():
    # scan.match splits the libkey on the FIRST ':' into (eco, name); a Maven key must yield the
    # OSV ecosystem 'maven' and the 'group:artifact' coordinate intact.
    key = "maven:org.apache.logging.log4j:log4j-core"
    eco, name = key.split(":", 1)
    assert eco == "maven" and name == "org.apache.logging.log4j:log4j-core"


# ------------------------------------------------------------------- D2: weaponization triggers
def test_tiff_trigger_is_valid_container_and_in_plan():
    t = T._tiff_oversized_dims()
    assert t.data[:2] in (b"II", b"MM") and t.channel == "file" and t.cwe == "CWE-190"
    labels = [p.label for p in T.weaponization_plan([("CVE-x", "libtiff", "CWE-190")])]
    assert any("libtiff" in l for l in labels)


def test_webp_trigger_is_valid_riff_and_in_plan():
    t = T._webp_oversized_dims()
    assert t.data[:4] == b"RIFF" and t.data[8:12] == b"WEBP" and b"VP8L" in t.data
    labels = [p.label for p in T.weaponization_plan([("CVE-y", "libwebp", "CWE-787")])]
    assert any("libwebp" in l for l in labels)
