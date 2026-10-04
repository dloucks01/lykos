"""CVE-depth additions (2026-10): three verified binary version banners (gnutls/xz/bzip2), four
more source-manifest ecosystems (Maven/Composer/RubyGems/Pub), and two more format-level
weaponization triggers (libtiff/libwebp). The banner regexes and manifest parsers are detection
logic (no hand-entered CVE version ranges — those come from the OSV feed); the triggers are
input generators the cve_poc stage records only on a real fault."""
import glob
import shutil
import subprocess

import pytest
from lykos.analyze.fingerprint import scan, source_scan
from lykos.analyze.poc import cve_triggers as T

_GCC = shutil.which("gcc") or shutil.which("cc")
_LIBWEBP = next(iter(glob.glob("/usr/lib/*/libwebp.so.7") + glob.glob("/usr/lib/libwebp.so.7")), None)


# A realistic naive WebP consumer: it reads the image dimensions from the REAL libwebp, then renders
# into a buffer sized for an assumed 1024x1024 maximum WITHOUT re-checking the declared dimensions --
# the "no dimension cap" bug (CWE-787) the libwebp trigger targets. Linked by soname (no dev header).
_WEBP_CONSUMER = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern int WebPGetInfo(const unsigned char*, unsigned long, int*, int*);
#define CAP 1024
int main(void){
    static unsigned char in[1<<20];
    size_t n = fread(in, 1, sizeof in, stdin);
    int w=0, h=0;
    if (!WebPGetInfo(in, (unsigned long)n, &w, &h)) return 0;
    unsigned char *canvas = malloc((size_t)CAP*CAP*4);
    if (!canvas) return 0;
    memset(canvas, 0x41, (size_t)w*(size_t)h*4);   /* heap overflow when the declared image > CAP */
    free(canvas);
    return 0;
}
'''


@pytest.mark.skipif(not (_GCC and _LIBWEBP), reason="needs gcc + libwebp.so.7 for the live demo")
def test_webp_trigger_faults_a_real_libwebp_consumer(tmp_path):
    """DEMONSTRATED EFFECT: the libwebp trigger, fed to a naive consumer that renders at the REAL
    libwebp's reported dimensions, causes an actual AddressSanitizer memory error; a benign image
    does not. Proves the trigger is a real weapon against real library code, not just well-formed
    bytes. (The cve_poc stage records a fault only on exactly this kind of real crash.)"""
    src = tmp_path / "c.c"; src.write_text(_WEBP_CONSUMER)
    exe = tmp_path / "c"
    build = subprocess.run([_GCC, "-fsanitize=address", "-g", "-O0", str(src), "-o", str(exe),
                            "-l:libwebp.so.7"], capture_output=True)
    if build.returncode:
        pytest.skip("cannot build/link the libwebp consumer: " + build.stderr.decode()[:120])
    trig = T._webp_oversized_dims().data
    r = subprocess.run([str(exe)], input=trig, capture_output=True, timeout=30)
    assert b"AddressSanitizer" in r.stderr and b"overflow" in r.stderr, \
        "the trigger did not fault the real-libwebp consumer"
    # negative control: a benign 8x8 lossless WebP must NOT fault
    import struct
    dims = (7 | (7 << 14)) & 0xFFFFFFFF
    vp8l = b"\x2f" + struct.pack("<I", dims) + b"\x00" * 8
    benign = b"RIFF" + struct.pack("<I", 4 + 8 + len(vp8l)) + b"WEBP" + b"VP8L" + \
        struct.pack("<I", len(vp8l)) + vp8l
    rc = subprocess.run([str(exe)], input=benign, capture_output=True, timeout=30)
    assert b"AddressSanitizer" not in rc.stderr, "benign 8x8 WebP must not fault (negative control)"


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
    assert any("libtiff" in lbl for lbl in labels)


def test_webp_trigger_is_valid_riff_and_in_plan():
    import struct
    t = T._webp_oversized_dims()
    assert t.data[:4] == b"RIFF" and t.data[8:12] == b"WEBP" and b"VP8L" in t.data
    # the VP8L dims must actually decode to the maxed 14-bit values (16384 x 16384) -- a real
    # libwebp reads width-1/height-1 from here, and an earlier packing bug truncated the height.
    vp8l = t.data[t.data.index(b"VP8L") + 8:]
    assert vp8l[0] == 0x2F                                  # VP8L signature byte
    dims = struct.unpack_from("<I", vp8l, 1)[0]
    assert (dims & 0x3FFF) + 1 == 16384                     # width
    assert ((dims >> 14) & 0x3FFF) + 1 == 16384             # height (the previously-truncated field)
    labels = [p.label for p in T.weaponization_plan([("CVE-y", "libwebp", "CWE-787")])]
    assert any("libwebp" in lbl for lbl in labels)
