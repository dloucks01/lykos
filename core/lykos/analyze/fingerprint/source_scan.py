"""Source-side CVE detection: find vulnerable dependency versions in an uploaded SOURCE project.

The binary-side scan (`scan.scan`) reads version BANNERS out of a compiled artifact. A source
project states its dependency versions directly -- in a package manifest (requirements.txt,
package-lock.json, go.mod, Cargo.lock) or a vendored library header (zlib.h's ZLIB_VERSION,
openssl's opensslv.h). Those versions never survive into a stripped/optimised binary, so this is
the only channel that sees them. Each parsed (library, version) is fed to the SAME matcher
(`scan.match`) and the SAME offline DB the binary path uses, so the ecosystem CVE index and the
reference pack apply identically.

Pure parsing, no execution, stdlib based. A malformed manifest is skipped, never fatal.
"""
from __future__ import annotations

import io
import logging
import re
import tarfile
from pathlib import Path

from ...db.dao import ArtifactDAO, FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from . import scan

_log = logging.getLogger(__name__)

SOURCE_CVE_STAGE = "source_cve_scan"
TOOL = "cve-source"
TOOL_VERSION = "cve-source-1"

_MAX_FILES = 4000
_MAX_FILE = 4 << 20

# Vendored C/C++ library headers carry the library's own version in a distinctive #define. We
# scan the CONTENT of header files (not filenames) for these macros, so a generic name like
# version.h disambiguates by which macro it holds (mbedtls vs wolfssl both ship a version.h).
# The library key matches the DB (bare name -> curated/NVD C-lib ranges).
_HEADER_MACROS = [
    ("zlib", re.compile(r'#\s*define\s+ZLIB_VERSION\s+"(\d+\.\d+\.\d+)')),
    ("openssl", re.compile(r'OPENSSL_VERSION_TEXT\s+"OpenSSL\s+(\d+\.\d+\.\d+[a-z]*)')),
    ("freertos", re.compile(r'#\s*define\s+tskKERNEL_VERSION_NUMBER\s+"V?(\d+\.\d+\.\d+)')),
    ("mbedtls", re.compile(r'#\s*define\s+MBEDTLS_VERSION_STRING\s+"(\d+\.\d+\.\d+)')),
    ("wolfssl", re.compile(r'#\s*define\s+LIBWOLFSSL_VERSION_STRING\s+"(\d+\.\d+\.\d+)')),
    ("lwip", re.compile(r'#\s*define\s+LWIP_VERSION_STRING\s+"(\d+\.\d+\.\d+)')),
    ("libxml2", re.compile(r'#\s*define\s+LIBXML_DOTTED_VERSION\s+"(\d+\.\d+\.\d+)')),
    ("mongoose", re.compile(r'#\s*define\s+MG_VERSION\s+"(\d+\.\d+)')),
    ("libjpeg-turbo", re.compile(r'#\s*define\s+LIBJPEG_TURBO_VERSION\s+"?(\d+\.\d+\.\d+)')),
]
# Some libraries spell the version as SEPARATE numeric #defines rather than one string. lwIP's
# lwip/init.h is the common case: MAJOR/MINOR/REVISION. Combine them into X.Y.Z.
_COMBINED_MACROS = [
    ("lwip", (re.compile(r'#\s*define\s+LWIP_VERSION_MAJOR\s+\(?(\d+)'),
              re.compile(r'#\s*define\s+LWIP_VERSION_MINOR\s+\(?(\d+)'),
              re.compile(r'#\s*define\s+LWIP_VERSION_REVISION\s+\(?(\d+)'))),
    # FreeType's freetype.h: FREETYPE_MAJOR/MINOR/PATCH.
    ("freetype", (re.compile(r'#\s*define\s+FREETYPE_MAJOR\s+(\d+)'),
                  re.compile(r'#\s*define\s+FREETYPE_MINOR\s+(\d+)'),
                  re.compile(r'#\s*define\s+FREETYPE_PATCH\s+(\d+)'))),
    # PCRE2's pcre2.h: PCRE2_MAJOR/MINOR (two-part version, PATCH synthesised as 0).
    ("pcre2", (re.compile(r'#\s*define\s+PCRE2_MAJOR\s+(\d+)'),
               re.compile(r'#\s*define\s+PCRE2_MINOR\s+(\d+)'),
               re.compile(r'(?:\A|\Z)()'))),  # no patch component -> 0
]
# Some libraries expose ONLY an ABI/version constant, never a dotted release string -- libwebp's
# decode.h has `#define WEBP_DECODER_ABI_VERSION 0x0209` and nothing else. The ABI number is stable
# across patch releases, so it maps to a release RANGE, not a point: this table gives the EARLIEST
# release carrying each ABI, so a CVE range check (`lt X`) fires conservatively across the window
# the ABI covers. It is intentionally operator-extensible -- add a library + its {abi: release}
# column as new ABIs land. A match is flagged approximate (the exact patch needs another signal).
_ABI_MACROS = [
    ("libwebp", re.compile(r'#\s*define\s+WEBP_DECODER_ABI_VERSION\s+0x([0-9a-fA-F]+)'),
     {0x0209: "1.3.0", 0x0208: "1.2.0", 0x0207: "1.1.0", 0x0200: "0.2.0"}),
]
_HEADER_SUFFIXES = (".h", ".hpp", ".hh", ".hxx", ".in")
# requirements.txt line: name[extras] ==|=== exact-version  (only exact pins give a version)
_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*"
                  r"([0-9][0-9A-Za-z.\-]*)", re.M)
# go.mod require line: module vX.Y.Z   (single line or inside a require(...) block)
_GOMOD = re.compile(r"^\s*(?:require\s+)?([a-zA-Z0-9./_-]+\.[a-zA-Z0-9./_-]+)\s+v"
                    r"([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.\-+]*)", re.M)


def _norm_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_requirements(text: str) -> list:
    out = []
    for m in _REQ.finditer(text):
        out.append(("pypi:" + _norm_pypi(m.group(1)), m.group(1), m.group(2)))
    return out


def _parse_package_lock(text: str) -> list:
    import json
    out = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    # v2/v3: {"packages": {"node_modules/<name>": {"version": ...}}}
    for path, meta in (data.get("packages") or {}).items():
        if not path or not isinstance(meta, dict) or "version" not in meta:
            continue
        name = path.split("node_modules/")[-1]
        if name:
            out.append(("npm:" + name.lower(), name, str(meta["version"])))
    # v1: {"dependencies": {"<name>": {"version": ...}}}
    for name, meta in (data.get("dependencies") or {}).items():
        if isinstance(meta, dict) and "version" in meta:
            out.append(("npm:" + name.lower(), name, str(meta["version"])))
    return out


def _parse_package_json(text: str) -> list:
    import json
    out = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            # strip a leading range operator to a concrete-ish version (best effort; a lockfile,
            # parsed above, is preferred and will dedupe-win on the same package).
            m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.\-]*)", str(spec))
            if m:
                out.append(("npm:" + name.lower(), name, m.group(1)))
    return out


def _parse_go_mod(text: str) -> list:
    return [("go:" + mod.lower(), mod, ver) for mod, ver in _GOMOD.findall(text)]


def _parse_cargo_lock(text: str) -> list:
    out = []
    try:
        import tomllib
        data = tomllib.loads(text)
    except Exception:
        return out
    for pkg in data.get("package", []):
        if isinstance(pkg, dict) and pkg.get("name") and pkg.get("version"):
            out.append(("crates:" + str(pkg["name"]).lower(), pkg["name"], str(pkg["version"])))
    return out


_DEP_RE = re.compile(
    r"<dependency>(.*?)</dependency>", re.DOTALL | re.IGNORECASE)
_MVN_G = re.compile(r"<groupId>\s*([^<$][^<]*?)\s*</groupId>", re.IGNORECASE)
_MVN_A = re.compile(r"<artifactId>\s*([^<$][^<]*?)\s*</artifactId>", re.IGNORECASE)
_MVN_V = re.compile(r"<version>\s*([0-9][0-9A-Za-z.\-]*)\s*</version>", re.IGNORECASE)


def _parse_pom(text: str) -> list:
    """Maven pom.xml <dependency> blocks -> OSV 'Maven' coordinates 'groupId:artifactId'. Only
    concrete versions are taken; a `${property}` version has no literal to match and is skipped."""
    out = []
    for block in _DEP_RE.findall(text):
        g, a, v = _MVN_G.search(block), _MVN_A.search(block), _MVN_V.search(block)
        if g and a and v:
            coord = f"{g.group(1)}:{a.group(1)}"
            out.append(("maven:" + coord.lower(), coord, v.group(1)))
    return out


def _parse_composer_lock(text: str) -> list:
    """Composer composer.lock -> OSV 'Packagist' packages 'vendor/name'. Both the runtime and dev
    package arrays are read; a leading 'v' on the version (v1.2.3) is normalised off."""
    import json
    out = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    for section in ("packages", "packages-dev"):
        for pkg in (data.get(section) or []):
            if isinstance(pkg, dict) and pkg.get("name") and pkg.get("version"):
                ver = re.sub(r"^v", "", str(pkg["version"]))
                out.append(("packagist:" + str(pkg["name"]).lower(), pkg["name"], ver))
    return out


_GEMSPEC = re.compile(r"^    ([A-Za-z0-9_.\-]+) \(([0-9][0-9A-Za-z.\-]*)\)\s*$")


def _parse_gemfile_lock(text: str) -> list:
    """Gemfile.lock -> OSV 'RubyGems' gems. Only the resolved `specs:` entries (indented four
    spaces with a parenthesised version) are taken, not the looser nested dependency lines."""
    out, in_specs = [], False
    for line in text.splitlines():
        if re.match(r"^\s{2}specs:\s*$", line):
            in_specs = True
            continue
        if in_specs and line and not line.startswith(" "):
            in_specs = False
        if in_specs:
            m = _GEMSPEC.match(line)
            if m:
                out.append(("rubygems:" + m.group(1).lower(), m.group(1), m.group(2)))
    return out


_PUB_PKG = re.compile(r'^  ([A-Za-z0-9_]+):\s*$')
_PUB_VER = re.compile(r'^    version:\s*"?([0-9][0-9A-Za-z.+\-]*)"?\s*$')


def _parse_pubspec_lock(text: str) -> list:
    """Dart/Flutter pubspec.lock -> OSV 'Pub' packages. Parsed as indentation-scoped key/value
    (no stdlib YAML): a 2-space package name under `packages:` followed by its 4-space `version:`."""
    out, cur = [], None
    for line in text.splitlines():
        pm = _PUB_PKG.match(line)
        if pm:
            cur = pm.group(1)
            continue
        if cur:
            vm = _PUB_VER.match(line)
            if vm:
                out.append(("pub:" + cur.lower(), cur, vm.group(1)))
                cur = None
    return out


_MANIFEST_PARSERS = {
    "requirements.txt": _parse_requirements,
    "package-lock.json": _parse_package_lock,
    "package.json": _parse_package_json,
    "go.mod": _parse_go_mod,
    "Cargo.lock": _parse_cargo_lock,
    "pom.xml": _parse_pom,
    "composer.lock": _parse_composer_lock,
    "Gemfile.lock": _parse_gemfile_lock,
    "pubspec.lock": _parse_pubspec_lock,
}


def parse_source_tree(root: Path) -> list:
    """Every (library-key, display-name, version) found across the source tree's dependency
    manifests and vendored library headers. Deduped; a lockfile/header wins over a loose spec."""
    found: dict = {}        # (libkey, version) -> {library, name, version, evidence}
    seen_files = 0
    for p in sorted(root.rglob("*")):
        if seen_files >= _MAX_FILES:
            break
        if not p.is_file():
            continue
        try:
            if p.stat().st_size > _MAX_FILE:
                continue
        except OSError:
            continue
        seen_files += 1
        base = p.name
        parser = _MANIFEST_PARSERS.get(base)
        hits = []
        if parser:
            try:
                hits = [(lk, nm, ver, f"{base}: {nm} {ver}")
                        for lk, nm, ver in parser(p.read_text("utf-8", "replace"))]
            except Exception:
                _log.debug("manifest parse failed for %s", p, exc_info=True)
                hits = []
        elif p.suffix.lower() in _HEADER_SUFFIXES:
            # scan the header's CONTENT for any known library version macro (filename-agnostic)
            try:
                text = p.read_text("utf-8", "replace")
            except Exception:
                text = ""
            for lib, rx in _HEADER_MACROS:
                m = rx.search(text)
                if m:
                    hits.append((lib, lib, m.group(1), f"{base}: {lib} {m.group(1)}"))
            for lib, (rmaj, rmin, rrev) in _COMBINED_MACROS:
                a, b, c = rmaj.search(text), rmin.search(text), rrev.search(text)
                if a and b and c:
                    ver = f"{a.group(1)}.{b.group(1)}.{c.group(1) or '0'}"
                    hits.append((lib, lib, ver, f"{base}: {lib} {ver} (MAJOR/MINOR/REVISION)"))
            for lib, rx, abimap in _ABI_MACROS:
                m = rx.search(text)
                if not m:
                    continue
                ver = abimap.get(int(m.group(1), 16))
                if ver:                                   # ABI maps to the earliest release with it
                    hits.append((lib, lib, ver, f"{base}: {lib} ABI 0x{m.group(1)} "
                                                f"-> ~{ver} (ABI-approximate; verify exact patch)"))
        for lk, nm, ver, ev in hits:
            found.setdefault((lk, ver), {"library": lk, "name": nm, "version": ver,
                                         "evidence": ev})
    return list(found.values())


def source_cve_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("source_cve_scan requires a target_id")
    # Recover the archived source tree for this target (built-from-source projects only).
    arts = ArtifactDAO(ctx.conn).list_by_case(target.case_id)
    proj = next((a for a in arts if a.kind == "source-project"
                 and (a.meta or {}).get("binary_sha") == target.sha256), None)
    if proj is None:
        ctx.emit("source_cve.done", payload={"applicable": False,
                 "note": "no archived source tree (target was not built from a source project)"})
        return {}
    root = ctx.scratch() / "srccve"
    root.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),
                          mode="r:gz") as tf:
            for m in tf.getmembers():
                if m.isfile() and not m.name.startswith("/") and ".." not in m.name:
                    tf.extract(m, root)
    except Exception:
        ctx.emit("source_cve.done", payload={"applicable": False,
                 "note": "could not unpack the archived source tree"})
        return {}

    ctx.progress(msg="parsing dependency manifests and vendored headers")
    detected = parse_source_tree(root)
    matches = scan.match(detected)

    fd = FindingDAO(ctx.conn)
    for m in matches:
        disp = m["library"].split(":", 1)[-1]
        label = f"{disp} {m['version']} — {m['cve']}"
        cvss = f", CVSS {m['cvss']}" if m.get("cvss") else ""
        fd.upsert(target.id, target.case_id, {
            "cwe": m["cwe"], "severity": m["severity"], "detector": "cve_source",
            "title": f"Vulnerable dependency: {label}",
            "evidence": [
                {"channel": "manifest", "detail": f"declared in source: {m['evidence']}"},
                {"channel": "cve", "detail": f"{m['cve']}{cvss}: {m['summary']}"}]
                + scan.exploit_evidence(m["cwe"]),
            "function_addr": None, "site_addr": None,
            "dedup_key": f"{m['cve']}:{m['library']}:{m['version']}",
            "state": "corroborated", "confidence": 0.85})

    ctx.emit("source_cve.done", payload={
        "applicable": True,
        "components": [{"library": d["library"], "version": d["version"]} for d in detected],
        "cves": [{"cve": m["cve"], "library": m["library"], "version": m["version"],
                  "severity": m["severity"]} for m in matches],
        "findings": len(matches),
        "note": None if detected else "no dependency manifests or vendored headers found"})
    ctx.progress(pct=100, msg=f"{len(detected)} declared component(s), {len(matches)} CVE finding(s)")
    return {}


def register() -> None:
    register_stage(SOURCE_CVE_STAGE, source_cve_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_source_cve_scan(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, SOURCE_CVE_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="quick", force=force)
