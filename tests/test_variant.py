"""Binary function matching, patch-diff and N-day variant hunting (bindiff)."""
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from lykos.analyze import variant as bindiff


def _fn(name, callees, mnems, blocks=3, size=64):
    """A native_re-shaped function dict with a synthetic P-Code mnemonic mix + callee list."""
    instrs = [{"pcode": [m + " reg:a:4 reg:b:4 -> reg:c:4"]} for m in mnems]
    return {"name": name, "size": size, "blocks": blocks, "edges": blocks - 1, "addr": "0x1000",
            "cfg": {"blocks": [{"addr": "0x1000", "succ": [], "instructions": instrs}]},
            "calls": [{"dst_name": c} for c in callees]}


def test_identical_functions_are_maximally_similar():
    a = bindiff.function_features(_fn("parse", ["malloc", "memcpy"], ["INT_ADD", "LOAD", "STORE"]))
    b = bindiff.function_features(_fn("parse", ["malloc", "memcpy"], ["INT_ADD", "LOAD", "STORE"]))
    assert bindiff.similarity(a, b) > 0.99


def test_changed_callee_lowers_similarity():
    vuln = bindiff.function_features(_fn("copy", ["strcpy"], ["LOAD", "STORE", "COPY"]))
    fixed = bindiff.function_features(
        _fn("copy", ["strncpy"], ["LOAD", "STORE", "COPY", "INT_LESS"]))
    s = bindiff.similarity(vuln, fixed)
    assert 0.3 < s < 0.99                                 # related but changed


def test_diff_localizes_the_changed_function():
    vuln = [_fn("main", ["process", "puts"], ["CALL", "CALL"]),
            _fn("process", ["strcpy"], ["LOAD", "STORE", "COPY"]),
            _fn("helper", ["malloc"], ["INT_ADD", "LOAD"])]
    patched = [_fn("main", ["process", "puts"], ["CALL", "CALL"]),
               _fn("process", ["strncpy", "memset"], ["LOAD", "STORE", "COPY", "INT_LESS"]),
               _fn("helper", ["malloc"], ["INT_ADD", "LOAD"])]
    d = bindiff.diff(vuln, patched)
    changed_names = {c["name"] for c in d["changed"]}
    assert "process" in changed_names                     # the patched function is localized
    assert "main" not in changed_names and "helper" not in changed_names


def test_variant_scan_finds_the_unpatched_copy():
    sig = bindiff.function_features(_fn("do_parse", ["strcpy", "atoi"], ["LOAD", "STORE", "COPY"]))
    corpus = [_fn("unrelated", ["printf"], ["CALL"]),
              _fn("parse_hdr", ["strcpy", "atoi"], ["LOAD", "STORE", "COPY"]),  # unpatched variant
              _fn("safe_parse", ["strncpy", "atoi"], ["LOAD", "STORE", "INT_LESS"])]
    hits = bindiff.variant_scan(sig, corpus, threshold=0.85)
    assert hits and hits[0]["name"] == "parse_hdr"        # the unpatched variant, best match
    assert all(h["name"] != "unrelated" for h in hits)


def test_generic_names_do_not_anchor():
    a = [_fn("fcn.00401000", ["malloc"], ["LOAD"])]
    b = [_fn("fcn.00408000", ["malloc"], ["LOAD"])]       # different auto-name, same shape
    m = bindiff.match_functions(a, b)
    # matched structurally (same features) despite different generic names
    assert len(m["matched"]) == 1 and m["matched"][0]["similarity"] > 0.9


@pytest.mark.skipif(not (shutil.which("gcc") or shutil.which("cc")), reason="no C compiler")
def test_end_to_end_real_binary_patch_diff():
    """Compile a vulnerable strcpy() and a patched strncpy() build, decompile both with the real
    backend, and confirm diff() localizes exactly the changed function."""
    from lykos import vendorenv
    vendorenv.activate()
    from lykos.analyze import native_re
    if native_re.locate_native() is None:
        pytest.skip("no native RE backend")
    gcc = shutil.which("gcc") or shutil.which("cc")
    d = Path(tempfile.mkdtemp())
    common = ('#include <stdio.h>\n#include <string.h>\n'
              'void banner(void){puts("v1");}\n'
              'int helper(int x){return x*3+1;}\n')
    (d / "vuln.c").write_text(common +
        'void process(char*s){char b[16]; strcpy(b,s); puts(b);}\n'
        'int main(int c,char**v){banner(); if(c>1)process(v[1]); return helper(c);}\n')
    (d / "patched.c").write_text(common +
        'void process(char*s){char b[16]; strncpy(b,s,15); b[15]=0; puts(b);}\n'
        'int main(int c,char**v){banner(); if(c>1)process(v[1]); return helper(c);}\n')
    vb, pb = d / "vuln", d / "patched"
    for src, out in ((d / "vuln.c", vb), (d / "patched.c", pb)):
        if subprocess.run([gcc, "-O0", str(src), "-o", str(out)], capture_output=True).returncode:
            pytest.skip("build failed")
    try:
        fv = native_re.analyze(str(vb)).get("functions", [])
        fp = native_re.analyze(str(pb)).get("functions", [])
    except Exception as e:
        pytest.skip(f"decompile failed: {e}")
    if not fv or not fp:
        pytest.skip("no functions recovered")
    dd = bindiff.diff(fv, fp)
    changed = {c["name"] for c in dd["changed"]}
    # `process` changed strcpy->strncpy; banner/helper are byte-identical and must not be flagged.
    assert "process" in changed, dd["changed"]
    assert "banner" not in changed and "helper" not in changed
