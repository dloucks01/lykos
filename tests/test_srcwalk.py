"""The source scanners' shared walk (fingerprint/srcwalk.py): same-named files in different
directories stay separate findings, a unique file keeps its old key, and the skip rule looks only
inside the tree -- a case store under a directory named `tests` is still scanned."""
from lykos.analyze.fingerprint import int_overflow, source_sinks, uaf

BUGS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void f(char *user, size_t n, size_t m) {
    char *p = malloc(n * m);
    printf(user);
    free(p);
    p[0] = 1;
}
"""


def _tree(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def _keys(findings, prefix):
    return sorted(f["dedup_key"] for f in findings if f["dedup_key"].startswith(prefix))


def test_same_named_files_stay_separate_and_unique_ones_keep_their_key(tmp_path):
    # the tree lives under `tests/` on purpose: only paths INSIDE it may trigger the skip rule
    root = _tree(tmp_path / "tests" / "proj", {"a/util.c": BUGS, "b/util.c": BUGS,
                                               "main.c": BUGS, "examples/demo.c": BUGS})
    for scan, prefix in ((int_overflow.scan_source, "intovf:"),
                         (source_sinks.scan_source, "srcsink:"), (uaf.scan_source, "uaf:")):
        keys = _keys(scan(root), prefix)
        assert any("a/util.c" in k for k in keys) and any("b/util.c" in k for k in keys), keys
        assert any(f"{prefix}main.c:" in k or f":main.c:" in k for k in keys), keys
        assert not any("demo.c" in k for k in keys), keys       # examples/ is still skipped
        assert len(keys) == len(set(keys))
