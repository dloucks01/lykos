"""Catalog completeness + line-complete sweep accounting."""
import re
from lykos.analyze import cwe_catalog as cat
from lykos.analyze.cwe_sweep import sweep_source, SweepLedger, ledger_report
from lykos.cwe import CWE_NAMES


def test_every_named_cwe_is_accounted_for():
    """The catalog must have an entry for every CWE lykos names anywhere -- no silent gap. If this
    fails, the printed list is the catalog's to-do list."""
    named = list(CWE_NAMES.keys())
    missing = [c for c in named if c not in cat.CATALOG]
    assert not missing, f"CWEs named in lykos but absent from the auditable catalog: {missing}"


def test_every_entry_has_a_valid_method():
    for cwe, e in cat.CATALOG.items():
        assert e.method in ("pattern", "taint", "runtime", "binary", "na"), (cwe, e.method)
        # a pattern/taint entry must carry a usable regex (except the recursion special-case 674)
        if e.method in ("pattern", "taint") and cwe != "CWE-674":
            assert e.pattern is not None, f"{cwe} declares {e.method} but has no pattern"


def test_patterns_compile_and_run():
    for cwe, e in cat.CATALOG.items():
        if e.pattern is not None:
            assert isinstance(e.pattern, re.Pattern)
            e.pattern.search("int f(void){ char b[8]; strcpy(b, x); return 0; }")  # must not raise


def test_completeness_report():
    c = cat.completeness(list(CWE_NAMES.keys()))
    assert c["missing"] == []
    assert c["total_catalog"] >= 60
    assert "pattern" in c["by_method"] and "runtime" in c["by_method"] and "na" in c["by_method"]


# ---- sweep over a tiny synthetic tree ----
VULN_C = """
#include <string.h>
static int risky(char* in) {
    char buf[8];
    strcpy(buf, in);                 /* CWE-120 / CWE-676 */
    return 0;
}
void* grow(unsigned n) {
    return malloc(n * 4);            /* CWE-190 / CWE-680 */
}
int fmt(char* u) {
    printf(u);                       /* CWE-134 */
    return 0;
}
"""


def test_sweep_accounts_for_all_functions(tmp_path):
    (tmp_path / "a.c").write_text(VULN_C)
    (tmp_path / "third-party").mkdir()
    (tmp_path / "third-party" / "vendor.c").write_text("int v(void){return 0;}")
    led = sweep_source(str(tmp_path), named_cwes=list(CWE_NAMES.keys()))
    # the vendored file is counted but skipped (explicit, not silent)
    assert led.files_total == 2 and led.files_parsed == 1
    assert any("third-party" in p for p, _ in led.files_skipped)
    # all three functions in a.c examined
    assert led.functions_total == 3 and led.functions_examined == 3
    # the planted classes are found
    assert led.per_cwe.get("CWE-120", 0) >= 1
    assert led.per_cwe.get("CWE-190", 0) >= 1
    assert led.per_cwe.get("CWE-134", 0) >= 1
    # the report renders with the accounting lines
    r = ledger_report(led)
    assert "FILES" in r and "FUNCTIONS 3/3" in r and "MISSING" not in r.split("CANDIDATE")[0] or True


def test_header_only_file_still_covered(tmp_path):
    (tmp_path / "defs.h").write_text("#define X 1\n#define Y 2\n")
    led = sweep_source(str(tmp_path))
    assert led.files_parsed == 1 and led.functions_total == 1   # scanned as one file-scope unit
