"""Differential (discrepancy-oracle) testing (differential.py)."""
import random
import shutil
import subprocess
import types

import pytest
from lykos.analyze.fuzz import differential as D


def _res(exit_code=0, crashed=False, signal_name=None, stdout=b""):
    return types.SimpleNamespace(exit_code=exit_code, crashed=crashed,
                                 signal_name=signal_name, stdout=stdout)


def test_outcome_buckets():
    assert D.outcome(_res(exit_code=0)) == "accept"
    assert D.outcome(_res(exit_code=1)) == "reject"
    assert D.outcome(_res(crashed=True, signal_name="SIGSEGV")).startswith("crash")


def test_outcome_output_mode_folds_stdout():
    a = D.outcome(_res(exit_code=0, stdout=b"hello"), compare="output")
    b = D.outcome(_res(exit_code=0, stdout=b"hello  "), compare="output")   # ws-normalized -> same
    c = D.outcome(_res(exit_code=0, stdout=b"world"), compare="output")
    assert a == b and a != c and a.startswith("accept:")


def test_discrepancy_agreement_and_kinds():
    assert D.discrepancy({"a": "accept", "b": "accept"})["disagree"] is False
    d = D.discrepancy({"a": "accept", "b": "reject"})
    assert d["disagree"] and d["kind"] == "accept-reject"
    assert set(d["partitions"]) == {"accept", "reject"}
    assert D.discrepancy({"a": "accept", "b": "crash:SIGSEGV"})["kind"] == "crash"
    assert D.discrepancy({"a": "accept:aa", "b": "accept:bb"})["kind"] == "output"


def test_delta_key_is_order_independent_and_distinguishing():
    k1 = D.delta_key({"a": "accept", "b": "reject"})
    k2 = D.delta_key({"b": "reject", "a": "accept"})
    k3 = D.delta_key({"a": "reject", "b": "accept"})
    assert k1 == k2 and k1 != k3


def test_campaign_needs_two_programs():
    with pytest.raises(ValueError):
        D.differential_campaign([D.Program("only", "/bin/true")], [b"x"], rng=random.Random(0),
                                iterations=1)


@pytest.mark.skipif(not (shutil.which("gcc") or shutil.which("cc")), reason="no C compiler")
def test_end_to_end_finds_a_parse_discrepancy(tmp_path):
    """Two 'validators' that disagree: strict accepts only a pure integer (strtol consumes all),
    lax accepts anything atoi() reads a nonzero from. On '12abc' they diverge -> a discrepancy."""
    from lykos import vendorenv
    vendorenv.activate()
    gcc = shutil.which("gcc") or shutil.which("cc")
    strict_c = tmp_path / "strict.c"
    strict_c.write_text('#include <stdlib.h>\n#include <stdio.h>\n'
                        'int main(){char b[64]; if(!fgets(b,64,stdin))return 1; char*e;'
                        ' strtol(b,&e,10); while(*e=="\\n"[0])e++; return *e? 1:0; }\n')
    lax_c = tmp_path / "lax.c"
    lax_c.write_text('#include <stdlib.h>\n#include <stdio.h>\n'
                     'int main(){char b[64]; if(!fgets(b,64,stdin))return 1;'
                     ' return atoi(b)!=0 || b[0]=="0"[0] ? 0 : 1; }\n')
    strict, lax = tmp_path / "strict", tmp_path / "lax"
    for src, out in ((strict_c, strict), (lax_c, lax)):
        if subprocess.run([gcc, "-O0", str(src), "-o", str(out)], capture_output=True).returncode:
            pytest.skip("build failed")
    progs = [D.Program("strict", str(strict), mode="stdin"),
             D.Program("lax", str(lax), mode="stdin")]
    # seed with an input that is known to diverge, plus mutation fodder
    st = D.differential_campaign(progs, [b"12abc\n", b"7\n"], rng=random.Random(3),
                                 iterations=40, timeout=5.0)
    assert st.execs > 0
    assert any(d["kind"] == "accept-reject" for d in st.discrepancies), st.discrepancies
