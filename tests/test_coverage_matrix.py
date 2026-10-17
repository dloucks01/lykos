"""The coverage matrix: axes derived from the fixtures, not from a table kept beside them.

This exists because the obvious instrument -- one fixture per CWE id -- cannot be built. `core/`
mentions 221 CWE strings; 29 are emitted by a literal `cwe="CWE-x"`; the rest live in
CVE-database rows and taxonomy tables, and one fixture legitimately carries five of them. CWE is
a vocabulary for describing a defect, not a dimension of capability. The dimensions that have
decided real outcomes here are mechanism, channel, substrate and oracle -- so those are the
axes, and they are READ OFF the fixtures so the table cannot drift from the cases.
"""
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import coverage_matrix as cm  # noqa: E402


class _Case:
    def __init__(self, name, src="", want_cwe=(), want_level=1, **kw):
        self.name, self.src, self.want_cwe, self.want_level = name, src, want_cwe, want_level
        self.note, self.clean, self.want_all_cwe = kw.get("note", ""), kw.get("clean", False), ()
        self.cross, self.want_file_type = kw.get("cross", ""), kw.get("want_file_type", "")
        self.as_source = kw.get("as_source", False)


def test_the_channel_comes_from_the_fixtures_own_source():
    """Whatever a case's name says, the C decides: the fixture is the only thing that cannot lie
    about how its input arrives."""
    assert cm.channel_of(_Case("x", 'int main(int c,char**v){strcpy(b,argv[1]);}')) == "argv"
    assert cm.channel_of(_Case("x", 'int main(void){char*p=getenv("Q");}')) == "env"
    assert cm.channel_of(_Case("x", 'int main(void){read(0,b,400);}')) == "stdin"
    assert cm.channel_of(_Case("x", 'int main(void){FILE*f=fopen(argv[1],"rb");}')) == "file"
    assert cm.channel_of(_Case("x", 'int main(void){int s=socket(2,1,0);}')) == "socket"
    # a dispatcher door is named by the case, because the channel is the PROGRAM inside the image
    assert cm.channel_of(_Case("multicall_dispatch", "#include <stdio.h>\nint main(void){}")) \
        == "door"


def test_one_printed_colon_is_not_a_prompted_target():
    """PROMPTED delivery means the program reads its fields one at a time, so the bytes have to
    be paced one line per prompt. Nearly every fixture prints a colon somewhere; treating that as
    the signature put 19 of the 22 out-of-bounds-write cases in the wrong column the first time
    this table was printed."""
    single = '#include <stdio.h>\nint main(void){printf("in: ");scanf("%s",b);}'
    assert cm.channel_of(_Case("x", single)) == "stdin"
    paced = ('#include <stdio.h>\nint main(void){printf("name: ");fgets(a,64,stdin);'
             'printf("age: ");fgets(b,64,stdin);}')
    assert cm.channel_of(_Case("x", paced)) == "prompt"


def test_a_fixture_that_reads_nothing_says_so():
    """`uninit_stack_read` prints a never-initialised local: its defect needs no input at all,
    which is a real answer and not an inference failure."""
    src = '#include <stdio.h>\nint main(void){char b[64];printf("%.64s\\n", b);}'
    assert cm.channel_of(_Case("x", src)) == "no-input"
    assert cm.channel_of(_Case("x", "printf 'py' > m.py && python3 -m compileall")) == "built"


def test_substrate_and_oracle_come_from_how_the_case_is_built():
    assert cm.substrate_of(_Case("x", cross="aarch64-linux-gnu-")) == "q:aarch64"
    assert cm.substrate_of(_Case("x", cross="x86_64-w64-mingw32-")) == "wine"
    assert cm.substrate_of(_Case("x", want_file_type="pyc")) == "cpython"
    assert cm.substrate_of(_Case("x", as_source=True)) == "src"
    assert cm.substrate_of(_Case("firmware_carve_overflow")) == "fw"
    assert cm.substrate_of(_Case("x")) == "native"
    # the oracle is what makes the defect VISIBLE, which is the axis busybox's lzma read taught:
    # it faults only under the guard-page allocator
    assert cm.oracle_of(_Case("x", as_source=True)) == "sanitizer build"
    assert cm.oracle_of(_Case("x")) == "signal + guard page"
    assert cm.oracle_of(_Case("x", clean=True)).startswith("none")


def test_several_cwes_collapse_to_one_mechanism():
    """121/122/787/119/120 are all "somebody wrote past the end"; a mechanism is what needs a
    different TECHNIQUE to find or to prove."""
    c = _Case("x", want_cwe=("CWE-190", "CWE-131", "CWE-122", "CWE-787", "CWE-119"))
    mechs = cm.mechanisms_of(c)
    assert "integer-overflow" in mechs and "heap-overflow" in mechs and "oob-write" in mechs
    assert len(mechs) == 3, mechs
    # a case that asserts only a LEVEL is labelled as such rather than dropped
    assert cm.mechanisms_of(_Case("x", want_cwe=())) == ["(level only)"]
    assert cm.mechanisms_of(_Case("x", want_file_type="pe")) == ["(front-end only)"]
    assert cm.mechanisms_of(_Case("x", clean=True)) == ["(precision control)"]


def test_every_real_case_lands_on_a_named_axis():
    """The whole point: no case may fall into an "unknown" bucket, because an unknown axis value
    is a hole in the instrument rather than a hole in the coverage."""
    data = cm.rows({})
    assert len(data) > 100
    unknown = sorted({r["case"] for r in data if r["channel"] == "unknown"})
    assert not unknown, f"the channel could not be read off these fixtures: {unknown}"
    assert {"stack-overflow", "oob-read", "lifetime", "uninitialised"} <= {
        r["mechanism"] for r in data}
    # and the ISA ladder contributes one mechanism across many substrates, which is its shape
    isa = [r for r in data if r["case"].startswith("archgate:")]
    assert len({r["substrate"] for r in isa}) >= 13
    assert {r["mechanism"] for r in isa} == {"stack-overflow"}


def test_measured_levels_are_parsed_from_a_real_run():
    """`--measured` overlays what a run REACHED. The demanded level is a claim; only this is
    evidence."""
    out = (
        "CASE                     | OK   | PROFILE                    | FINDINGS / REASON\n"
        "addr_leak_pie_ret2win    | PASS | x86-64 pie=on can=off relro=part L3* | primitive [132s]\n"
        "indexed_read_l2          | PASS | x86-64 pie=on can=off relro=part L2* | root_cause [104s]\n"
        "double_free              | FAIL | x86-64 pie=on L0 | want L1 [60s]\n")
    import tempfile
    f = Path(tempfile.mkdtemp()) / "run.txt"
    f.write_text(out)
    m = cm.read_measured(f)
    assert m["addr_leak_pie_ret2win"] == "L3"
    assert m["indexed_read_l2"] == "L2"
    assert m["double_free"] == "L0"
