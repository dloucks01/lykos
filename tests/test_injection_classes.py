"""Three injection classes the probe set did not have, each with a native sink and an offline
oracle -- and the measurement that justifies each being its OWN probe rather than another payload
in an existing one.

* **XInclude** is not an XXE variant. The accepted XXE fix is to parse without `XML_PARSE_NOENT`
  so a SYSTEM entity is never substituted; XInclude is a separate libxml2 feature that reads files
  regardless. The differential is asserted here on ONE binary: the entity payload comes back
  unexpanded, the `xi:include` payload returns /etc/passwd.
* **`wordexp`** is a command-execution sink that reads like a path utility, in a binary with no
  `system` and no `popen` anywhere in it. Its payload set has to be its own: `wordexp` REJECTS a
  bare `;` as a syntax error, so the cmdi list confirms nothing.
* **XPath** is deliberately a CAPABILITY verdict. There is no document-independent marker an
  injected XPath 1.0 expression can make the engine emit, so the oracle is the evaluator's own
  error -- the same rung, for the same reason, as error-based SQL injection.
"""
import os
import re
import shutil
import subprocess

import pytest
from lykos.analyze.poc import injection

_XML2_INC = "/usr/include/libxml2"


def _cc(tmp_path, src, name, extra=()):
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    (tmp_path / f"{name}.c").write_text(src)
    exe = tmp_path / name
    cmd = [gcc, "-O0", "-w", str(tmp_path / f"{name}.c"), "-o", str(exe), *extra]
    if subprocess.run(cmd, capture_output=True).returncode:
        pytest.skip(f"cannot build {name}")
    return exe


def _run(exe, payload: bytes) -> bytes:
    p = subprocess.run([str(exe)], input=payload, capture_output=True, timeout=30)
    return p.stdout + p.stderr


# ----------------------------------------------------------------------------- probe-table shape
def test_the_three_probes_are_registered_with_distinct_sinks():
    for name, cwe in (("wordexp-command-substitution", "CWE-78"), ("xinclude", "CWE-611"),
                      ("xpath-injection", "CWE-643")):
        p = injection.PROBES[name]
        assert p["cwe"] == cwe
        assert p["sinks"] and p["payloads"]("MK") and p["confirm"]
        assert p["binary"] is True
    # a probe fires on IMPORTED SYMBOLS, so an overlapping sink set would make two probes claim the
    # same target; these three must not collide with the classes they resemble.
    assert not (injection.PROBES["xinclude"]["sinks"] & injection.PROBES["xxe"]["sinks"])
    assert not (injection.PROBES["wordexp-command-substitution"]["sinks"]
                & injection.PROBES["command-injection"]["sinks"])


def test_xpath_is_a_capability_verdict_and_the_others_are_effects():
    assert injection.PROBES["xpath-injection"]["proves"] == injection._PROVES_CAPABILITY
    assert injection.PROBES["xinclude"]["proves"] == injection._PROVES_EFFECT
    assert (injection.PROBES["wordexp-command-substitution"]["proves"]
            == injection._PROVES_EFFECT)


def test_wordexp_payloads_avoid_the_metacharacters_wordexp_rejects():
    """The measured reason this is not just another cmdi payload: `wordexp` returns an error for a
    bare `;` or `|`, so only the substitution forms can confirm."""
    pls = injection.wordexp_payloads("MK")
    assert pls
    for p in pls:
        assert "MK" in p
        assert "$(" in p or "`" in p
        assert not re.match(r"^\s*[;|&]", p), p
    # and the cmdi set, which this probe deliberately does not reuse, is full of them
    assert any(c.lstrip().startswith((";", "|", "&")) for c in injection.cmdi_payloads("MK"))


def test_xinclude_payloads_use_text_parsing():
    """`parse="text"` is load-bearing: the default parse="xml" tries to parse /etc/passwd AS XML
    and the include fails."""
    pls = injection.xinclude_payloads()
    assert pls
    for p in pls:
        assert b'parse="text"' in p
        assert b"XInclude" in p and b"passwd" in p


def test_xpath_payloads_carry_both_a_union_and_an_unbalanced_quote():
    pls = injection.xpath_payloads("MK")
    assert any("|" in p and "//" in p for p in pls), "no node-set union payload"
    assert any(p.count("'") % 2 == 1 for p in pls), "no unbalanced-quote payload"


def test_xpath_confirm_needs_an_engine_error_and_not_a_reflection():
    assert injection.xpath_confirm(b"XPath error : Invalid predicate\n", "'MK", "MK")
    assert injection.xpath_confirm(b"xpath failed", "'MK", "MK")
    # no error signature -> not a confirmation, however much of our payload came back
    assert not injection.xpath_confirm(b"row: hello\nrow: world\n", "' or '1'='1", "MK")
    assert not injection.xpath_confirm(b"", "'MK", "MK")
    # a program that prints its query AND errors still confirms; one that only echoes does not
    assert not injection.xpath_confirm(b"query: /a[x='MK']\n", "'MK", "MK")


# --------------------------------------------------------------------------------- live fixtures
_XINC = r"""
#include <stdio.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/xinclude.h>
#include <libxml/tree.h>
int main(void){ setvbuf(stdout,0,2,0);
  static char doc[8192];
  size_t n = fread(doc, 1, sizeof doc - 1, stdin); doc[n] = 0;
  xmlDocPtr d = xmlReadMemory(doc, (int)n, "in.xml", NULL, XML_PARSE_NONET);
  if(!d){ printf("parse failed\n"); return 1; }
  xmlXIncludeProcess(d);
  xmlChar *out = NULL; int len = 0;
  xmlDocDumpMemory(d, &out, &len);
  printf("doc: %.*s\n", len, out ? (char*)out : "");
  if(out) xmlFree(out);
  xmlFreeDoc(d); return 0; }
"""

_WEXP = r"""
#include <stdio.h>
#include <string.h>
#include <wordexp.h>
int main(void){ setvbuf(stdout,0,2,0);
  char in[512]; if(!fgets(in, sizeof in, stdin)) return 0;
  in[strcspn(in, "\n")] = 0;
  wordexp_t we;
  if(wordexp(in, &we, 0) != 0){ printf("bad pattern\n"); return 1; }
  for(size_t i = 0; i < we.we_wordc; i++) printf("word: %s\n", we.we_wordv[i]);
  wordfree(&we); return 0; }
"""

_XPATH = r"""
#include <stdio.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
static const char *DOC =
  "<users><user><name>alice</name><public>hello</public><secret>S3CRET-A</secret></user>"
  "<user><name>bob</name><public>world</public><secret>S3CRET-B</secret></user></users>";
int main(void){ setvbuf(stdout,0,2,0);
  char in[512]; if(!fgets(in, sizeof in, stdin)) return 0;
  in[strcspn(in, "\n")] = 0;
  xmlDocPtr d = xmlReadMemory(DOC, (int)strlen(DOC), "d.xml", NULL, 0);
  xmlXPathContextPtr c = xmlXPathNewContext(d);
  char q[1024];
  snprintf(q, sizeof q, "/users/user[name='%s']/public", in);
  xmlXPathObjectPtr o = xmlXPathEvalExpression((const xmlChar*)q, c);
  if(!o){ printf("xpath failed\n"); return 1; }
  if(o->nodesetval)
    for(int i = 0; i < o->nodesetval->nodeNr; i++){
      xmlChar *t = xmlNodeGetContent(o->nodesetval->nodeTab[i]);
      printf("row: %s\n", t ? (char*)t : ""); if(t) xmlFree(t); }
  return 0; }
"""


@pytest.mark.skipif(not os.path.isdir(_XML2_INC), reason="libxml2 headers required")
def test_xinclude_discloses_a_file_where_the_xxe_payload_cannot(tmp_path):
    """The differential that makes XInclude its own class, on ONE binary and one run each: the
    parser has external entities OFF (the accepted XXE fix) so the entity payload is inert, and
    the xi:include payload returns /etc/passwd anyway."""
    exe = _cc(tmp_path, _XINC, "xinc", ("-I" + _XML2_INC, "-lxml2"))
    xxe = injection.xxe_payloads()[0]
    out_xxe = _run(exe, xxe)
    assert not injection.traversal_confirm(out_xxe, xxe, "MK"), \
        "the entity payload disclosed a file, so this fixture is not entity-hardened"
    hit = False
    for p in injection.xinclude_payloads():
        out = _run(exe, p)
        if injection.traversal_confirm(out, p, "MK"):
            hit = True
            break
    assert hit, "no XInclude payload disclosed /etc/passwd"


def test_wordexp_runs_a_command_in_a_binary_with_no_exec_sink(tmp_path):
    """And the import gate is the point: the binary has no system/popen/exec*, so the
    `command-injection` probe does not even apply to it."""
    from lykos.analyze.poc import rop
    exe = _cc(tmp_path, _WEXP, "wexp")
    imports = set(rop.got_entries(exe.read_bytes()))
    assert not (imports & injection.PROBES["command-injection"]["sinks"]), imports
    assert imports & injection.PROBES["wordexp-command-substitution"]["sinks"]
    marker = "LYKOSMK77"
    hit = None
    for p in injection.wordexp_payloads(marker):
        out = _run(exe, p.encode() + b"\n")
        if injection.cmdi_confirm(out, p, marker):
            hit = p
            break
    assert hit, "no wordexp payload ran a command"
    # the control: a plain path expands and confirms nothing
    assert not injection.cmdi_confirm(_run(exe, b"/tmp/*\n"), "/tmp/*", marker)


@pytest.mark.skipif(not os.path.isdir(_XML2_INC), reason="libxml2 headers required")
def test_xpath_injection_confirms_by_the_evaluators_error(tmp_path):
    """The capability oracle, and -- separately -- that the union payload really does reach the
    document's secrets, which is why the class matters even though the generic verdict is L2."""
    exe = _cc(tmp_path, _XPATH, "xp", ("-I" + _XML2_INC, "-lxml2"))
    marker = "LYKOSMK77"
    assert any(injection.xpath_confirm(_run(exe, p.encode() + b"\n"), p, marker)
               for p in injection.xpath_payloads(marker)), "no payload raised an evaluator error"
    # a benign value must confirm nothing
    assert not injection.xpath_confirm(_run(exe, b"alice\n"), "alice", marker)
    # and the disclosure itself: a lookup restricted to `public` returning a `secret`
    out = _run(exe, b"x'] | //* | //a[name='\n")
    assert b"S3CRET-A" in out, "the union payload did not reach the document's secrets"
