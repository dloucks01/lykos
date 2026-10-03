"""Active injection probes: send a payload, and decide from the output whether it actually
EXECUTED rather than merely appeared.

That distinction is the whole capability. A program that echoes its input back will contain
the marker in its output whether or not anything was injected, so a confirmer that just looks
for the marker turns every echo into a critical CWE-78. Confirming execution -- not presence
-- is what makes these findings worth the word "confirmed".
"""
from __future__ import annotations

import pytest
from lykos.analyze.poc import injection

MARK = "LYKOSMARK1234"


# ---- command injection -------------------------------------------------------------------

def test_the_payloads_cover_the_ways_out_of_a_shell_argument():
    """Each metacharacter breaks a different construction; a program quoting one may not
    quote the others, so one payload shape is not enough."""
    pays = injection.cmdi_payloads(MARK)
    assert pays
    joined = " ".join(pays)
    for meta in (";", "$(", "`", "|", "&&", "'", '"', "\n"):
        assert meta in joined, f"no payload uses {meta!r}"
    assert all(MARK in p for p in pays), "a payload that cannot be confirmed"


def test_an_executed_echo_confirms():
    assert injection.cmdi_confirm(f"output\n{MARK}\n".encode(), f"; echo {MARK}", MARK)


def test_an_echoed_payload_does_NOT_confirm():
    """The program printed our payload back. The marker is present and nothing ran -- this is
    the false positive the confirmer exists to refuse."""
    out = f"you said: ; echo {MARK}\n".encode()
    assert not injection.cmdi_confirm(out, f"; echo {MARK}", MARK)


def test_output_without_the_marker_does_not_confirm():
    assert not injection.cmdi_confirm(b"nothing interesting", f"; echo {MARK}", MARK)
    assert not injection.cmdi_confirm(b"", f"; echo {MARK}", MARK)


def test_an_execution_alongside_an_echo_still_confirms_only_if_the_literal_is_gone():
    """Conservative by design: if the literal `echo <marker>` is anywhere in the output we
    cannot tell execution from echo, so we decline rather than guess."""
    both = f"cmd: ; echo {MARK}\n{MARK}\n".encode()
    assert not injection.cmdi_confirm(both, f"; echo {MARK}", MARK)


# ---- format string -----------------------------------------------------------------------

def test_format_payloads_carry_directives_and_a_marker():
    pays = injection.fmt_payloads(MARK)
    assert pays
    for p in pays:
        assert MARK.encode() in p
        assert b"%p" in p or b"%x" in p


def test_interpreted_directives_leak_pointers_and_confirm():
    out = MARK.encode() + b".0x7ffd1234.0x40100a.0x0.0x1"
    assert injection.fmt_confirm(out, b"", MARK)


def test_a_nil_pointer_leak_also_confirms():
    assert injection.fmt_confirm(MARK.encode() + b".(nil).(nil)", b"", MARK)
    assert injection.fmt_confirm(MARK.encode() + b".(null)", b"", MARK)


def test_directives_echoed_verbatim_do_NOT_confirm():
    """printf("%s", user) prints the directives; printf(user) interprets them. The difference
    is the bug, and the output tells them apart."""
    out = MARK.encode() + b".%p.%p.%p.%p"
    assert not injection.fmt_confirm(out, b"", MARK)
    assert not injection.fmt_confirm(MARK.encode() + b"%x.%x", b"", MARK)


def test_a_single_hex_word_is_not_enough_to_confirm():
    """One hex number could be the program's own output. Two or more in the segment after our
    marker is the pointer leak."""
    assert not injection.fmt_confirm(MARK.encode() + b".0xdeadbeef", b"", MARK)


def test_no_marker_means_no_confirmation():
    assert not injection.fmt_confirm(b"0x1 0x2 0x3", b"", MARK)
    assert not injection.fmt_confirm(b"", b"", MARK)


def test_only_the_output_AFTER_the_marker_is_considered():
    """Hex the program printed before our payload arrived says nothing about a format bug."""
    out = b"build 0x1000 0x2000 ok\n" + MARK.encode() + b".%p.%p"
    assert not injection.fmt_confirm(out, b"", MARK)


# ---- path traversal ----------------------------------------------------------------------

def test_traversal_payloads_cover_encoded_and_collapsed_forms():
    pays = injection.traversal_payloads()
    assert any(b"../" in p for p in pays)
    assert any(b"%2f" in p.lower() for p in pays), "no URL-encoded form"
    assert any(b"....//" in p for p in pays), "no filter-collapsing form"
    assert any(p.startswith(b"/etc") for p in pays), "no absolute-path form"


@pytest.mark.parametrize("out", [
    b"root:x:0:0:root:/root:/bin/bash\n",
    b"root::0:0:root:/root:/bin/sh\n",
    b"daemon:x:1:1\nroot:x:0:0:root\n",
])
def test_reading_the_password_file_confirms(out):
    assert injection.traversal_confirm(out, b"", "")


@pytest.mark.parametrize("out", [
    b"", b"permission denied", b"No such file or directory",
    b"root is not here", b"rooted:x:0:0",
])
def test_anything_short_of_the_file_contents_does_not_confirm(out):
    assert not injection.traversal_confirm(out, b"", "")


# ---- SQL injection -----------------------------------------------------------------------

def test_sqli_payloads_cover_quote_contexts_and_column_counts():
    pays = injection.sqli_payloads(MARK)
    assert any(p.startswith("' UNION SELECT") for p in pays), "no single-quote context"
    assert any(p.startswith('" UNION SELECT') for p in pays), "no double-quote context"
    assert any(p.startswith("0 UNION SELECT") for p in pays), "no numeric (unquoted) context"
    assert all(MARK in p for p in pays), "a payload with no marker cannot be judged"
    assert any("-- " in p for p in pays) and any(p.rstrip().endswith("#") for p in pays)


def test_sqli_confirms_when_the_db_returns_the_injected_marker():
    # the UNION-selected marker came back as a row -- the input was parsed as SQL
    out = f"search name: found: {MARK}\n".encode()
    assert injection.sqli_confirm(out, f"' UNION SELECT '{MARK}'-- ", MARK)


def test_sqli_does_NOT_confirm_on_a_verbatim_echo_of_the_payload():
    pl = f"' UNION SELECT '{MARK}'-- "
    assert not injection.sqli_confirm(("you searched for: " + pl + "\n").encode(), pl, MARK)


def test_sqli_does_not_confirm_without_the_marker():
    assert not injection.sqli_confirm(b"found: bob\n", f"' UNION SELECT '{MARK}'-- ", MARK)
    assert not injection.sqli_confirm(b"", f"' UNION SELECT '{MARK}'-- ", MARK)


# ---- XXE ---------------------------------------------------------------------------------

def test_xxe_payloads_declare_an_external_entity_to_a_local_file():
    pays = injection.xxe_payloads(MARK)
    assert pays and all(b"<!DOCTYPE" in p and b"SYSTEM" in p for p in pays)
    assert any(b"/etc/passwd" in p for p in pays)
    assert any(b"file://" in p for p in pays)


def test_xxe_confirms_only_on_the_leaked_file_contents():
    # XXE reuses the traversal oracle: the entity resolved /etc/passwd and its content came back
    assert injection.traversal_confirm(b"parsed: root:x:0:0:root:/root:/bin/sh\n", b"", "")
    assert not injection.traversal_confirm(b"parsed: hello\n", b"", "")


# ---- SSRF --------------------------------------------------------------------------------

def test_ssrf_payloads_use_the_file_scheme_for_offline_confirmation():
    pays = injection.ssrf_payloads(MARK)
    assert pays and all(b"etc/passwd" in p for p in pays)
    assert any(p.lower().startswith(b"file:") for p in pays)
    # confirmed by the fetched file's contents (shared traversal oracle)
    assert injection.traversal_confirm(b"root:x:0:0:root:/root:/bin/sh\n", b"", "")


# ---- the probe table ---------------------------------------------------------------------

def test_every_probe_is_wired_end_to_end():
    """A probe missing any piece is inert: it generates nothing, or generates payloads whose
    result can never be judged."""
    assert injection.PROBES
    for name, spec in injection.PROBES.items():
        assert spec.get("cwe", "").startswith("CWE-"), name
        assert spec.get("severity") in ("low", "medium", "high", "critical"), name
        assert spec.get("sinks"), f"{name} names no sink to aim at"
        assert callable(spec.get("payloads")), name
        assert callable(spec.get("confirm")), name
        assert spec.get("title"), name
        pays = spec["payloads"](MARK)
        assert pays, f"{name} generates no payloads"


def test_no_probe_confirms_on_empty_output():
    """A program that printed nothing has not demonstrated anything."""
    for name, spec in injection.PROBES.items():
        payload = spec["payloads"](MARK)[0]
        assert not spec["confirm"](b"", payload, MARK), f"{name} confirmed on no output"
