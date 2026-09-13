"""The two secret capabilities: recovering a constant a program compares against, and turning
it into an offline reproducer.

Both rest on predicates that decide what is a FINDING rather than reverse-engineering
inventory, and the cost of getting that wrong is measured: ncompress filed 56 corroborated
findings that were every one a dynamic-loader path like '/lib64/ld-linux-x86-64.so.2'. A
channel that reports 56 non-findings is worse than one that reports nothing, because an
analyst stops reading it.
"""
from __future__ import annotations

import pytest
from lykos.analyze.debug import extract_stage as ex
from lykos.analyze.poc import secret_stage as ss

# ---- what is worth filing ----------------------------------------------------------------

def test_a_comparison_against_our_own_input_is_evidence():
    """`is_gate` means our probe was one of the operands: the program compared what we sent
    against something, which is a statement about how it handles input."""
    assert ex.worth_filing("hunter2", True, "main")


def test_a_constant_the_loader_compared_is_not():
    """The probe sees ld.so's own strcmp calls, and they outnumber the program's."""
    assert not ex.worth_filing("/lib64/ld-linux-x86-64.so.2", False, "_dl_map_object")
    assert not ex.worth_filing("GLIBC_2.2.5", False, "check_match")
    assert not ex.worth_filing("libc.so.6", False, None)


@pytest.mark.parametrize("value", [
    "api_key", "PASSWORD", "secret_token", "admin", "login_hash", "licence_key",
    "license", "auth_bearer", "the_flag", "pwd",
])
def test_a_value_that_names_a_secret_is_kept_even_ungated(value):
    """`strcmp(x, "api_key")` is worth surfacing however it was reached."""
    assert ex.worth_filing(value, False, "someFunc")


@pytest.mark.parametrize("caller", [
    "check_password", "verifyToken", "isAdmin", "load_licence", "auth_user",
])
def test_a_caller_that_names_a_secret_is_kept(caller):
    assert ex.worth_filing("zzz", False, caller)


def test_an_ordinary_constant_in_ordinary_code_is_inventory_not_a_finding():
    assert not ex.worth_filing("%s: %s\n", False, "print_row")
    assert not ex.worth_filing("", False, None)
    assert not ex.worth_filing(None, False, None)


def test_the_keyword_test_is_case_insensitive_and_matches_inside_a_word():
    assert ex.worth_filing("MyPassWordHere", False, None)
    assert ex.worth_filing("xx", False, "GetAdminFlag")


# ---- is this operand ours --------------------------------------------------------------

def test_our_probe_is_recognised_whole_and_in_part():
    """The program may compare a PREFIX of what we sent -- a length-limited strncmp -- and
    that is still our input reaching the comparison."""
    probe = ex._PROBE.decode("latin-1")
    assert ex._ours(probe)
    assert ex._ours(probe[:12])
    assert ex._ours(ex._MARK)
    assert ex._ours("xxx" + ex._MARK + "yyy"), "the marker embedded in a larger string"


def test_something_that_is_not_ours_is_not_claimed():
    assert not ex._ours("hunter2")
    assert not ex._ours("")
    assert not ex._ours(None)
    assert not ex._ours("/etc/passwd")


def test_the_probe_marker_is_distinctive_enough_not_to_collide():
    """A marker that appears in ordinary binaries would make every comparison look like ours."""
    assert len(ex._MARK) >= 8
    assert ex._MARK in ex._PROBE.decode("latin-1")
    assert not ex._MARK.isalpha() or ex._MARK.upper() != ex._MARK.lower()


# ---- printability ------------------------------------------------------------------------

@pytest.mark.parametrize("s,ok", [
    ("hunter2", True), ("with space", True), ("tab\there", True),
    ("", False), ("\x00null", False), ("high\xff", False), ("\x01ctrl", False),
])
def test_only_printable_operands_are_reported(s, ok):
    """A binary blob rendered as text is noise in the operator's face, not a secret."""
    assert ex._printable(s) is ok


# ---- locating the secret in the file, for the reproducer ---------------------------------

def test_the_file_offset_of_a_secret_is_found():
    blob = b"\x7fELF" + b"\x00" * 64 + b"s3cr3t-passphrase\x00" + b"\x00" * 32
    off = ss._file_offset(blob, "s3cr3t-passphrase")
    assert off is not None
    assert blob[off:off + 17] == b"s3cr3t-passphrase"


def test_a_multi_line_secret_is_located_by_its_first_line():
    """A private key spans many lines and the stored value may be truncated; matching the
    whole thing would find nothing and the reproducer would have no offset to seek to."""
    key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN...\n-----END PRIVATE KEY-----"
    blob = b"pad" * 10 + key.encode() + b"\x00"
    assert ss._file_offset(blob, key) is not None


def test_a_truncated_secret_is_still_located_by_its_prefix():
    secret = "A" * 200
    blob = b"\x00" * 16 + secret.encode() + b"\x00"
    assert ss._file_offset(blob, secret[:70]) is not None


def test_a_secret_too_short_to_be_distinctive_is_not_located():
    """A 3-byte needle matches somewhere in almost any binary; an offset found that way points
    at a coincidence and the reproducer would extract the wrong bytes."""
    assert ss._file_offset(b"\x00" * 100 + b"abc" + b"\x00" * 100, "abc") is None


def test_a_secret_that_is_not_in_the_file_has_no_offset():
    assert ss._file_offset(b"\x7fELF" + b"\x00" * 200, "not-present-anywhere") is None
    assert ss._file_offset(b"", "anything") is None
    assert ss._file_offset(b"data", "") is None


def test_a_c_string_is_read_to_its_terminator():
    blob = b"....hunter2\x00trailing garbage"
    assert ss._cstr_at(blob, 4) == b"hunter2"


def test_an_unterminated_c_string_runs_to_the_end_rather_than_off_it():
    assert ss._cstr_at(b"....hunter2", 4) == b"hunter2"
    assert ss._cstr_at(b"", 0) == b""


def test_the_offset_round_trips_back_to_the_secret():
    """This is the contract the offline reproducer depends on: seek to the offset, read the
    C string, get the secret back."""
    secret = "correct-horse-battery-staple"
    blob = b"\x7fELF" + b"\x00" * 100 + secret.encode() + b"\x00" + b"junk"
    off = ss._file_offset(blob, secret)
    assert ss._cstr_at(blob, off).decode() == secret
