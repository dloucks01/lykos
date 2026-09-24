"""Which recovered constants are findings?

The probe breakpoints comparison functions and records both operands. Every recovered constant
used to become a finding at `corroborated`/0.85 -- so ncompress produced **56** of them, every
one a dynamic-loader string like '/lib64/ld-linux-x86-64.so.2' or '__vdso_clock_gettime',
because the probe sees ld.so's own strcmp calls long before the program runs.

A comparison is evidence about how the program handles INPUT only when our input was one of
the operands.
"""
from lykos.analyze.debug.extract_stage import worth_filing


def test_a_gate_on_our_input_is_a_finding():
    """`if (strcmp(argv[1], "hunter2") == 0)` -- the constant is a hard-coded credential."""
    assert worth_filing("hunter2-s3cret-password", True, "main")


def test_a_loader_string_is_not():
    """Neither operand was ours: the loader compared two of its own constants."""
    assert not worth_filing("/lib64/ld-linux-x86-64.so.2", False, "_dl_new_object")
    assert not worth_filing("__vdso_clock_gettime", False, "dl_main")


def test_a_value_that_names_a_secret_is_kept_even_ungated():
    """`strcmp(x, "api_key")` is worth surfacing however it was reached."""
    assert worth_filing("api_key", False, "somefunc")
    assert worth_filing("PRIVATE_KEY_PEM", False, "somefunc")


def test_a_caller_that_names_a_secret_is_kept():
    assert worth_filing("abc123", False, "check_password")


def test_an_ordinary_constant_in_ordinary_code_is_inventory():
    """Still reported in the event's `recovered` list -- it is just not a finding."""
    assert not worth_filing("GET", False, "parse_request")
    assert not worth_filing("", False, None)
