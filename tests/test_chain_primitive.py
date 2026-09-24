"""Primitive chaining: payload shaping + CWE->technique recipe selection (pure helpers).

The live control-flow demonstration (drive the primitive to overwrite a code pointer and confirm
the win under ptrace) is exercised end-to-end by the stage on a real target; here we cover the
deterministic building blocks."""
import struct

from lykos.analyze.poc import chain_primitive as chain


def test_p64_little_endian():
    assert chain._p64(0x40129d) == struct.pack("<Q", 0x40129d)
    assert chain._p64(-1) == b"\xff" * 8                     # masked to 64 bits


def test_drive_overflow_puts_payload_in_last_string_field():
    # edit flow [idx, str]: id then the overflow buffer
    out = chain._drive_overflow(["idx", "str"], b"PAY", idx=b"0")
    assert out == b"0\nPAY\n"
    # add flow [num, str]: the size is driven large (unbounded copy), payload in the string
    out = chain._drive_overflow(["num", "str"], b"XX")
    assert out == b"999\nXX\n"
    # multiple strings: only the LAST carries the payload
    out = chain._drive_overflow(["str", "str"], b"P")
    assert out == b"AAAA\nP\n"
    # no learned fields: still delivers the payload
    assert chain._drive_overflow([], b"P") == b"P\n"


def test_vclass_maps_every_primitive_cwe():
    assert chain._VCLASS["CWE-415"] == "double_free"
    assert chain._VCLASS["CWE-416"] == "uaf"
    assert chain._VCLASS["CWE-122"] == "heap_overflow"
    assert chain._VCLASS["CWE-129"] == "oob_write"


def test_recipe_control_flow_when_win_reachable():
    # a heap primitive with a reachable win -> an aaheg technique + the win as the transfer target
    r = chain._recipe("heap_overflow", ("win", 0x40129d), b"")
    assert r.get("technique")                                 # a concrete technique was chosen
    # oob is not a heap technique: it writes through the escaped array slot
    r2 = chain._recipe("oob_write", ("win", 0x1234), b"")
    assert r2["technique"] == "oob-index-write"
    assert "out-of-bounds" in r2["note"].lower()


def test_recipe_arbitrary_write_without_win():
    r = chain._recipe("uaf", None, b"")
    assert r.get("technique") or r.get("advisory_alternatives") or r.get("reason")
