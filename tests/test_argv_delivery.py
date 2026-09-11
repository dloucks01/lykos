"""Does the payload we built actually reach the program?

Three defects here between a working exploitation primitive and a confirmed one, all silent.
Measured on ncompress 4.2.4 (CVE-2001-1413), a real stack overflow reached through argv: the
offset was recovered correctly and the primitive still reported `confirmed: False`, because
the bytes never arrived intact.
"""
import pytest
from lykos.analyze.dynamic import sandbox
from lykos.analyze.poc import bundle

# The IP-control sentinel, little-endian. Two of its bytes are >= 0x80, which is what breaks.
_MARKER = bytes([0x37, 0x13, 0xDE, 0xC0, 0x37, 0x13])


def test_a_payload_survives_the_trip_to_execve():
    """os.execv and subprocess encode str with the filesystem encoding, so UTF-8 turns every
    byte >= 0x80 into two. Any payload carrying an address is silently corrupted -- which is
    most of them."""
    as_text = _MARKER.decode("latin-1")
    assert as_text.encode("utf-8") != _MARKER, "the corruption this guards against"
    assert sandbox.argv_bytes(as_text) == _MARKER


def test_bytes_are_passed_through_untouched():
    assert sandbox.argv_bytes(_MARKER) == _MARKER


def test_real_text_is_not_forced_through_latin_1():
    """A genuine non-ASCII path cannot be a payload -- latin-1 cannot even represent it -- so
    it is encoded the way the filesystem expects."""
    assert sandbox.argv_bytes("café/π.bin") == "café/π.bin".encode()


def test_an_ordinary_argument_is_unchanged():
    assert sandbox.argv_bytes("-v") == b"-v"


# ---------------------------------------------------------------- NUL and argv
def test_a_nul_payload_is_still_refused_by_default():
    """Unchanged: a caller that cannot handle truncation must hear about it."""
    with pytest.raises(sandbox.ArgvNulError):
        sandbox.argv_arg(b"AAAA\x00BBBB")


def test_truncation_delivers_what_the_kernel_would():
    """Refusing outright was too strong for the case that matters. An argv-reachable strcpy
    overflow copies until the NUL anyway, so a payload whose control slot sits BEFORE the
    first NUL arrives perfectly intact -- that is exactly CVE-2001-1413, where the return
    address lands at 1048 and the sentinel's own high zero bytes are the first NUL at 1054.
    """
    payload = b"A" * 1048 + _MARKER + b"\x00\x00" + b"C" * 100
    delivered = sandbox.argv_arg(payload, truncate=True).encode("latin-1")
    assert delivered == b"A" * 1048 + _MARKER
    assert delivered[1048:1054] == _MARKER, "the control slot survives"


def test_truncation_is_not_assumed_to_be_harmless():
    """Nothing is claimed by truncating: if the control slot does not survive, the marker
    check simply fails and no primitive is reported."""
    payload = b"A" * 10 + b"\x00" + _MARKER
    assert sandbox.argv_arg(payload, truncate=True) == "A" * 10


# ---------------------------------------------------------------- the bundle must reproduce
def test_an_argv_bundle_delivers_the_input():
    """The runner emitted the stage's BASE argv -- normally empty -- so every argv-mode
    reproducer ran `./target.bin ''` and demonstrated nothing. The bundle IS the deliverable;
    one that does not reproduce is worse than no bundle."""
    sh = bundle._runner("arg", [], "SIGSEGV").decode()
    assert './target.bin "$(cat ./input.bin)"' in sh
    assert "./target.bin ''" not in sh


def test_base_arguments_come_before_the_payload():
    sh = bundle._runner("arg", ["-d", "x y"], "SIGSEGV").decode()
    assert """./target.bin -d 'x y' "$(cat ./input.bin)\"""" in sh


def test_the_other_modes_are_unchanged():
    assert "./target.bin < ./input.bin" in bundle._runner("stdin", [], "SIGSEGV").decode()
    assert "./target.bin ./input.bin" in bundle._runner("file", [], "SIGSEGV").decode()


def test_a_script_reproducer_still_wins():
    sh = bundle._runner("arg", [], "SIGSEGV", run_cmd="python3 ./exploit.py").decode()
    assert "python3 ./exploit.py" in sh and "cat ./input.bin" not in sh
