"""The interactive console's command construction and framing helpers.

`test_console.py` drives one happy-path session end to end; the pieces it is built from --
how a cross-architecture target is launched, what isolation tier is claimed, and how malformed
client traffic is handled -- had no test. The isolation string is what the UI shows the
operator, so a wrong one is a claim about containment that nothing checks.
"""
from __future__ import annotations

import json

import pytest
from lykos.analyze.dynamic import sandbox
from lykos.api import console


def test_a_native_target_is_launched_directly_with_its_arguments():
    cmd, iso, emu = console._build_cmd("/bin/ls", ["-l", "/tmp"], None, None, None)
    assert emu is None
    assert "/bin/ls" in cmd and cmd[-2:] == ["-l", "/tmp"]
    assert "qemu" not in iso


def test_the_same_architecture_as_the_host_is_not_emulated():
    """Routing a native target through qemu would be slower and would change its behaviour
    under the analyst's hands for no reason."""
    host = sandbox.host_arch()
    _cmd, iso, emu = console._build_cmd("/bin/ls", [], host, None, None)
    assert emu is None and "qemu" not in iso


def test_a_cross_architecture_target_is_launched_under_its_emulator():
    if not sandbox._qemu_for("aarch64"):
        pytest.skip("no qemu-aarch64 on this host")
    cmd, iso, emu = console._build_cmd("/tmp/t.bin", ["-v"], "aarch64", None, None)
    assert emu and "aarch64" in emu
    assert cmd.index(emu) < cmd.index("/tmp/t.bin"), "the emulator has to come first"
    assert "qemu" in iso, "the operator is told they are looking at an emulated process"


def test_the_isolation_string_names_the_tier_actually_used():
    """It is shown to the operator as the containment claim. `bwrap+netns` where bubblewrap
    did not run would be a false statement about where hostile code is executing."""
    _cmd, iso, _emu = console._build_cmd("/bin/ls", [], None, None, None)
    assert iso.startswith("bwrap+netns" if sandbox._bwrap_usable() else "rlimits-only")


def test_the_target_directory_is_bound_past_the_tmpfs_when_sandboxed():
    """The exe is staged under /tmp, which the sandbox masks with a tmpfs -- without binding
    its directory back in, the binary simply is not there inside the sandbox."""
    if not sandbox._bwrap_usable():
        pytest.skip("no bubblewrap on this host")
    from pathlib import Path
    cmd, _iso, _emu = console._build_cmd("/bin/ls", [], None, None, None)
    assert "--ro-bind" in cmd
    i = len(cmd) - 1 - cmd[::-1].index("--ro-bind")
    # the SYMLINK is resolved first: /bin/ls is a link on most distributions, and binding the
    # link's directory leaves the real binary outside the sandbox
    want = str(Path("/bin/ls").resolve().parent)
    assert cmd[i + 1] == cmd[i + 2] == want, "the exe's own directory is bound at itself"


# ---- client traffic ----------------------------------------------------------------------

def test_a_client_message_is_parsed_as_json():
    assert console._parse(b'{"t":"in","b64":"QQ=="}') == {"t": "in", "b64": "QQ=="}


@pytest.mark.parametrize("junk", [b"", b"not json", b"{", b"\xff\xfe\x00", b"[1,2"])
def test_malformed_client_traffic_is_none_rather_than_an_exception(junk):
    """This arrives over a WebSocket from a browser; a parse error that escapes takes the
    session down and the operator loses the shell they were in the middle of using."""
    assert console._parse(junk) is None


def test_valid_json_that_is_not_an_object_still_parses_without_raising():
    assert console._parse(b'"a string"') == "a string"
    assert console._parse(b"123") == 123


def test_sending_on_a_closed_socket_is_swallowed():
    """The peer going away is the normal end of a session, not an error to propagate."""
    class Closed:
        def sendall(self, _b):
            raise OSError("broken pipe")
    console._send(Closed(), {"t": "out"})          # must not raise


def test_a_sent_object_goes_out_as_one_json_text_frame():
    sent = []

    class Sock:
        def sendall(self, b):
            sent.append(b)

    console._send(Sock(), {"t": "out", "b64": "QQ=="})
    assert len(sent) == 1
    frame = sent[0]
    assert frame[0] == 0x81, "a text frame, so the browser reads it as a string"
    body = frame[2:] if frame[1] < 126 else frame[4:]
    assert json.loads(body.decode()) == {"t": "out", "b64": "QQ=="}


def test_the_session_has_a_wall_clock_ceiling():
    """A console left open holds a live process under the analyst's own account."""
    assert console._HARD_CAP > 0
    assert console._HARD_CAP <= 3600
