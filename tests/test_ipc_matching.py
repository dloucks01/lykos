"""IPC channel discovery across a case's components.

This is the multi-binary capability: two programs are linked when one SENDS on a channel the
other RECEIVES on, and they name the same channel. Everything about that is a judgement --
which strings look like channel names, which direction an API implies, and whether an
ambiguous family (shm, fifo) should be treated as both.

The failure mode is a case graph full of edges that are not real: every binary on a Linux
system mentions /lib64/ld-linux-x86-64.so.2, so a matcher that treats any leading-slash string
as a channel key links every component to every other and the graph stops meaning anything.
"""
from __future__ import annotations

import pytest
from lykos.analyze.link import ipc

# ---- what counts as a channel name -------------------------------------------------------

@pytest.mark.parametrize("key", [
    "/tmp/app.sock", "/run/svc.fifo", "/myqueue", "/dev/shm/region",
    "/var/run/daemon.socket", "/a.b_c-d/e",
])
def test_a_channel_looking_literal_is_kept(key):
    assert key in ipc._scan_keys(b"\x00" + key.encode() + b"\x00")


@pytest.mark.parametrize("junk", [
    "/lib64/ld-linux-x86-64.so.2", "/usr/share/locale", "/proc/self/maps",
    "/sys/devices", "/bin/sh", "/sbin/init", "/dev/null", "/dev/urandom",
    "/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/libfoo.so.1", "/some/dir/",
])
def test_a_system_path_is_not_a_channel(junk):
    """Every binary on the system carries these. Treated as keys they link everything to
    everything, and a graph in which all components are connected says nothing at all."""
    assert junk not in ipc._scan_keys(b"\x00" + junk.encode() + b"\x00")


@pytest.mark.parametrize("junk", ["relative/path", "no-slash-at-all", "/", ""])
def test_a_non_path_is_not_a_channel(junk):
    assert junk not in ipc._scan_keys(b"\x00" + junk.encode() + b"\x00")


def test_a_shared_object_name_is_not_a_channel_wherever_it_lives():
    """`.so` anywhere in the name, not just under /lib -- a vendored library in /opt is still
    a library."""
    for s in ("/opt/vendor/libthing.so", "/opt/libthing.so.3", "/home/x/libx.so.1.2"):
        assert s not in ipc._scan_keys(b"\x00" + s.encode() + b"\x00")


def test_keys_are_deduplicated():
    blob = b"\x00/tmp/a.sock\x00padding\x00/tmp/a.sock\x00"
    assert sorted(ipc._scan_keys(blob)) == ["/tmp/a.sock"]


def test_scanning_empty_or_binary_data_yields_nothing():
    assert ipc._scan_keys(b"") == set()
    assert ipc._scan_keys(None) == set()
    assert ipc._scan_keys(bytes(range(32))) == set()


# ---- direction -----------------------------------------------------------------------------

def test_an_explicit_direction_is_honoured():
    assert ipc._is_sender({"send"}, "socket")
    assert not ipc._is_sender({"recv"}, "socket")
    assert ipc._is_receiver({"recv"}, "socket")
    assert not ipc._is_receiver({"send"}, "socket")


@pytest.mark.parametrize("family", sorted(ipc._AMBIGUOUS))
def test_an_ambiguous_family_is_both_directions(family):
    """Mapping a shared-memory region or a FIFO gives no direction: the same call both reads
    and writes. Refusing to link them would lose the channel entirely."""
    assert ipc._is_sender(set(), family)
    assert ipc._is_receiver(set(), family)


# ---- matching ------------------------------------------------------------------------------

class _T:
    def __init__(self, tid, filename):
        self.id, self.filename = tid, filename


def _profile(*, keys=(), families=None, sources=(), sinks=()):
    return {"keys": set(keys), "families": {f: set(r) for f, r in (families or {}).items()},
            "sources": list(sources), "sinks": list(sinks), "norm": set()}


def test_two_components_sharing_a_key_and_a_family_are_linked():
    targets = {"a": _T("a", "producer"), "b": _T("b", "consumer")}
    profiles = {
        "a": _profile(keys=["/tmp/q"], families={"socket": {"send"}}, sources=["recv"]),
        "b": _profile(keys=["/tmp/q"], families={"socket": {"recv"}},
                      sinks=[("CWE-78", "high", "system")]),
    }
    edges, findings = ipc.match_channels(targets, profiles)
    assert [(e["src"], e["dst"], e["family"], e["key"]) for e in edges] == \
        [("a", "b", "socket", "/tmp/q")]
    assert len(findings) == 1
    assert findings[0]["_target"] == "b", "the finding lands on the component with the sink"


def test_no_shared_key_means_no_edge():
    targets = {"a": _T("a", "x"), "b": _T("b", "y")}
    profiles = {"a": _profile(keys=["/tmp/one"], families={"socket": {"send"}}),
                "b": _profile(keys=["/tmp/two"], families={"socket": {"recv"}})}
    assert ipc.match_channels(targets, profiles) == ([], [])


def test_two_receivers_do_not_form_a_channel():
    """Both ends reading is not a channel; linking them would invent a data flow."""
    targets = {"a": _T("a", "x"), "b": _T("b", "y")}
    profiles = {"a": _profile(keys=["/tmp/q"], families={"socket": {"recv"}}),
                "b": _profile(keys=["/tmp/q"], families={"socket": {"recv"}})}
    assert ipc.match_channels(targets, profiles)[0] == []


def test_a_shared_key_on_different_families_is_not_a_channel():
    targets = {"a": _T("a", "x"), "b": _T("b", "y")}
    profiles = {"a": _profile(keys=["/tmp/q"], families={"socket": {"send"}}),
                "b": _profile(keys=["/tmp/q"], families={"msgqueue": {"recv"}})}
    assert ipc.match_channels(targets, profiles)[0] == []


def test_an_edge_without_a_source_and_a_sink_is_not_a_finding():
    """A channel between two components is structure. It only becomes a candidate finding
    when untrusted input on one end can reach a dangerous sink on the other."""
    targets = {"a": _T("a", "x"), "b": _T("b", "y")}
    profiles = {"a": _profile(keys=["/tmp/q"], families={"socket": {"send"}}),
                "b": _profile(keys=["/tmp/q"], families={"socket": {"recv"}},
                              sinks=[("CWE-78", "high", "system")])}
    edges, findings = ipc.match_channels(targets, profiles)
    assert edges and not findings, "a finding was filed with no untrusted source"


def test_the_most_severe_sink_is_the_one_reported():
    targets = {"a": _T("a", "x"), "b": _T("b", "y")}
    profiles = {"a": _profile(keys=["/tmp/q"], families={"socket": {"send"}},
                              sources=["recv"]),
                "b": _profile(keys=["/tmp/q"], families={"socket": {"recv"}},
                              sinks=[("CWE-120", "low", "strcpy"),
                                     ("CWE-78", "high", "system")])}
    _edges, findings = ipc.match_channels(targets, profiles)
    assert len(findings) == 1 and findings[0]["cwe"] == "CWE-78"


def test_a_component_is_never_linked_to_itself():
    targets = {"a": _T("a", "x")}
    profiles = {"a": _profile(keys=["/tmp/q"],
                              families={"socket": {"send", "recv"}}, sources=["recv"])}
    assert ipc.match_channels(targets, profiles)[0] == []


def test_the_same_pair_is_not_emitted_twice_for_one_key():
    targets = {"a": _T("a", "x"), "b": _T("b", "y")}
    profiles = {"a": _profile(keys=["/tmp/q"], families={"socket": {"send", "recv"}}),
                "b": _profile(keys=["/tmp/q"], families={"socket": {"send", "recv"}})}
    edges, _f = ipc.match_channels(targets, profiles)
    assert len({(e["src"], e["dst"], e["family"], e["key"]) for e in edges}) == len(edges)


def test_matching_is_deterministic_across_runs():
    """The case graph is shown to an operator and diffed between runs; edge order that
    wobbles with dict ordering makes a stable graph look like it changed."""
    targets = {t: _T(t, t) for t in ("a", "b", "c")}
    profiles = {t: _profile(keys=["/tmp/q"], families={"socket": {"send", "recv"}},
                            sources=["recv"], sinks=[("CWE-78", "high", "system")])
                for t in targets}
    first = ipc.match_channels(targets, profiles)[0]
    for _ in range(5):
        assert ipc.match_channels(targets, profiles)[0] == first
