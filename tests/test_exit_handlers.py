"""The exit() handler route: located from the libc's bytes, and reported as a CONDITIONAL verdict.

`exit()` walks a registered list of handlers and calls each -- the one control-flow endpoint the
engine did not model, since every other route it has lands through stdio (FSOP) or a saved return
address. A write-what-where that reaches the handler list is a fourth way to turn a write into a
call, and the one left when the FILE structs are unreachable.

It is CONDITIONAL, and that is the whole point of the verdict: every handler flavor stores its
function pointer under glibc's pointer guard, so the route is not an overwrite-with-an-address --
it needs the guard, which the paired arbitrary read recovers. These tests pin down that the
location is read from the bytes (not a version table), that the guard requirement is measured, and
that the verdict says UNKNOWN rather than guessing when handed no libc -- the same discipline as
the large-bin and tcache-stash verdicts in test_largebin.py.
"""
import glob

import pytest
from lykos.analyze.poc import aaheg, rop

_SYS_LIBC = next(iter(glob.glob("/usr/lib/x86_64-linux-gnu/libc.so.6")
                      + glob.glob("/lib/x86_64-linux-gnu/libc.so.6")), None)
_OLD_LIBC = next(iter(glob.glob("/home/kali/.cache/qqprobe/glibc/libc.so.6")), None)


def test_exit_funcs_is_located_from_exits_own_body():
    """`exit` is exported and loads its handler list with a RIP-relative `lea`, so the list's
    address is recoverable exactly, anchored on the symbol -- no backend, no version table."""
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    t = rop.exit_handlers_targets(open(_SYS_LIBC, "rb").read())
    assert t and t["exit_funcs"] > t["exit"] > 0
    # the struct layout a write-what-where has to target
    assert t["entry_stride"] == 0x20 and t["fn_field"] == 0x8
    assert t["guarded"] is True and t["demangle_sites"] > 0


def test_the_address_is_read_from_bytes_not_hardcoded():
    """A cross-libc differential: two glibcs put __exit_funcs at different offsets, and the locate
    returns each libc's own -- which it could not do from a constant."""
    if not (_SYS_LIBC and _OLD_LIBC):
        pytest.skip("need both the system libc and the cached 2.35")
    a = rop.exit_handlers_targets(open(_SYS_LIBC, "rb").read())["exit_funcs"]
    b = rop.exit_handlers_targets(open(_OLD_LIBC, "rb").read())["exit_funcs"]
    assert a and b and a != b, (hex(a), hex(b))


def test_guard_demangle_sites_counts_the_real_demangle():
    """The precondition is measured, not assumed: the count is the number of times the libc applies
    `ror 0x11; xor fs:0x30` to a guarded pointer. Every modern glibc returns a large positive
    count, which is exactly what makes the guard a hard precondition rather than a formality."""
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    n = rop.guard_demangle_sites(open(_SYS_LIBC, "rb").read())
    assert n > 0
    assert rop.guard_demangle_sites(b"") == 0
    # the pattern is specific: random bytes do not read as a demangle site
    assert rop.guard_demangle_sites(b"\x90" * 4096) == 0


def test_the_locate_is_empty_for_a_non_libc():
    assert rop.exit_handlers_targets(b"") == {}
    assert rop.exit_handlers_targets(b"\x7fELF" + b"\x00" * 128) == {}


def test_the_verdict_is_unknown_without_libc_bytes():
    """UNKNOWN, not the historical answer -- the discipline the large-bin verdict established."""
    v = aaheg.exit_handlers_verdict(aaheg.Env())
    assert v["ok"] is None
    assert "UNKNOWN" in v["reason"]
    assert not v["located"]


def test_the_verdict_locates_and_reports_the_guard_precondition():
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    v = aaheg.exit_handlers_verdict(aaheg.Env(libc_data=open(_SYS_LIBC, "rb").read()))
    assert v["ok"] is True and v["located"] is True
    assert v["guarded"] is True
    # the conditional-ness has to be stated: a guarded route needs the paired read, and the
    # verdict must say so rather than implying a bare overwrite
    assert "guard" in v["precondition"].lower() and "read" in v["precondition"].lower()
    assert "exit()" in v["shape"]


def test_plan_exploit_surfaces_the_route_only_for_a_control_flow_goal():
    """It is a write->CALL consumer, a peer of the FSOP helpers, so it belongs to the control-flow
    goal -- not to an arbitrary-write or arbitrary-alloc goal, which have not reached the call yet."""
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    env = aaheg.Env(libc_data=open(_SYS_LIBC, "rb").read())
    v = aaheg.Vuln("heap_overflow", size=0x28)

    cf = aaheg.plan_exploit(v, aaheg.Goal("control_flow"), env)
    consumers = {c["consumer"] for c in cf.get("write_consumers", [])}
    assert "exit_handlers" in consumers, cf.get("write_consumers")

    aw = aaheg.plan_exploit(v, aaheg.Goal("arbitrary_write"), env)
    assert not aw.get("write_consumers"), "the route is not a write PRODUCER"


def test_the_verdict_follows_the_libc_like_the_large_bin_one():
    """Both cached libcs guard, so the measured answer is the same on both -- but it is READ from
    each, and the located address differs, which is what proves it is not a constant dressed up as
    a measurement."""
    if not (_SYS_LIBC and _OLD_LIBC):
        pytest.skip("need both libcs")
    new = aaheg.exit_handlers_verdict(aaheg.Env(libc_data=open(_SYS_LIBC, "rb").read()))
    old = aaheg.exit_handlers_verdict(aaheg.Env(libc_data=open(_OLD_LIBC, "rb").read()))
    assert new["guarded"] is old["guarded"] is True
    assert new["exit_funcs"] != old["exit_funcs"]
