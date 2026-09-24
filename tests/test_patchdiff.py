"""Binary patch-diff (1-day): localise a security fix as the function whose body changed between a
vulnerable and a patched build, address/layout-independently."""
from lykos.analyze import patchdiff


def _fn(name, mnems, callees=(), edges=1):
    # one block carrying the given mnemonics; callees as call edges
    ins = [{"text": m} for m in mnems]
    return {"name": name, "addr": "0x1000",
            "cfg": {"blocks": [{"instructions": ins}], "edges": edges},
            "calls": [{"dst_name": c} for c in callees]}


def test_diff_localises_the_changed_function():
    old = [_fn("parse", ["mov", "lea", "call"], callees=["strcpy"]),
           _fn("helper", ["mov", "ret"]),
           _fn("main", ["push", "call", "ret"], callees=["parse", "helper"])]
    new = [_fn("parse", ["mov", "lea", "mov", "call"], callees=["strncpy"]),   # the fix
           _fn("helper", ["mov", "ret"]),                                       # untouched
           _fn("main", ["push", "call", "ret"], callees=["parse", "helper"])]
    d = patchdiff.diff(old, new)
    assert d["symbols"] is True
    assert [c["name"] for c in d["changed"]] == ["parse"], "only parse changed"
    c = d["changed"][0]
    assert c["new_callees"] == ["strncpy"] and c["dropped_callees"] == ["strcpy"]
    assert d["unchanged"] == 2


def test_identical_builds_show_no_change():
    fns = [_fn("a", ["mov", "ret"]), _fn("b", ["push", "call", "ret"], callees=["a"])]
    d = patchdiff.diff(fns, list(fns))
    assert d["changed"] == [] and d["unchanged"] == 2


def test_recompilation_noise_is_not_a_change():
    # same body, different ADDRESS -> same fingerprint (address-independent), so unchanged
    a = [_fn("f", ["mov", "add", "ret"], callees=["g"])]
    b = [dict(_fn("f", ["mov", "add", "ret"], callees=["g"]), addr="0x9999")]
    assert patchdiff.diff(a, b)["changed"] == []


def test_is_patched_classifies_a_target_function():
    vuln = _fn("parse", ["mov", "call"], callees=["strcpy"])
    patched = _fn("parse", ["mov", "mov", "call"], callees=["strncpy"])
    assert patchdiff.is_patched([patched], vuln, patched) == "patched"
    assert patchdiff.is_patched([vuln], vuln, patched) == "vulnerable"
    assert patchdiff.is_patched([_fn("other", ["ret"])], vuln, patched) is None
