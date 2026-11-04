"""Missing-sibling-validation detector: a guard call most siblings in a handler family make but one
omits (the copy-paste variant bug, e.g. CVE-2026-26955's missing is_within_surface)."""
from lykos.analyze.sibling_guard import find_missing_sibling_guards, _family_key


def test_flags_the_sibling_that_omits_the_majority_guard():
    src = """
    static int h_one(ctx* c, cmd* m) { if (!validate(c, m)) return -1; work(c, m); return 0; }
    static int h_two(ctx* c, cmd* m) { if (!validate(c, m)) return -1; work(c, m); return 0; }
    static int h_three(ctx* c, cmd* m) { if (!validate(c, m)) return -1; work(c, m); return 0; }
    static int h_four(ctx* c, cmd* m) { work(c, m); return 0; }   /* MISSING validate */
    """
    hits = find_missing_sibling_guards(src)
    assert any(h["fn"] == "h_four" and h["missing"] == "validate" for h in hits)
    # the ones that DO guard are not flagged for it
    assert not any(h["fn"] in ("h_one", "h_two", "h_three") and h["missing"] == "validate"
                   for h in hits)


def test_silent_when_all_siblings_guard():
    src = """
    static int h_one(ctx* c, cmd* m) { if (!validate(c, m)) return -1; return 0; }
    static int h_two(ctx* c, cmd* m) { if (!validate(c, m)) return -1; return 0; }
    static int h_three(ctx* c, cmd* m) { if (!validate(c, m)) return -1; return 0; }
    """
    assert find_missing_sibling_guards(src) == []


def test_silent_on_minority_guard_noise():
    # validate used by only 1 of 4 -> below the 0.5 majority threshold -> not a real asymmetry.
    src = """
    static int h_one(ctx* c, cmd* m) { if (!validate(c, m)) return -1; return 0; }
    static int h_two(ctx* c, cmd* m) { return 0; }
    static int h_three(ctx* c, cmd* m) { return 0; }
    static int h_four(ctx* c, cmd* m) { return 0; }
    """
    assert find_missing_sibling_guards(src) == []


def test_small_family_ignored():
    src = """
    static int h_one(ctx* c) { if (!validate(c)) return -1; return 0; }
    static int h_two(ctx* c) { return 0; }
    """
    assert find_missing_sibling_guards(src) == []


def test_family_key():
    assert _family_key("gdi_SurfaceCommand_ClearCodec") == "gdi_SurfaceCommand"
    assert _family_key("rdpgfx_recv_wire_to_surface_2_pdu") == "rdpgfx_recv_wire_to_surface_2"


def test_skips_trivial_wrapper():
    # a 1-line delegator must not be flagged for "omitting" a guard its siblings have.
    src = """
    static int h_one(ctx* c, cmd* m) { if (!validate(c, m)) return -1; work(c, m); return 0; }
    static int h_two(ctx* c, cmd* m) { if (!validate(c, m)) return -1; work(c, m); return 0; }
    static int h_three(ctx* c, cmd* m) { if (!validate(c, m)) return -1; work(c, m); return 0; }
    static int h_four(ctx* c, cmd* m) { return h_four_ex(c, m, FALSE); }
    """
    hits = find_missing_sibling_guards(src)
    assert not any(h["fn"] == "h_four" for h in hits)
