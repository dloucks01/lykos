"""Shared environment gates for tests whose *exercise* depends on the host's runtime.

A capability test that needs a specific runtime the host does not provide -- a glibc whose heap the
classic leak/FSOP/tcache chains target, a per-guest afl-qemu-trace, a SystemZ-capable RE backend --
is SKIPPED with a precise reason rather than failed, so the suite is honest on any host while still
exercising the capability where it can run. These are NOT blanket xfails: on a matching environment
the test runs and must pass. Importable because tests/ has no __init__.py (pytest prepend mode puts
it on sys.path).
"""
import os
import shutil

import pytest


def host_glibc():
    """(major, minor) of the host's glibc, or (0, 0) when it cannot be read."""
    try:
        return tuple(int(x) for x in
                     os.confstr("CS_GNU_LIBC_VERSION").split()[-1].split(".")[:2])
    except Exception:                                    # noqa: BLE001 -- unknown host libc
        return (0, 0)


_GLIBC = ".".join(str(x) for x in host_glibc())

# The classic libc-leak / FSOP / House-of-* / tcache-stashing chains are validated against the glibc
# <= 2.42 heap and file-structure layout. glibc 2.43 hardened the tcache (size caps, safe-linking,
# key-clear) and moved structure/gadget offsets (e.g. setcontext's register load) enough that the
# bin-head / tcache leak primitive no longer discloses a libc pointer and the FSOP cells no longer
# land -- so the chain cannot start here. On an OLDER-glibc target (what an air-gapped box typically
# analyses, selected at run time from the libc DB) these run; on this build host they skip.
glibc_hardened_heap = pytest.mark.skipif(
    host_glibc() > (2, 42),
    reason=f"classic libc-leak/FSOP/tcache chain is validated against glibc <= 2.42; this host's "
           f"glibc {_GLIBC} hardened the heap (tcache size caps / safe-linking / key-clear) so the "
           f"bin-head leak primitive the chain starts from does not land -- it runs where the "
           f"analysed target links an older glibc, selected at run time from the libc DB")

# setcontext's register-load tail changed shape in glibc 2.43: its continuation no longer ends in
# the `mov rcx,[rdx+..]; push rcx` that find_setcontext reads, so the pushed-RIP offset (rip_at)
# is absent and the setcontext *finisher* is unavailable here. The pipeline falls through to the
# system/cat route (that fall-through is covered by test_cat_plan_wins_*), but tests that assert
# the setcontext route itself -- its gadget offsets or that it wins outright -- are ABI/version
# bound to glibc <= 2.42 and skip where setcontext looks different.
glibc_setcontext_layout = pytest.mark.skipif(
    host_glibc() > (2, 42),
    reason=f"setcontext's register-load/push-RIP layout this asserts is the glibc <= 2.42 shape; "
           f"this host's glibc {_GLIBC} moved it, so the setcontext finisher is unavailable here "
           f"(the pipeline falls through to system/cat) -- exercised on an older-glibc target")

# The SystemZ (s390x) static recovery is validated against rizin proper: rizin leaves the xref DB
# empty on s390 but disassembles it correctly, so call edges are harvested from the instruction
# stream AND the static libc imports (read, ...) are named. The r2/radare2 fallback recovers the
# call graph but does not attach the static `read` import name to the vuln edge here. The air-gap
# bundle ships rizin, so this runs there; on a host with only r2/radare2 it skips.
needs_rizin = pytest.mark.skipif(
    shutil.which("rizin") is None,
    reason="SystemZ call-edge/import naming is validated against rizin; only r2/radare2 is present "
           "here, which recovers the s390 call graph but does not name the static `read` import")


def find_old_glibc(max_ver=(2, 42), min_ver=(2, 36)):
    """Locate the NEWEST glibc in [min_ver, max_ver] on this host as a (version, libc.so.6, ld.so)
    triple -- the OLD-GLIBC CONFIRMATION LANE. The classic heap/FSOP/tcache chains skip on a
    hardened (>=2.43) build host (`glibc_hardened_heap`); this finds a real pre-hardening glibc to
    CONFIRM them end-to-end instead of only asserting their structure. Scans $LYKOS_OLD_GLIBC_DIR
    (a directory holding both files) and the podman/docker container overlay stores. Newest-in-range
    is chosen so a target compiled against the host's modern glibc still loads (symbol-version
    compatibility) while the runtime heap is the unhardened one the technique targets. Returns None
    (-> the lane skips cleanly) on a host with no such glibc. Cached."""
    import glob
    import re
    cache = getattr(find_old_glibc, "_cache", {})
    key = (max_ver, min_ver)
    if key in cache:
        return cache[key]
    roots = []
    env = os.environ.get("LYKOS_OLD_GLIBC_DIR")
    if env:
        roots.append(env)
    roots += glob.glob(os.path.expanduser("~/.local/share/containers/storage/overlay/*/diff"))
    roots += glob.glob("/var/lib/docker/overlay2/*/diff")
    cands = []
    for root in roots:
        for libc in (glob.glob(f"{root}/lib/x86_64-linux-gnu/libc.so.6")
                     + glob.glob(f"{root}/lib/libc.so.6") + glob.glob(f"{root}/libc.so.6")):
            ld = next((c for c in (os.path.join(os.path.dirname(libc), "ld-linux-x86-64.so.2"),
                                   os.path.join(root, "lib64/ld-linux-x86-64.so.2"),
                                   os.path.join(root, "lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"))
                       if os.path.exists(c)), None)
            if not ld:
                continue
            try:
                with open(libc, "rb") as f:
                    m = re.search(rb"release version (\d+)\.(\d+)", f.read())
            except OSError:
                m = None
            if not m:
                continue
            ver = (int(m.group(1)), int(m.group(2)))
            if min_ver <= ver <= max_ver:
                cands.append((ver, libc, ld))
    result = max(cands, default=None)                    # newest in range
    cache[key] = result
    find_old_glibc._cache = cache
    return result
