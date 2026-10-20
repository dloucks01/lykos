"""Shared environment gates for tests whose *exercise* depends on the host's runtime.

A capability test that needs a specific runtime the host does not provide -- a glibc whose heap the
classic leak/FSOP/tcache chains target, a per-guest afl-qemu-trace, a SystemZ-capable RE backend --
is SKIPPED with a precise reason rather than failed, so the suite is honest on any host while still
exercising the capability where it can run. These are NOT blanket xfails: on a matching environment
the test runs and must pass. Importable because tests/ has no __init__.py (pytest prepend mode puts
it on sys.path).
"""
import os

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
