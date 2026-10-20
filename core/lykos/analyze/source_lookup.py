"""Find the archived source tree for a target.

Source is archived as a ``source-project`` artifact keyed to a binary's sha256, but the binary a
detector is analysing is often NOT that exact one, so an exact-sha-only lookup made every source
detector report "no archived source tree" for all but one target -- a real engagement symptom:

  * a multi-binary project (libtiff builds ~20 tools) keys its ONE tree to the primary executable,
    so every other entry point missed it;
  * a source archive uploaded SEPARATELY from the binaries is keyed to lykos's freshly-rebuilt
    binaries, never the operator's pre-existing ones, so none of them matched.

Resolution: the tree keyed to this target's own sha when present, else -- when the case holds
exactly one source tree -- that one. The single-tree fallback enriches every binary target without
cross-contaminating a case that legitimately holds several source projects (there the exact match
is kept and an ambiguous fallback is declined). Mirrors the ``in (None, target.sha256)`` precedent
already used in poc/capture.py.
"""
from ..db.dao import ArtifactDAO


def source_project_for(conn, target, *, kind: str = "source-project"):
    """The `kind` artifact (default: the archived source tree) that applies to `target`, or None.

    Exact `binary_sha == target.sha256` first; failing that, the case's SOLE `kind` artifact (so a
    separately-uploaded or primary-keyed tree still reaches this binary). None when the case holds
    none, or holds several and none match this target exactly (ambiguous -- decline rather than
    guess)."""
    arts = [a for a in ArtifactDAO(conn).list_by_case(target.case_id) if a.kind == kind]
    if not arts:
        return None
    exact = next((a for a in arts if (a.meta or {}).get("binary_sha") == target.sha256), None)
    if exact is not None:
        return exact
    return arts[0] if len(arts) == 1 else None
