"""`lifecycle_scan` stage — UAF/double-free (static gap 3) over the case source."""
from __future__ import annotations
import io, os, tarfile
from ..db.dao import FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from .source_lookup import source_project_for
from . import lifecycle
LIFECYCLE_STAGE="lifecycle_scan"; TOOL="lykos.lifecycle"; TOOL_VERSION="1"
_EXCL=("third-party","third_party","external","/test/","/tests/","/_")
def _root(ctx,target):
    proj=source_project_for(ctx.conn,target)
    if proj is None: return None
    r=ctx.scratch()/"lifecycle-src"
    if not r.exists():
        r.mkdir(parents=True,exist_ok=True)
        try:
            with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),mode="r:gz") as tf:
                for m in tf.getmembers():
                    if m.isfile() and not m.name.startswith("/") and ".." not in m.name: tf.extract(m,r)
        except Exception:                            # noqa: BLE001 -- no source tree: decline
            import logging
            logging.getLogger(__name__).warning("source archive could not be unpacked", exc_info=True)
            return None
    return r
def lifecycle_stage(ctx)->dict:
    target=TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None: raise ValueError("lifecycle_scan requires a target_id")
    root=_root(ctx,target)
    if root is None: return {"metrics":{"lifecycle_scan":"no source project"}}
    fd=FindingDAO(ctx.conn); n=0
    for dp,_d,fs in os.walk(str(root)):
        for fn in fs:
            if not fn.endswith(".c"): continue
            p=os.path.join(dp,fn)
            if any(x in p.replace(os.sep,"/") for x in _EXCL): continue
            try: src=open(p,errors="ignore").read()
            except OSError: continue
            rel=os.path.relpath(p,str(root))
            for b in lifecycle.find_lifecycle_bugs(src):
                cwe="CWE-416" if b.kind=="use-after-free" else "CWE-415"
                fd.upsert(target.id,target.case_id,{"cwe":cwe,"severity":"high","state":"candidate",
                    "detector":"lifecycle","stage":LIFECYCLE_STAGE,
                    "title":f"{b.kind}: '{b.ptr}' in {b.function}()",
                    "dedup_key":f"lifecycle:{cwe}:{rel}:{b.function}:{b.ptr}:{b.bad_line}",
                    "evidence":[{"channel":"source","detail":f"{rel}: {b.function}() {b.kind} of '{b.ptr}' "
                                 f"(freed line {b.free_line}, used/again line {b.bad_line}): {b.hint}"}]})
                n+=1
    return {"metrics":{"lifecycle_findings":n}}
register_stage(LIFECYCLE_STAGE,lifecycle_stage,resource_class="quick",tool=TOOL,tool_version=TOOL_VERSION,timeout=300)
def enqueue_lifecycle_scan(queue,target,*,force=True):
    return queue.enqueue(target.case_id,LIFECYCLE_STAGE,target_id=target.id,input_hashes=[target.sha256],
                         tool=TOOL,tool_version=TOOL_VERSION,resource_class="quick",force=force)
