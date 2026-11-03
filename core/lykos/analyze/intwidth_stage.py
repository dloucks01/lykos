"""`intwidth_scan` stage — integer signedness/width misuse (static gap 4) over the case source."""
from __future__ import annotations
import io, os, tarfile
from ..db.dao import FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from .source_lookup import source_project_for
from . import intwidth
INTWIDTH_STAGE="intwidth_scan"; TOOL="lykos.intwidth"; TOOL_VERSION="1"
_EXCL=("third-party","third_party","external","/test/","/tests/","/_")
def _root(ctx,target):
    proj=source_project_for(ctx.conn,target)
    if proj is None: return None
    r=ctx.scratch()/"intwidth-src"
    if not r.exists():
        r.mkdir(parents=True,exist_ok=True)
        try:
            with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),mode="r:gz") as tf:
                for m in tf.getmembers():
                    if m.isfile() and not m.name.startswith("/") and ".." not in m.name: tf.extract(m,r)
        except Exception: return None
    return r
def intwidth_stage(ctx)->dict:
    target=TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None: raise ValueError("intwidth_scan requires a target_id")
    root=_root(ctx,target)
    if root is None: return {"metrics":{"intwidth_scan":"no source project"}}
    fd=FindingDAO(ctx.conn); n=0
    for dp,_d,fs in os.walk(str(root)):
        for fn in fs:
            if not fn.endswith(".c"): continue
            p=os.path.join(dp,fn)
            if any(x in p.replace(os.sep,"/") for x in _EXCL): continue
            try: src=open(p,errors="ignore").read()
            except OSError: continue
            rel=os.path.relpath(p,str(root))
            for b in intwidth.find_intwidth_bugs(src):
                fd.upsert(target.id,target.case_id,{"cwe":b.cwe,"severity":"medium","state":"candidate",
                    "detector":"intwidth","stage":INTWIDTH_STAGE,
                    "title":f"{b.kind}: wire value '{b.var}' in {b.function}()",
                    "dedup_key":f"intwidth:{b.cwe}:{rel}:{b.function}:{b.var}:{b.kind}",
                    "evidence":[{"channel":"source","detail":f"{rel}: {b.function}() {b.kind} on wire '{b.var}': {b.hint}"}]})
                n+=1
    return {"metrics":{"intwidth_findings":n}}
register_stage(INTWIDTH_STAGE,intwidth_stage,resource_class="quick",tool=TOOL,tool_version=TOOL_VERSION,timeout=300)
def enqueue_intwidth_scan(queue,target,*,force=True):
    return queue.enqueue(target.case_id,INTWIDTH_STAGE,target_id=target.id,input_hashes=[target.sha256],
                         tool=TOOL,tool_version=TOOL_VERSION,resource_class="quick",force=force)
