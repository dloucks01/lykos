# ExportAnalysis.py -- Ghidra headless post-script (Jython / Python 2).
# Per function: decompiled C, CFG (basic blocks + edges), P-Code IR per instruction, and
# call sites (call graph + dangerous-API sinks). Program level: imported functions and
# defined strings with their xref sites. Writes JSON to scriptArgs[0].
# @category lykos
import json

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()          # noqa: F821
outpath = args[0] if args else "analysis.json"

prog = currentProgram           # noqa: F821
monitor = ConsoleTaskMonitor()
listing = prog.getListing()
fm = prog.getFunctionManager()
refmgr = prog.getReferenceManager()
symtab = prog.getSymbolTable()
bbm = BasicBlockModel(prog)
deco = DecompInterface()
deco.openProgram(prog)


def _vn(v):
    if v is None:
        return "-"
    # resolve register varnodes to names (e.g. reg:RDI:8) so taint matches ABI registers
    try:
        reg = prog.getRegister(v.getAddress(), v.getSize())
        if reg is not None:
            return "reg:%s:%d" % (reg.getName(), v.getSize())
    except Exception:
        pass
    try:
        space = v.getAddress().getAddressSpace().getName()
    except Exception:
        space = "?"
    return "%s:0x%x:%d" % (space, v.getOffset() & 0xffffffffffffffff, v.getSize())


def _pcode(op):
    ins = " ".join(_vn(x) for x in op.getInputs())
    s = op.getMnemonic()
    if ins:
        s += " " + ins
    out = op.getOutput()
    if out is not None:
        s += " -> " + _vn(out)
    return s


def _cfg(func):
    blocks = []
    edges = 0
    it = bbm.getCodeBlocksContaining(func.getBody(), monitor)
    while it.hasNext():
        b = it.next()
        insns = []
        ins_it = listing.getInstructions(b, True)
        while ins_it.hasNext():
            i = ins_it.next()
            pcs = []
            try:
                for op in i.getPcode():
                    pcs.append(_pcode(op))
            except Exception:
                pass
            insns.append({"addr": "0x%x" % i.getAddress().getOffset(),
                          "text": i.toString(), "pcode": pcs})
        succ = []
        d_it = b.getDestinations(monitor)
        while d_it.hasNext():
            db = d_it.next().getDestinationBlock()
            if db is not None:
                succ.append("0x%x" % db.getFirstStartAddress().getOffset())
        edges += len(succ)
        blocks.append({"addr": "0x%x" % b.getFirstStartAddress().getOffset(),
                       "instructions": insns, "succ": succ})
    return blocks, edges


def _calls(func):
    out = []
    ins_it = listing.getInstructions(func.getBody(), True)
    while ins_it.hasNext():
        i = ins_it.next()
        ft = i.getFlowType()
        if ft is None or not ft.isCall():
            continue
        site = "0x%x" % i.getAddress().getOffset()
        for ref in i.getReferencesFrom():
            rt = ref.getReferenceType()
            if rt is None or not rt.isCall():
                continue
            to = ref.getToAddress()
            tf = fm.getFunctionAt(to)
            name = None
            external = False
            if tf is not None:
                name = tf.getName()
                external = bool(tf.isExternal() or tf.isThunk())
            else:
                sym = symtab.getPrimarySymbol(to)
                if sym is not None:
                    name = sym.getName()
            out.append({"site_addr": site, "dst_addr": "0x%x" % to.getOffset(),
                        "dst_name": name, "external": external})
    return out


def _strings(limit=5000):
    out = []
    di = listing.getDefinedData(True)
    n = 0
    while di.hasNext() and n < limit:
        d = di.next()
        dt = d.getDataType()
        if dt is None or "string" not in dt.getName().lower():
            continue
        val = d.getValue()
        s = val.toString() if val is not None else ""
        addr = d.getAddress()
        xrefs = []
        rit = refmgr.getReferencesTo(addr)
        while rit.hasNext():
            xrefs.append("0x%x" % rit.next().getFromAddress().getOffset())
        out.append({"addr": "0x%x" % addr.getOffset(), "value": s[:200], "xrefs": xrefs})
        n += 1
    return out


functions = []
for f in fm.getFunctions(True):
    entry = f.getEntryPoint()
    body = f.getBody()
    size = body.getNumAddresses() if body is not None else 0
    code = ""
    try:
        res = deco.decompileFunction(f, 30, monitor)
        if res is not None and res.decompileCompleted():
            df = res.getDecompiledFunction()
            if df is not None:
                code = df.getC()
    except Exception:
        code = ""
    try:
        blocks, edges = _cfg(f)
    except Exception:
        blocks, edges = [], 0
    try:
        calls = _calls(f)
    except Exception:
        calls = []
    functions.append({
        "addr": "0x%x" % entry.getOffset(),
        "name": f.getName(),
        "size": int(size),
        "decompiled": code,
        "blocks": len(blocks),
        "edges": edges,
        "cfg": {"blocks": blocks},
        "calls": calls,
    })

imports = []
ext_it = fm.getExternalFunctions()
while ext_it.hasNext():
    imports.append(ext_it.next().getName())

meta = {
    "format": prog.getExecutableFormat(),
    "language": str(prog.getLanguageID()),
    "compiler": str(prog.getCompilerSpec().getCompilerSpecID()),
    "image_base": "0x%x" % prog.getImageBase().getOffset(),
    "function_count": len(functions),
    "imports": imports,
}

fh = open(outpath, "w")
try:
    json.dump({"program": meta, "functions": functions, "strings": _strings()}, fh)
finally:
    fh.close()

print("lykos: exported %d functions (CFG + P-Code + calls) and strings" % len(functions))
