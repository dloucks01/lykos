// ExportAnalysis.java -- Ghidra headless post-script (Java; works on all Ghidra versions,
// including 11.3+/12 which dropped bundled Jython for PyGhidra).
// Per function: decompiled C, CFG (basic blocks + edges), P-Code IR per instruction, and
// call sites. Program level: imported functions and defined strings with xref sites.
// Writes JSON to the first script argument. @category lykos
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class ExportAnalysis extends GhidraScript {

    private Listing listing;
    private FunctionManager fm;
    private ReferenceManager refmgr;
    private SymbolTable symtab;
    private BasicBlockModel bbm;

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }

    private static String hex(long v) { return "0x" + Long.toHexString(v); }

    private String vn(Varnode v) {
        if (v == null) return "-";
        try {
            Register reg = currentProgram.getRegister(v.getAddress(), v.getSize());
            if (reg != null) return "reg:" + reg.getName() + ":" + v.getSize();
        } catch (Exception e) { /* fall through */ }
        String space;
        try { space = v.getAddress().getAddressSpace().getName(); }
        catch (Exception e) { space = "?"; }
        return space + ":" + hex(v.getOffset()) + ":" + v.getSize();
    }

    private String pcode(PcodeOp op) {
        StringBuilder s = new StringBuilder(op.getMnemonic());
        Varnode[] ins = op.getInputs();
        for (int i = 0; i < ins.length; i++) s.append(" ").append(vn(ins[i]));
        Varnode out = op.getOutput();
        if (out != null) s.append(" -> ").append(vn(out));
        return s.toString();
    }

    // returns {blocksJson, edgeCount, blockCount}
    private Object[] cfg(Function f) throws Exception {
        StringBuilder blocks = new StringBuilder("[");
        int edges = 0, nblocks = 0;
        CodeBlockIterator it = bbm.getCodeBlocksContaining(f.getBody(), monitor);
        boolean firstBlk = true;
        while (it.hasNext()) {
            CodeBlock b = it.next();
            if (!firstBlk) blocks.append(","); firstBlk = false;
            StringBuilder insns = new StringBuilder("[");
            InstructionIterator ii = listing.getInstructions(b, true);
            boolean firstIns = true;
            while (ii.hasNext()) {
                Instruction i = ii.next();
                if (!firstIns) insns.append(","); firstIns = false;
                StringBuilder pcs = new StringBuilder("[");
                try {
                    PcodeOp[] ops = i.getPcode();
                    for (int k = 0; k < ops.length; k++) {
                        if (k > 0) pcs.append(",");
                        pcs.append("\"").append(esc(pcode(ops[k]))).append("\"");
                    }
                } catch (Exception e) { /* skip */ }
                pcs.append("]");
                insns.append("{\"addr\":\"").append(hex(i.getAddress().getOffset()))
                    .append("\",\"text\":\"").append(esc(i.toString()))
                    .append("\",\"pcode\":").append(pcs).append("}");
            }
            insns.append("]");
            StringBuilder succ = new StringBuilder("[");
            CodeBlockReferenceIterator di = b.getDestinations(monitor);
            boolean firstS = true;
            while (di.hasNext()) {
                CodeBlockReference r = di.next();
                CodeBlock db = r.getDestinationBlock();
                if (db == null) continue;
                if (!firstS) succ.append(","); firstS = false;
                succ.append("\"").append(hex(db.getFirstStartAddress().getOffset())).append("\"");
                edges++;
            }
            succ.append("]");
            blocks.append("{\"addr\":\"").append(hex(b.getFirstStartAddress().getOffset()))
                  .append("\",\"instructions\":").append(insns)
                  .append(",\"succ\":").append(succ).append("}");
            nblocks++;
        }
        blocks.append("]");
        return new Object[]{blocks.toString(), edges, nblocks};
    }

    private String calls(Function f) {
        StringBuilder out = new StringBuilder("[");
        boolean first = true;
        InstructionIterator ii = listing.getInstructions(f.getBody(), true);
        while (ii.hasNext()) {
            Instruction i = ii.next();
            if (i.getFlowType() == null || !i.getFlowType().isCall()) continue;
            String site = hex(i.getAddress().getOffset());
            for (Reference ref : i.getReferencesFrom()) {
                if (ref.getReferenceType() == null || !ref.getReferenceType().isCall()) continue;
                Address to = ref.getToAddress();
                Function tf = fm.getFunctionAt(to);
                String name = null;
                boolean external = false;
                if (tf != null) {
                    name = tf.getName();
                    external = tf.isExternal() || tf.isThunk();
                } else {
                    Symbol sym = symtab.getPrimarySymbol(to);
                    if (sym != null) name = sym.getName();
                }
                if (!first) out.append(","); first = false;
                out.append("{\"site_addr\":\"").append(site)
                   .append("\",\"dst_addr\":\"").append(hex(to.getOffset()))
                   .append("\",\"dst_name\":").append(name == null ? "null"
                        : "\"" + esc(name) + "\"")
                   .append(",\"external\":").append(external).append("}");
            }
        }
        out.append("]");
        return out.toString();
    }

    private String strings(int limit) {
        StringBuilder out = new StringBuilder("[");
        boolean first = true;
        int n = 0;
        DataIterator di = listing.getDefinedData(true);
        while (di.hasNext() && n < limit) {
            Data d = di.next();
            DataType dt = d.getDataType();
            if (dt == null || !dt.getName().toLowerCase().contains("string")) continue;
            Object val = d.getValue();
            String s = val != null ? val.toString() : "";
            if (s.length() > 200) s = s.substring(0, 200);
            Address addr = d.getAddress();
            StringBuilder xrefs = new StringBuilder("[");
            ReferenceIterator rit = refmgr.getReferencesTo(addr);
            boolean firstX = true;
            while (rit.hasNext()) {
                if (!firstX) xrefs.append(","); firstX = false;
                xrefs.append("\"").append(hex(rit.next().getFromAddress().getOffset())).append("\"");
            }
            xrefs.append("]");
            if (!first) out.append(","); first = false;
            out.append("{\"addr\":\"").append(hex(addr.getOffset()))
               .append("\",\"value\":\"").append(esc(s))
               .append("\",\"xrefs\":").append(xrefs).append("}");
            n++;
        }
        out.append("]");
        return out.toString();
    }

    private static boolean isBuffer(DataType dt) {
        if (dt instanceof Array) {
            DataType el = ((Array) dt).getDataType();
            // char/byte arrays are the classic overflow target; any array >= 8 counts
            return dt.getLength() >= 8 || (el != null && el.getLength() == 1);
        }
        return dt != null && dt.getLength() >= 16;   // a large scalar local, treated as a buffer
    }

    private static String dtName(DataType dt) { return dt == null ? "undefined" : dt.getName(); }

    // ---- decompiler (HighFunction) based recovery: refined types, real params, char[N] arrays ----
    // Falls back to the listing-level Function view when the decompiler has no high function.

    private String signatureHF(Function f, HighFunction hf) {
        try {
            if (hf != null && hf.getFunctionPrototype() != null) {
                FunctionPrototype p = hf.getFunctionPrototype();
                StringBuilder s = new StringBuilder();
                s.append(dtName(p.getReturnType())).append(" ").append(f.getName()).append("(");
                int n = p.getNumParams();
                for (int i = 0; i < n; i++) {
                    if (i > 0) s.append(", ");
                    HighSymbol hs = p.getParam(i);
                    s.append(dtName(hs.getDataType())).append(" ").append(hs.getName());
                }
                if (n == 0) s.append("void");
                s.append(")");
                return esc(s.toString());
            }
        } catch (Exception e) { /* fall through */ }
        try { return esc(f.getPrototypeString(true, false)); }
        catch (Exception e) { return esc(f.getName()); }
    }

    private String paramsHF(Function f, HighFunction hf) {
        StringBuilder s = new StringBuilder("[");
        try {
            if (hf != null && hf.getFunctionPrototype() != null) {
                FunctionPrototype p = hf.getFunctionPrototype();
                for (int i = 0; i < p.getNumParams(); i++) {
                    if (i > 0) s.append(",");
                    HighSymbol hs = p.getParam(i);
                    DataType dt = hs.getDataType();
                    s.append("{\"name\":\"").append(esc(hs.getName()))
                     .append("\",\"type\":\"").append(esc(dtName(dt)))
                     .append("\",\"size\":").append(hs.getSize()).append("}");
                }
                return s.append("]").toString();
            }
            Parameter[] ps = f.getParameters();
            for (int i = 0; i < ps.length; i++) {
                if (i > 0) s.append(",");
                s.append("{\"name\":\"").append(esc(ps[i].getName()))
                 .append("\",\"type\":\"").append(esc(dtName(ps[i].getDataType())))
                 .append("\",\"size\":").append(ps[i].getLength()).append("}");
            }
        } catch (Exception e) { /* partial */ }
        return s.append("]").toString();
    }

    // stack-frame layout: every stack local with signed offset, size, refined type, buffer flag.
    // This is what lets overflow detection reason about buffer sizes and offset-to-return.
    private String frameHF(Function f, HighFunction hf) {
        StringBuilder s = new StringBuilder("{");
        StackFrame sf = f.getStackFrame();
        try {
            s.append("\"frame_size\":").append(sf.getFrameSize())
             .append(",\"local_size\":").append(sf.getLocalSize())
             .append(",\"param_size\":").append(sf.getParameterSize())
             .append(",\"ret_offset\":").append(sf.getReturnAddressOffset())
             .append(",\"vars\":[");
            boolean first = true;
            if (hf != null && hf.getLocalSymbolMap() != null) {
                LocalSymbolMap lsm = hf.getLocalSymbolMap();
                java.util.Iterator<HighSymbol> it = lsm.getSymbols();
                while (it.hasNext()) {
                    HighSymbol hs = it.next();
                    if (hs.isParameter()) continue;
                    VariableStorage st = hs.getStorage();
                    if (st == null || !st.isStackStorage()) continue;
                    DataType dt = hs.getDataType();
                    if (!first) s.append(","); first = false;
                    s.append("{\"name\":\"").append(esc(hs.getName()))
                     .append("\",\"offset\":").append(st.getStackOffset())
                     .append(",\"size\":").append(hs.getSize())
                     .append(",\"type\":\"").append(esc(dtName(dt)))
                     .append("\",\"is_buffer\":").append(isBuffer(dt)).append("}");
                }
            } else {                                      // listing-level fallback
                for (Variable v : sf.getStackVariables()) {
                    if (!first) s.append(","); first = false;
                    s.append("{\"name\":\"").append(esc(v.getName()))
                     .append("\",\"offset\":").append(v.getStackOffset())
                     .append(",\"size\":").append(v.getLength())
                     .append(",\"type\":\"").append(esc(dtName(v.getDataType())))
                     .append("\",\"is_buffer\":").append(isBuffer(v.getDataType())).append("}");
                }
            }
            s.append("]");
        } catch (Exception e) { return "{\"frame_size\":0,\"vars\":[]}"; }
        return s.append("}").toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outpath = args.length > 0 ? args[0] : "analysis.json";
        listing = currentProgram.getListing();
        fm = currentProgram.getFunctionManager();
        refmgr = currentProgram.getReferenceManager();
        symtab = currentProgram.getSymbolTable();
        bbm = new BasicBlockModel(currentProgram);
        DecompInterface deco = new DecompInterface();
        deco.openProgram(currentProgram);

        StringBuilder funcs = new StringBuilder("[");
        boolean first = true;
        int count = 0;
        for (Function f : fm.getFunctions(true)) {
            long size = f.getBody() != null ? f.getBody().getNumAddresses() : 0;
            String code = "";
            HighFunction hf = null;
            try {
                DecompileResults res = deco.decompileFunction(f, 30, monitor);
                if (res != null && res.decompileCompleted()) {
                    if (res.getDecompiledFunction() != null)
                        code = res.getDecompiledFunction().getC();
                    hf = res.getHighFunction();       // refined types, real params, char[N] arrays
                }
            } catch (Exception e) { code = ""; }
            String blocksJson = "[]"; int edges = 0, nblocks = 0;
            try {
                Object[] c = cfg(f);
                blocksJson = (String) c[0]; edges = (Integer) c[1]; nblocks = (Integer) c[2];
            } catch (Exception e) { /* keep defaults */ }
            String callsJson;
            try { callsJson = calls(f); } catch (Exception e) { callsJson = "[]"; }
            String sigJson, paramsJson, frameJson;
            try { sigJson = signatureHF(f, hf); } catch (Exception e) { sigJson = esc(f.getName()); }
            try { paramsJson = paramsHF(f, hf); } catch (Exception e) { paramsJson = "[]"; }
            try { frameJson = frameHF(f, hf); } catch (Exception e) { frameJson = "{\"vars\":[]}"; }
            boolean thunk = false, varargs = false; String cc = "";
            try { thunk = f.isThunk(); varargs = f.hasVarArgs();
                  cc = f.getCallingConventionName() == null ? "" : f.getCallingConventionName(); }
            catch (Exception e) { /* keep defaults */ }
            if (!first) funcs.append(","); first = false;
            funcs.append("{\"addr\":\"").append(hex(f.getEntryPoint().getOffset()))
                 .append("\",\"name\":\"").append(esc(f.getName()))
                 .append("\",\"size\":").append(size)
                 .append(",\"signature\":\"").append(sigJson)
                 .append("\",\"calling_convention\":\"").append(esc(cc))
                 .append("\",\"thunk\":").append(thunk)
                 .append(",\"varargs\":").append(varargs)
                 .append(",\"params\":").append(paramsJson)
                 .append(",\"frame\":").append(frameJson)
                 .append(",\"decompiled\":\"").append(esc(code))
                 .append("\",\"blocks\":").append(nblocks)
                 .append(",\"edges\":").append(edges)
                 .append(",\"cfg\":{\"blocks\":").append(blocksJson).append("}")
                 .append(",\"calls\":").append(callsJson).append("}");
            count++;
        }
        funcs.append("]");

        StringBuilder imports = new StringBuilder("[");
        boolean firstImp = true;
        java.util.Iterator<Function> ext = fm.getExternalFunctions();
        while (ext.hasNext()) {
            if (!firstImp) imports.append(","); firstImp = false;
            imports.append("\"").append(esc(ext.next().getName())).append("\"");
        }
        imports.append("]");

        StringBuilder meta = new StringBuilder("{");
        meta.append("\"format\":\"").append(esc(currentProgram.getExecutableFormat()))
            .append("\",\"language\":\"").append(esc(currentProgram.getLanguageID().toString()))
            .append("\",\"compiler\":\"")
            .append(esc(currentProgram.getCompilerSpec().getCompilerSpecID().toString()))
            .append("\",\"image_base\":\"").append(hex(currentProgram.getImageBase().getOffset()))
            .append("\",\"function_count\":").append(count)
            .append(",\"imports\":").append(imports).append("}");

        StringBuilder json = new StringBuilder("{");
        json.append("\"program\":").append(meta)
            .append(",\"functions\":").append(funcs)
            .append(",\"strings\":").append(strings(5000)).append("}");

        FileWriter fw = new FileWriter(outpath);
        try { fw.write(json.toString()); } finally { fw.close(); }
        println("lykos: exported " + count + " functions (CFG + P-Code + calls) and strings");
    }
}
