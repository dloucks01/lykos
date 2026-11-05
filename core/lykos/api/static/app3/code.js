// Code screen: the recovered functions of a target, a function's disassembly with every finding
// site marked, its callers/callees as links, and a hop from a marked site to its finding.
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { html } from "../app2/html.js";
import { functionAt, getJSON, hexToInt } from "./data.js";

const asList = (r) => (Array.isArray(r) ? r : (r && Object.values(r).find(Array.isArray)) || []);
const parseMaybe = (v) => {
  if (Array.isArray(v) || (v && typeof v === "object")) return v;
  try { return JSON.parse(v); } catch (_e) { return null; }
};

export function CodeScreen({ data, targetId, focusTarget, focusAddr, openFinding }) {
  const [funcs, setFuncs] = useState([]);
  const [q, setQ] = useState("");
  const [onlyFindings, setOnlyFindings] = useState(false);
  const [sel, setSel] = useState(null);         // function id
  const [detail, setDetail] = useState(null);
  const [focus, setFocus] = useState(focusAddr || null);
  const tid = targetId || (data.targets[0] && data.targets[0].id);

  useEffect(() => {
    if (!tid) return;
    setFuncs([]); setDetail(null);
    getJSON(`/targets/${tid}/functions`).then((r) => setFuncs(asList(r))).catch(() => setFuncs([]));
  }, [tid]);

  const findings = useMemo(() => data.findings.filter((f) => f.target_id === tid), [data.findings, tid]);
  // function addr -> findings in it (by site / function address)
  const byFunc = useMemo(() => {
    const m = new Map();
    for (const f of findings) {
      const fn = functionAt(funcs, f.site_addr || f.function_addr);
      if (!fn) continue;
      if (!m.has(fn.id)) m.set(fn.id, []);
      m.get(fn.id).push(f);
    }
    return m;
  }, [findings, funcs]);

  // a requested address (from a finding): open the function containing it
  useEffect(() => {
    if (!focusAddr || !funcs.length) return;
    const fn = functionAt(funcs, focusAddr);
    if (fn) { setSel(fn.id); setFocus(focusAddr); }
  }, [focusAddr, funcs]);
  useEffect(() => {
    if (!sel) return;
    setDetail(null);
    getJSON(`/functions/${sel}`).then(setDetail).catch(() => setDetail({ error: true }));
  }, [sel]);

  const shown = useMemo(() => {
    const qq = q.trim().toLowerCase();
    return funcs.filter((f) => (!onlyFindings || byFunc.has(f.id))
      && (!qq || (f.name || "").toLowerCase().includes(qq) || (f.addr || "").includes(qq)))
      .sort((a, b) => (byFunc.has(b.id) - byFunc.has(a.id)) || ((+b.size || 0) - (+a.size || 0)));
  }, [funcs, q, onlyFindings, byFunc]);

  const goAddr = (addr) => {
    const fn = functionAt(funcs, addr);
    if (fn) { setSel(fn.id); setFocus(addr); }
  };

  return html`
    <div style="display:flex;flex-wrap:wrap;align-items:center;gap:12px">
      <h1>Code</h1>
      <select value=${tid || ""} onChange=${(e) => focusTarget(e.target.value)}>
        ${data.targets.map((t) => html`<option value=${t.id}>${t.filename}</option>`)}
      </select>
      <span class="dim" style="font-size:12px">${funcs.length} functions · ${byFunc.size} with findings</span>
    </div>
    <div class="code">
      <section class="panel flist">
        <div class="pad" style="display:flex;flex-direction:column;gap:8px;padding-bottom:10px">
          <input type="text" placeholder="filter by name or address" value=${q} onInput=${(e) => setQ(e.target.value)} />
          <label class="muted" style="font-size:12px;display:flex;gap:6px;align-items:center">
            <input type="checkbox" checked=${onlyFindings} onChange=${(e) => setOnlyFindings(e.target.checked)} />only functions with findings</label>
        </div>
        <div class="items">
          ${shown.slice(0, 800).map((f) => html`<button class=${"fitem" + (sel === f.id ? " on" : "")} onClick=${() => { setSel(f.id); setFocus(null); }}>
            <span class="nm">${f.name || f.addr}</span>
            ${byFunc.has(f.id) ? html`<span class="lvl amber" style="font-size:10.5px;padding:0 6px">${byFunc.get(f.id).length}</span>` : null}
            <span class="dim">${f.addr}</span></button>`)}
          ${shown.length > 800 ? html`<div class="dim pad" style="font-size:12px">${shown.length - 800} more — filter to narrow</div>` : null}
        </div>
      </section>
      <div class="fview">
        ${!sel ? html`<div class="panel empty">Pick a function. Functions with findings are listed first.</div>`
          : !detail ? html`<div class="panel empty">Loading…</div>`
          : detail.error ? html`<div class="panel empty">Could not load this function.</div>`
          : html`<${FunctionView} fn=${detail} findings=${byFunc.get(sel) || []} focus=${focus}
                    goAddr=${goAddr} openFinding=${openFinding} />`}
      </div>
    </div>`;
}

function FunctionView({ fn, findings, focus, goAddr, openFinding }) {
  const [tab, setTab] = useState("asm");
  const box = useRef(null);
  const ir = parseMaybe(fn.ir) || {};
  const blocks = ir.blocks || [];
  const callers = parseMaybe(fn.callers) || [];
  const callees = parseMaybe(fn.callees) || [];
  const sites = useMemo(() => {
    const m = new Map();
    for (const f of findings) { const a = hexToInt(f.site_addr); if (a != null) { if (!m.has(a)) m.set(a, []); m.get(a).push(f); } }
    return m;
  }, [findings]);
  const focusInt = hexToInt(focus);
  useEffect(() => {
    const el = box.current && (box.current.querySelector(".ins.focus") || box.current.querySelector(".ins.site"));
    if (el) el.scrollIntoView({ block: "center" });
  }, [fn.id, focus]);
  const uniq = (xs, k) => [...new Map(xs.map((x) => [x[k], x])).values()];
  return html`
    <section class="panel pad" style="display:flex;flex-direction:column;gap:6px">
      <div class="row-c" style="flex-wrap:wrap"><h2 class="mono">${fn.name}</h2>
        <span class="mono dim" style="font-size:12px">${fn.addr} · ${fn.size} bytes · ${fn.blocks} blocks</span></div>
      ${fn.signature ? html`<span class="mono muted" style="font-size:12px;word-break:break-word">${fn.signature}</span>` : null}
      ${findings.length ? html`<div class="row-c" style="flex-wrap:wrap;margin-top:4px">
        ${findings.map((f) => html`<button class="chip" style="cursor:pointer;color:var(--amber-tx);border-color:#5C4618"
          onClick=${() => openFinding(f.id)} title=${f.title}>${f.cwe} · ${f.state} @ ${f.site_addr || "fn"}</button>`)}</div>` : null}
    </section>
    <div class="row-c" style="flex-wrap:wrap;align-items:flex-start">
      <section class="panel pad" style="flex:1 1 240px;min-width:0">
        <div class="dim" style="font-size:11px;letter-spacing:.05em">CALLED FROM (${uniq(callers, "src_addr").length})</div>
        ${uniq(callers, "src_addr").slice(0, 30).map((e) => html`<div><button class="xref" onClick=${() => goAddr(e.src_addr)}>${e.src_addr}</button>
          <span class="mono dim" style="font-size:11px"> at ${e.site_addr}</span></div>`)}
      </section>
      <section class="panel pad" style="flex:1 1 240px;min-width:0">
        <div class="dim" style="font-size:11px;letter-spacing:.05em">CALLS (${uniq(callees, "dst_addr").length})</div>
        ${uniq(callees, "dst_addr").slice(0, 40).map((e) => html`<div><button class="xref" disabled=${!!e.external}
          onClick=${() => goAddr(e.dst_addr)}>${e.dst_name || e.dst_addr}</button>
          ${e.external ? html`<span class="dim" style="font-size:11px"> import</span>` : null}</div>`)}
      </section>
    </div>
    <div class="seg" role="group" aria-label="View" style="align-self:flex-start">
      <button class=${tab === "asm" ? "on" : ""} onClick=${() => setTab("asm")}>Disassembly</button>
      <button class=${tab === "src" ? "on" : ""} onClick=${() => setTab("src")} disabled=${!fn.decompiled}>Decompiled</button>
    </div>
    ${tab === "src" && fn.decompiled ? html`<pre class="asm" style="padding:12px 14px;margin:0;white-space:pre-wrap">${fn.decompiled}</pre>`
      : html`<div class="asm" ref=${box}>
        ${blocks.length ? blocks.map((b) => html`<div>
          <div class="bb">${b.addr}:</div>
          ${(b.instructions || []).map((i) => {
            const a = hexToInt(i.addr);
            const fs = sites.get(a);
            const cls = "ins" + (fs ? " site" : "") + (focusInt != null && a === focusInt ? " focus" : "");
            return html`<div class=${cls}><span class="a">${i.addr}</span><span>${i.text}</span>
              ${fs ? html`<button class="xref" style="color:var(--amber-tx);margin-left:auto;padding-right:6px"
                onClick=${() => openFinding(fs[0].id)}>◂ ${fs[0].cwe} ${fs[0].state}</button>` : null}</div>`;
          })}</div>`) : html`<div class="dim" style="padding:12px 14px">No instruction listing recovered for this function.</div>`}
      </div>`}`;
}
