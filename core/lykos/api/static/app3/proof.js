// Proof screen: every finding of the case laid out by what is PROVEN. Three lanes --
//   proven (a PoC ran), real but no PoC yet (with what it takes), unverified leads --
// plus the case's crash groups, the research queue (techniques to build next) and the composed
// attack path; and a finding detail view: its PoCs (replay in the sandbox, inspect the bundle,
// payload hexdump), the evidence trail, why it is in this state, what would promote it, the
// mitigations in the way, the operator's triage, and a hop to the code at its site.
//
// Honesty rules (the lane rules live in data.js): a lead or a constructed (not executed) PoC is
// never presented as proven; the operator's triage sits BESIDE the tool's state, never over it; a
// replay result is shown as what it is -- N runs, M crashed -- and changes nothing else.
import { useEffect, useMemo, useState } from "preact/hooks";
import { html } from "../app2/html.js";
import { api } from "../app/api.js";
import { backlogFor, bestLevel, functionAt, getJSON, isNoise, laneOf, pocsOf, rankFindings } from "./data.js";

// ── vocabulary ──────────────────────────────────────────────────────────────────────────────
const STATE_GLOSS = {
  "poc-backed": "A reproducer ran and the fault fired.",
  confirmed: "Multiple independent channels agree on this defect.",
  corroborated: "A second signal supports the initial detection.",
  candidate: "One detector flagged a pattern. Not yet demonstrated.",
};
const LADDER = ["candidate", "corroborated", "confirmed", "poc-backed"];
const CUR_STATUSES = ["false_positive", "true_positive", "needs_review"];
const CUR_LABEL = { false_positive: "False positive", true_positive: "True positive (operator)", needs_review: "Needs review" };
const CUR_TIP = {
  false_positive: "A false positive: hidden from the default board (the tool's evidence and level are kept)",
  true_positive: "A real issue you reviewed (operator judgement, separate from the tool's 'confirmed' state)",
  needs_review: "Flag for follow-up",
};
const TRIAGE = [["hide_fp", "Hide false positives"], ["all", "All findings"], ["needs_review", "Needs review"],
  ["true_positive", "True positives"], ["false_positive", "False positives only"], ["uncurated", "Not yet triaged"]];
// the "is this an actual finding?" review -- a triage signal, never the earned `confirmed` state
const VERDICT = {
  "prove-out-shortlist": { label: "prove-out shortlist", tip: "a real finding on the fuzzed attack surface — the slice worth proving out" },
  "off-surface": { label: "off-surface", tip: "not compiled into any in-tree harness — lower remote-reachability priority, not dismissed" },
  "instrumentation-noise": { label: "instrumentation artifact", tip: "anchored in sanitizer/fuzzer runtime code, not the target's own — de-prioritised" },
};
const SEVS = ["critical", "high", "medium", "low", "info"];
const SEV_N = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const CH_LABEL = {
  "root-cause": "Root cause", exploitability: "Exploitability", dataflow: "Dataflow", dynamic: "Reached / how found",
  recipe: "Exploitation recipe", "recipe-input": "Computed input", "recipe-plan": "Write plan",
  "recipe-assumptions": "Assumptions", "recipe-ceiling": "Reach so far", "chain-ceiling": "Reach so far",
  poc: "Proof", detonation: "Detonation", chain: "Primitive chain", effects: "End effects",
};
const RATING_TONE = { EXPLOITABLE: "hi", PROBABLY_EXPLOITABLE: "hi", UNKNOWN: "mid", PROBABLY_NOT_EXPLOITABLE: "lo", NOT_EXPLOITABLE: "lo" };

const ran = (p) => !!(p && (p.verified || p.provenance === "detonated"));
const lvlN = (p) => +((String((p && p.level) || "").match(/\d/) || [0])[0]);
const lvlTxt = (l) => (l == null || l === "" ? null : "L" + String(l).replace(/^L/, ""));
const ev = (f, ch) => (f.evidence || []).find((e) => e && e.channel === ch);
const plural = (n, w, ws) => `${n} ${n === 1 ? w : (ws || w + "s")}`;
const short = (s) => (s ? String(s).slice(0, 12) : "");
const caseOf = (data) => (data.findings[0] && data.findings[0].case_id) || (data.targets[0] && data.targets[0].case_id) || null;
function fmtTime(t) { return t ? new Date(t * 1000).toLocaleString() : ""; }
function fmtBytes(n) {
  if (n == null) return "";
  return n < 1024 ? `${n} B` : n < 1 << 20 ? `${(n / 1024).toFixed(1)} KB` : `${(n / (1 << 20)).toFixed(1)} MB`;
}
function parseJSON(s, dflt) { try { return JSON.parse(s); } catch (_e) { return dflt; } }
function saveText(name, text) {
  const url = URL.createObjectURL(new Blob([text || ""], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

// One GET, re-run when `path` changes. {data, err, loading, reload}
function useJSON(path) {
  const [st, setSt] = useState({ data: null, err: null, loading: !!path });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!path) { setSt({ data: null, err: null, loading: false }); return undefined; }
    let live = true;
    setSt((o) => ({ ...o, loading: true, err: null }));
    getJSON(path).then((d) => { if (live) setSt({ data: d, err: null, loading: false }); })
      .catch((e) => { if (live) setSt({ data: null, err: String(e.message || e), loading: false }); });
    return () => { live = false; };
  }, [path, tick]);
  return { ...st, reload: () => setTick((x) => x + 1) };
}

// ── case-side state shared by the board and the detail: operator curation + replay verdicts ──
// The server is the truth (GET /cases/{id}/curation, /cases/{id}/verifications); a save is
// reflected at once through a local override that yields to any newer server entry.
const bus = { cur: new Map(), caseCur: {}, verifs: {}, labels: null, subs: new Set() };
function emit() { for (const s of bus.subs) s(); }
function useBus() {
  const [, setN] = useState(0);
  useEffect(() => {
    const s = () => setN((n) => n + 1);
    bus.subs.add(s);
    return () => { bus.subs.delete(s); };
  }, []);
}
async function loadCaseSide(caseId) {
  if (!caseId) return;
  const [cc, vv] = await Promise.all([api.caseCuration(caseId).catch(() => null), api.verifications(caseId).catch(() => null)]);
  if (cc) { bus.caseCur[caseId] = cc.curation || {}; if (cc.labels) bus.labels = cc.labels; }
  if (vv) bus.verifs[caseId] = vv;
  emit();
}
function useCaseSide(caseId, key) {
  useBus();
  useEffect(() => { loadCaseSide(caseId); }, [caseId, key]);
}
const curLabel = (st) => (bus.labels && bus.labels[st]) || CUR_LABEL[st] || st;
function curOf(f) {
  const cm = bus.caseCur[f.case_id];
  const server = cm ? (cm[f.id] || null) : (f.curation || null);
  const o = bus.cur.get(f.id);
  if (!o) return server;
  if (server && (server.updated_at || 0) > o.at) return server;
  return o.value;
}
const curStatus = (f) => (curOf(f) || {}).status || null;
async function saveCuration(fs, status, note) {
  const out = await Promise.all(fs.map((f) => api.setCuration(f.id, status, note)));
  for (const r of out) {
    bus.cur.set(r.finding_id, { value: r.cleared ? null : { status: r.status, note: r.note, updated_at: r.updated_at }, at: r.updated_at || 0 });
  }
  emit();
  return out;
}
// the replay verdicts for a finding's PoCs: [{poc, v}]
function verifsOf(f, pocs) {
  const vm = bus.verifs[f.case_id] || {};
  return pocs.filter((p) => p.input_sha && vm[p.input_sha]).map((p) => ({ poc: p, v: vm[p.input_sha] }));
}
// curated false positives count as noise for the leads lane too
const noiseOf = (f) => isNoise(f) || curStatus(f) === "false_positive";

// ── filters + issue grouping ────────────────────────────────────────────────────────────────
function triageOk(f, mode) {
  const st = curStatus(f);
  switch (mode) {
    case "all": return true;
    case "uncurated": return !st;
    case "false_positive": case "true_positive": case "needs_review": return st === mode;
    default: return st !== "false_positive";
  }
}
function haystack(f) {
  return [f.title, f.cwe, f.cwe_name, f.function_addr, f.site_addr, f.detector, f.stage_label, f.target_name,
    (ev(f, "root-cause") || {}).detail].filter(Boolean).join(" ").toLowerCase();
}
function matchQ(f, q) {
  const toks = q.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!toks.length) return true;
  const h = haystack(f);
  return toks.every((t) => h.includes(t));
}
const sevOk = (f, min) => !min || (SEV_N[(f.severity || "").toLowerCase()] ?? 9) <= SEV_N[min];
const FACETS = [["stage", "Found by", (f) => f.stage, (f) => f.stage_label || f.stage],
  ["detector", "Detector", (f) => f.detector, (f) => f.detector],
  ["cwe", "CWE", (f) => f.cwe, (f) => f.cwe + (f.cwe_name ? " — " + f.cwe_name : "")],
  ["verdict", "Review verdict", (f) => (f.verification || {}).verdict, (f) => (VERDICT[(f.verification || {}).verdict] || {}).label || (f.verification || {}).verdict],
  ["level", "PoC level", (f) => f.poc_level, (f) => f.poc_level]];
function facetOptions(fs) {
  return FACETS.map(([k, label, get, show]) => {
    const m = new Map();
    for (const f of fs) {
      const v = get(f);
      if (v == null || v === "") continue;
      const o = m.get(v) || { v, label: show(f), n: 0 };
      o.n += 1; m.set(v, o);
    }
    return { k, label, opts: [...m.values()].sort((a, b) => b.n - a.n) };
  }).filter((g) => g.opts.length > 1 || (g.k === "verdict" && g.opts.length));
}
function facetOk(f, facet) {
  if (!facet) return true;
  const i = facet.indexOf(":");
  const k = facet.slice(0, i), v = facet.slice(i + 1);
  const def = FACETS.find((x) => x[0] === k);
  return !def || String(def[2](f)) === v;
}
// one issue = the same function, or (siteless) the same CWE + title shape with addresses stripped
function clusterKey(f) {
  if (f.function_addr) return `${f.target_id}|fn:${f.function_addr}`;
  const t = (f.title || f.detector || "").replace(/0x[0-9a-fA-F]+/g, "").replace(/\s+/g, " ").trim().slice(0, 48);
  return `${f.target_id}|t:${f.cwe || ""}:${t}`;
}
// `ranked` is already best-first, so each group's first member is its representative
function clusterize(ranked) {
  const m = new Map();
  for (const f of ranked) {
    const k = clusterKey(f);
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(f);
  }
  return [...m.values()].map((g) => ({ rep: g[0], members: g.slice(1) }));
}

// ── small shared pieces ─────────────────────────────────────────────────────────────────────
function LevelBadge({ level, constructed }) {
  if (!level) return null;
  const cls = constructed ? "lvl pf-lvl-con" : level === "L3" ? "lvl pf-lvl-strong" : "lvl pf-lvl";
  return html`<span class=${cls} title=${constructed ? "a constructed PoC at this level — not executed" : "a PoC ran at this level"}>${level}${constructed ? " · constructed" : ""}</span>`;
}

function Meta({ f, showTarget }) {
  return html`<span class="mono dim pf-meta">
    ${[f.cwe, f.severity, showTarget ? f.target_name : null, f.site_addr ? "@ " + f.site_addr : null].filter(Boolean).join(" · ")}</span>`;
}

function CurChip({ f }) {
  const c = curOf(f);
  if (!c || (!c.status && !c.note)) return null;
  return html`<span class=${"chip pf-cur pf-cur-" + (c.status || "note")} title=${"operator triage" + (c.note ? ": " + c.note : "")}>
    ${c.status ? curLabel(c.status) : "note"}${c.status && c.note ? " · note" : ""}</span>`;
}

function VerifyChip({ v }) {
  if (!v || v.runs == null) return null;
  const all = v.crashed === v.runs, none = !v.crashed;
  const txt = all ? `replay ✓ ${v.crashed}/${v.runs}` : none ? `did not reproduce 0/${v.runs}` : `flaky ${v.crashed}/${v.runs}`;
  return html`<span class=${"chip " + (all ? "on" : "pf-warn")}
    title=${`replayed the recorded input ${v.runs}× in the sandbox; crashed ${v.crashed}×${v.signal ? ` (${v.signal})` : ""}`}>${txt}</span>`;
}

// The finding resolver's latest measured verdict (analyze/resolve_stage.py, evidence channel
// "resolve": "[kind] detail"). Says what was MEASURED about reach and firing -- never a proof by
// itself, except "fired", which raised the finding and handed a crash to the prove loop.
const RESOLVE = {
  "fired": ["fired at its site", "on"],
  "reached-did-not-fire": ["reached · quiet", ""],
  "function-entered-site-cold": ["site cold", ""],
  "not-reached": ["not reached", ""],
  "unmapped": ["unmeasured", ""],
  "untested": ["unmeasured", ""],
};
function resolveOf(f) {
  const ev = (f.evidence || []).filter((e) => e && e.channel === "resolve");
  const last = ev[ev.length - 1];
  if (!last) return null;
  const m = /^\[([a-z-]+)\]\s*(.*)$/s.exec(last.detail || "");
  if (!m) return null;
  const reach = (f.evidence || []).filter((e) => e && e.channel === "resolve-reach").pop();
  return { kind: m[1], detail: m[2], reach: reach ? reach.detail : null };
}
function ResolveChip({ f }) {
  const r = resolveOf(f);
  if (!r) return null;
  const [label, cls] = RESOLVE[r.kind] || [r.kind, ""];
  return html`<span class=${"chip" + (cls ? " " + cls : "")} title=${r.detail}>${label}</span>`;
}

function VerdictChip({ f }) {
  const vr = f.verification || {};
  const d = VERDICT[vr.verdict];
  if (!d) return null;
  return html`<span class="chip" title=${vr.noise_reason || d.tip}>${d.label}</span>`;
}

// ── attack path: entry → step → … → objective, each step a real finding (or technique) edge ──
function attackSteps(f) {
  const steps = parseJSON((ev(f, "attack-path-steps") || {}).detail || "[]", []);
  const rendered = (ev(f, "attack-path") || {}).detail || "";
  const m = rendered.match(/\n\[(reflected|detonated|constructed|not detonated)\] end-to-end: (.*)$/s);
  return { steps: Array.isArray(steps) ? steps : [], e2e: m ? { kind: m[1], text: m[2] } : null, rendered };
}
// a step names its CWE + the (truncated) finding title; link it only when that is unambiguous
function stepFinding(st, findings) {
  if (!st.cwe || !st.function) return null;
  const hits = findings.filter((x) => x.detector !== "attack_path" && x.cwe === st.cwe
    && ((x.title || "").startsWith(st.function) || x.function_addr === st.function));
  return hits.length === 1 ? hits[0] : null;
}
function AttackPathDiagram({ f, findings, open }) {
  const { steps, e2e, rendered } = attackSteps(f);
  if (!steps.length) return rendered ? html`<pre class="pf-pre">${rendered}</pre>` : null;
  return html`<div>
    <ol class="pf-ap" aria-label="attack path">
      <li class="pf-ap-node pf-ap-entry"><b>Entry</b><span class="dim">attacker reaches the surface</span></li>
      ${steps.map((st) => {
        const lv = st.level || (st.technique ? "technique" : "candidate");
        const hit = open ? stepFinding(st, findings) : null;
        const body = html`
          <span class="pf-ap-caps">${(st.gained || []).map((c) => html`<span class="pf-capa">${c}</span>`)}
            <span class=${"lvl" + (/^L\d$/.test(lv) ? "" : " pf-lvl-con")}>${lv}</span></span>
          <span class="pf-ap-label">${st.label}</span>
          <span class="mono dim pf-ap-src">${st.cwe ? st.cwe + (st.function ? " · " + st.function : "") : "weaponization step"}</span>`;
        return html`<li class="pf-ap-arrow" aria-hidden="true">→</li>
          <li class="pf-ap-node">${hit ? html`<button class="pf-ap-btn" onClick=${() => open(hit.id)} title="open this finding">${body}</button>` : body}</li>`;
      })}
      <li class="pf-ap-arrow" aria-hidden="true">→</li>
      <li class="pf-ap-node pf-ap-obj"><b>Objective</b><span>${f.title || "objective"}</span></li>
    </ol>
    ${e2e ? html`<div class=${"pf-e2e" + (e2e.kind === "not detonated" ? " no" : "")}><b>End-to-end: ${e2e.kind}</b> — ${e2e.text}</div>` : null}
  </div>`;
}
function AttackPathCard({ f, pocs, findings, open }) {
  const lane = laneOf(f, pocs);
  return html`<section class="panel pad pf-apcard">
    <div class="row-c" style="flex-wrap:wrap">
      <span class=${"lane-h" + (lane === "proven" ? " blue" : lane === "needs" ? " amber" : "")} style="margin-right:4px">ATTACK PATH</span>
      <span class=${"lvl" + (lane === "needs" ? " amber" : "")}>${f.state}</span>
      ${bestLevel(pocs) ? html`<${LevelBadge} level=${bestLevel(pocs)} />` : null}
      <${CurChip} f=${f} />
      <button class="btn sm" style="margin-left:auto" onClick=${() => open(f.id)}>Details</button>
    </div>
    <div class="card-t" style="margin:6px 0 10px">${f.title}</div>
    <${AttackPathDiagram} f=${f} findings=${findings} open=${open} />
  </section>`;
}

// ── board cards ─────────────────────────────────────────────────────────────────────────────
function QuickFP({ f, members }) {
  const [busy, setBusy] = useState(false);
  const fp = curStatus(f) === "false_positive";
  const all = [f, ...(members || [])];
  const act = async () => {
    setBusy(true);
    try { await saveCuration(all, fp ? null : "false_positive", (curOf(f) || {}).note || ""); } catch (_e) { /* the detail view shows errors */ }
    setBusy(false);
  };
  return html`<button class="pf-mini" disabled=${busy} onClick=${act}
    title=${fp ? "clear the false-positive mark" : `mark ${all.length > 1 ? `this issue (${all.length} findings)` : "this finding"} a false positive`}>
    ${fp ? "Unmark FP" : "Mark FP"}</button>`;
}

function Related({ members, open, pocsBy }) {
  const [on, setOn] = useState(false);
  if (!members.length) return null;
  return html`<div class="pf-rel">
    <button class="pf-mini" aria-expanded=${on ? "true" : "false"} onClick=${() => setOn((x) => !x)}>
      ${on ? "▾" : "▸"} +${members.length} related</button>
    ${on ? html`<div class="pf-rel-list">${members.map((m) => html`<button class="pf-rel-i" onClick=${() => open(m.id)} title=${m.title}>
      <span class="mono dim">${m.cwe || "—"}</span><span class="pf-trunc">${m.title || m.detector}</span>
      <span class="dim">${laneOf(m, pocsOf(m, pocsBy)) === "proven" ? "proven" : m.state}</span></button>`)}</div>` : null}
  </div>`;
}

function CardFoot({ f, members, open, pocs, pocsBy }) {
  const vs = verifsOf(f, pocs);
  return html`<div class="pf-foot">
    <${CurChip} f=${f} />
    ${vs.slice(0, 1).map(({ v }) => html`<${VerifyChip} v=${v} />`)}
    <${VerdictChip} f=${f} />
    <${ResolveChip} f=${f} />
    <span style="flex:1 1 auto"></span>
    <${QuickFP} f=${f} members=${members} />
    <${Related} members=${members} open=${open} pocsBy=${pocsBy} />
  </div>`;
}

function ProvenCard({ u, pocsBy, open, showTarget }) {
  const f = u.rep, pocs = pocsOf(f, pocsBy);
  const best = pocs.find(ran);
  const why = f.analysis && f.analysis.why_state;
  return html`<div class=${"card proven pf-card" + (curStatus(f) === "false_positive" ? " pf-dim" : "")}>
    <button class="pf-main" onClick=${() => open(f.id)} title=${f.title}>
      <span class="row-c" style="flex-wrap:wrap"><${LevelBadge} level=${bestLevel(pocs)} /><${Meta} f=${f} showTarget=${showTarget} /></span>
      <span class="card-t pf-clamp">${f.title}</span>
      ${why ? html`<span class="card-b pf-clamp">${why}</span>` : null}
      <span class="row-c" style="flex-wrap:wrap">
        ${best ? html`<span class="chip on">PoC ran${best.signal ? " · " + best.signal : ""}</span>` : null}
        ${f.stage_label ? html`<span class="chip">found by ${f.stage_label}</span>` : null}
        ${f.site_count > 1 ? html`<span class="chip">${f.site_count} sites${f.proven_sites ? ` · ${f.proven_sites} proven` : ""}</span>` : null}
      </span>
    </button>
    <${CardFoot} f=${f} members=${u.members} open=${open} pocs=${pocs} pocsBy=${pocsBy} />
  </div>`;
}

function NeedsCard({ u, pocsBy, backlog, open, showTarget }) {
  const f = u.rep, pocs = pocsOf(f, pocsBy);
  const a = f.analysis || {};
  const bl = backlogFor(f, backlog);
  const next = (bl && bl.missing_technique) || a.to_promote;
  const con = pocs.slice().sort((x, y) => lvlN(y) - lvlN(x))[0];
  return html`<div class=${"card pf-card" + (curStatus(f) === "false_positive" ? " pf-dim" : "")}>
    <button class="pf-main" onClick=${() => open(f.id)} title=${f.title}>
      <span class="row-c" style="flex-wrap:wrap"><span class="lvl amber">${f.state}</span><${Meta} f=${f} showTarget=${showTarget} />
        ${con ? html`<${LevelBadge} level=${lvlTxt(con.level) || "L?"} constructed=${true} />` : null}</span>
      <span class="card-t pf-clamp">${f.title}</span>
      ${a.why_state ? html`<span class="card-b pf-clamp">${a.why_state}</span>` : null}
      ${next ? html`<span class="next"><b>${bl ? "Technique to build next" : "To promote it"}:</b> ${next}</span>` : null}
    </button>
    <${CardFoot} f=${f} members=${u.members} open=${open} pocs=${pocs} pocsBy=${pocsBy} />
  </div>`;
}

function LeadRow({ u, open, showTarget, pocsBy }) {
  const f = u.rep;
  const fp = curStatus(f) === "false_positive";
  return html`<div class="pf-lead">
    <button class="pf-lead-main" onClick=${() => open(f.id)} title=${f.title}>
      <span class="mono dim pf-lead-cwe">${f.cwe || "—"}</span>
      <span class="pf-lead-t">
        <span class="pf-trunc" style=${noiseOf(f) ? "color:var(--tx3)" : ""}>${f.title}</span>
        <span class="dim pf-trunc" style="font-size:11.5px">${[f.stage_label || f.detector, showTarget ? f.target_name : null,
          isNoise(f) ? "flagged as noise" : null, fp ? "marked false positive" : null].filter(Boolean).join(" · ")}</span>
      </span>
      <span class="dim" style="font-size:12px;flex:none">${f.severity}</span>
    </button>
    <div class="pf-lead-side">
      <${ResolveChip} f=${f} />
      <${CurChip} f=${f} />
      <${QuickFP} f=${f} members=${u.members} />
      <${Related} members=${u.members} open=${open} pocsBy=${pocsBy} />
    </div>
  </div>`;
}

// ── per-target chain strip: how far the exploit chain got on each target (PoCs that RAN only) ──
function ChainStrip({ targets, data, open }) {
  const rows = targets.map((t) => {
    const ps = data.pocs[t.id] || [];
    const runs = ps.filter(ran), cons = ps.filter((p) => !ran(p));
    const top = runs.slice().sort((a, b) => lvlN(b) - lvlN(a))[0];
    const conTop = cons.slice().sort((a, b) => lvlN(b) - lvlN(a))[0];
    const head = top ? data.findings.find((f) => f.id === top.finding_id) : null;
    return { t, level: top ? lvlN(top) : 0, head, conLevel: conTop && lvlN(conTop) > (top ? lvlN(top) : 0) ? lvlN(conTop) : 0 };
  });
  if (!rows.length) return null;
  return html`<div class="pf-chains">${rows.map((r) => html`
    <div class="pf-chain">
      <span class="mono pf-trunc" style="font-size:12px;max-width:220px" title=${r.t.filename}>${r.t.filename}</span>
      <span class="pf-ladder" title="how far the exploit chain got — PoCs that ran only">
        ${[1, 2, 3].map((n) => html`${n > 1 ? html`<span class=${"pf-arr" + (r.level >= n ? " on" : "")}>▸</span>` : null}<span class=${"pf-rung" + (r.level >= n ? " on" : "")}>L${n}</span>`)}
      </span>
      ${r.head ? html`<button class="pf-link pf-trunc" onClick=${() => open(r.head.id)} title=${r.head.title}>${r.head.title}</button>`
        : html`<span class="dim" style="font-size:12px">no PoC ran yet</span>`}
      ${r.conLevel ? html`<span class="chip" title="a PoC was constructed at this level but not executed here">constructed L${r.conLevel} · not executed</span>` : null}
    </div>`)}</div>`;
}

// ── crash groups (per target) ───────────────────────────────────────────────────────────────
function RawCrashes({ tid }) {
  const r = useJSON(`/targets/${tid}/dynresults`);
  if (r.loading) return html`<div class="dim pf-pad-s">Loading…</div>`;
  if (r.err) return html`<div class="dim pf-pad-s">Could not load: ${r.err}</div>`;
  const c = (Array.isArray(r.data) ? r.data : []).filter((x) => x.crashed);
  return html`<div class="pf-tbl">${c.map((x) => html`<div class="pf-raw-row">
    <span class="mono">${x.signal || "crash"}</span><span class="mono dim">${x.fault_pc || "—"}</span>
    <span class="dim pf-trunc">${[x.input_mode || "stdin", x.argv && x.argv.length ? x.argv.join(" ") : null, x.isolation].filter(Boolean).join(" · ")}</span>
    ${x.input_sha ? html`<a class="pf-mini" href=${"/artifacts/" + x.input_sha} download>input</a>` : html`<span></span>`}</div>`)}</div>`;
}

function CrashGroupRow({ g, t, open }) {
  const [more, setMore] = useState(false);
  const where = g.defect_key || g.fault_pc || `no fault PC · ${g.channel}`;
  const ex = g.exploitability;
  return html`<div class="pf-cg">
    <div class="pf-cg-row">
      <span class="dim mono">#${g.rank}</span>
      ${g.best_level ? html`<span class="lvl pf-lvl" title="verified PoC level">L${g.best_level}</span>`
        : g.candidate_level ? html`<span class="lvl pf-lvl-con" title="an unverified PoC exists for this level — not executed/confirmed">cand. L${g.candidate_level}</span>`
        : html`<span class="lvl" title="no PoC built from this crash yet">—</span>`}
      <span class="pf-cg-what">
        <span class="mono" style="font-weight:600">${g.signal}</span>
        <span class="mono dim pf-trunc" title=${g.resolved ? "the root-cause bucket" : "the fault PC could not be read: grouped by signal and channel, may hold more than one defect"}>${where}</span>
        ${g.resolved ? null : html`<span class="chip pf-warn">unresolved</span>`}
      </span>
      <span class="mono" title=${`${g.count} crashing execution(s), ${g.input_count} distinct input(s)`}>×${g.count}</span>
      ${ex && ex.rating ? html`<span class=${"chip pf-rate-" + (RATING_TONE[ex.rating] || "mid")} title=${ex.why || ""}>${ex.rating.replace(/_/g, " ").toLowerCase()}${ex.score != null ? ` ${ex.score}` : ""}</span>` : html`<span></span>`}
      <button class="pf-mini" aria-expanded=${more ? "true" : "false"} onClick=${() => setMore((x) => !x)}>${more ? "▾" : "▸"} details</button>
    </div>
    <div class="pf-cg-links">
      ${(g.findings || []).map((f) => html`<button class="pf-mini" onClick=${() => open(f.id)} title=${`${f.cwe || ""} ${f.title || ""} (${f.state})`}>
        finding: <span class="pf-trunc" style="max-width:260px">${f.title || f.cwe}</span> · ${f.state}</button>`)}
      ${!(g.findings || []).length ? html`<span class="dim" style="font-size:12px">not filed as a finding</span>` : null}
      ${g.poc && g.poc.bundle_sha ? html`<a class="pf-mini" href=${"/artifacts/" + g.poc.bundle_sha} download=${`poc-${short(g.poc.bundle_sha)}.tar.gz`}>PoC bundle ${g.poc.level || ""}</a>` : null}
      ${g.representative ? html`<a class="pf-mini" href=${"/artifacts/" + g.representative} download>representative input</a>` : null}
    </div>
    ${more ? html`<div class="pf-cg-more">
      <div class="dim" style="font-size:12px">${[g.channel ? "channel " + g.channel : null, g.isolation ? "isolation " + g.isolation : null,
        g.argv && g.argv.length ? "argv " + g.argv.join(" ") : null, g.first_seen ? "first seen " + fmtTime(g.first_seen) : null].filter(Boolean).join(" · ")}</div>
      ${g.representative ? html`<${Replay} tid=${t.id} sha=${g.representative} caseId=${t.case_id} />` : null}
      ${g.poc && g.poc.bundle_sha ? html`<${BundleInspector} sha=${g.poc.bundle_sha} />` : null}
      ${(g.inputs || []).length > 1 ? html`<div class="dim" style="font-size:12px">inputs in this group (${g.input_count}):
        ${g.inputs.map((s) => html` <a class="mono" href=${"/artifacts/" + s} download>${short(s)}</a>`)}</div>` : null}
    </div>` : null}
  </div>`;
}

function TargetCrashes({ t, open, showName }) {
  const r = useJSON(`/targets/${t.id}/crash-triage`);
  const [raw, setRaw] = useState(false);
  const groups = (r.data && r.data.groups) || [];
  return html`<section class="panel" style="overflow:hidden">
    <div class="pad" style="padding-bottom:8px;display:flex;flex-wrap:wrap;gap:6px 12px;align-items:baseline">
      <h2>${showName ? html`<span class="mono">${t.filename}</span> · ` : ""}Crashes</h2>
      ${r.data && groups.length ? html`<span class="dim" style="font-size:12px">${plural(r.data.distinct ?? groups.length, "distinct root cause")} from ${plural(r.data.crashes || 0, "crashing execution")} — ranked by verified level, then exploitability</span>` : null}
    </div>
    ${r.loading ? html`<div class="empty" style="padding:20px">Grouping crashes…</div>`
      : r.err ? html`<div class="empty" style="padding:20px">Could not load crash groups: ${r.err}</div>`
      : !groups.length ? html`<div class="empty" style="padding:20px">No reproduced crashes for this target.</div>`
      : html`
        ${r.data.over_prove_cap ? html`<div class="next" style="margin:0 16px 10px">The autopilot proves at most ${r.data.prove_cap} distinct crashes per target; an unlevelled group may simply not have been worked on.</div>` : null}
        ${groups.map((g) => html`<${CrashGroupRow} key=${g.rank} g=${g} t=${t} open=${open} />`)}
        <div class="pad" style="border-top:1px solid var(--line)">
          <button class="pf-mini" aria-expanded=${raw ? "true" : "false"} onClick=${() => setRaw((x) => !x)}>${raw ? "▾" : "▸"} all ${plural(r.data.crashes || 0, "crashing execution")}</button>
          ${raw ? html`<${RawCrashes} tid=${t.id} />` : null}
        </div>`}
  </section>`;
}

// ── research queue: the techniques to build next, ranked by how many findings each advances ──
function entryFinding(e, findings) {
  return findings.find((f) => e.dedup_key && f.dedup_key === e.dedup_key)
    || findings.find((f) => f.cwe === e.cwe && (f.title === e.title || (e.site && e.site === f.site_addr))) || null;
}
function ResearchQueue({ backlog, findings, targetId, open }) {
  const [openK, setOpenK] = useState(null);
  if (!backlog) return html`<div class="panel empty">No research queue for this case.</div>`;
  const entries = (backlog.entries || []).map((e) => ({ e, f: entryFinding(e, findings) }))
    .filter((x) => !targetId || (x.f && x.f.target_id === targetId));
  const techs = (backlog.techniques || []).slice().sort((a, b) => (b.advances || 0) - (a.advances || 0));
  if (!entries.length) return html`<div class="panel pad"><h2>Research queue</h2>
    <p class="muted" style="font-size:13px;margin:6px 0 0">Nothing queued: every finding the current techniques reached is already
      carried to a validated PoC, or there are no findings yet. This is lykos's reach, not a clearance of the target.</p></div>`;
  return html`<section class="panel" style="overflow:hidden">
    <div class="pad">
      <h2>Research queue — techniques to build next</h2>
      ${backlog.framing ? html`<p class="muted" style="font-size:13px;margin:6px 0 0">${backlog.framing}</p>` : null}
      <p class="dim" style="font-size:12px;margin:6px 0 0">${plural(entries.length, "finding")} not yet at a validated PoC${targetId ? " on this target" : ""} · ${plural(techs.length, "technique")} to build, highest leverage first.</p>
    </div>
    ${techs.map((t, i) => {
      const mine = entries.filter((x) => x.e.missing_technique === t.missing_technique);
      if (targetId && !mine.length) return null;
      const k = i + ":" + t.missing_technique;
      const on = openK === k;
      return html`<div class="pf-rq">
        <button class="pf-rq-h" aria-expanded=${on ? "true" : "false"} onClick=${() => setOpenK(on ? null : k)}>
          <span class="pf-adv" title=${`${t.advances} finding(s) advance when this is built`}>+${t.advances}</span>
          <span style="flex:1 1 auto;min-width:0">${t.missing_technique || "(not yet classified)"}</span>
          <span class="dim" style="flex:none">${on ? "▾" : "▸"}</span>
        </button>
        ${on ? html`<div class="pf-rq-list">${mine.map(({ e, f }) => html`
          <div class="pf-rq-i">
            <span class="mono dim">${e.cwe || "—"}</span>
            ${f ? html`<button class="pf-link pf-trunc" onClick=${() => open(f.id)} title=${f.title}>${e.title || f.title}</button>`
              : html`<span class="pf-trunc" title=${e.title}>${e.title || "(untitled)"}</span>`}
            <span class="dim mono" title="lykos's tooling today → what building the technique would reach">${e.reached || "—"} → ${e.would_reach || "L3"}</span>
            ${e.reason ? html`<span class="dim pf-rq-why">${e.reason}</span>` : null}
          </div>`)}</div>` : null}
      </div>`;
    })}
  </section>`;
}

// ── the board ───────────────────────────────────────────────────────────────────────────────
export function ProofScreen({ data, targetId, open, focusTarget }) {
  const caseId = caseOf(data);
  useCaseSide(caseId, data.findings);
  const [seg, setSeg] = useState("all");
  const [q, setQ] = useState("");
  const [minSev, setMinSev] = useState("");
  const [triage, setTriage] = useState("hide_fp");
  const [facet, setFacet] = useState("");
  const [group, setGroup] = useState(true);
  const [hideNoise, setHideNoise] = useState(true);
  const { findings, pocs, backlog } = data;
  const scoped = useMemo(() => rankFindings(findings.filter((f) => !targetId || f.target_id === targetId), pocs),
    [findings, pocs, targetId]);
  const attack = scoped.filter((f) => f.detector === "attack_path");
  const base = scoped.filter((f) => f.detector !== "attack_path");
  const facets = useMemo(() => facetOptions(base), [scoped]);
  const pre = base.filter((f) => matchQ(f, q) && sevOk(f, minSev) && facetOk(f, facet));
  const byTriage = pre.filter((f) => triageOk(f, triage));
  const triageHidden = pre.length - byTriage.length;
  const laneById = new Map(byTriage.map((f) => [f.id, laneOf(f, pocsOf(f, pocs))]));
  const shown = hideNoise ? byTriage.filter((f) => !(laneById.get(f.id) === "lead" && noiseOf(f))) : byTriage;
  const noiseHidden = byTriage.length - shown.length;
  const units = group ? clusterize(shown) : shown.map((f) => ({ rep: f, members: [] }));
  const lanes = { proven: [], needs: [], lead: [] };
  for (const u of units) lanes[laneById.get(u.rep.id)].push(u);
  const showTarget = !targetId && data.targets.length > 1;
  const tgt = data.targets.find((t) => t.id === targetId);
  const scopeTargets = tgt ? [tgt] : data.targets;
  const filtering = !!(q || minSev || facet || triage !== "hide_fp");
  const clear = () => { setQ(""); setMinSev(""); setFacet(""); setTriage("hide_fp"); };
  const show = (k) => seg === "all" || seg === k;
  const bq = ((backlog && backlog.entries) || []).filter((e) => !targetId || entryFinding(e, base)).length;
  const SEGS = [["all", "All", null], ["proven", "Proven", lanes.proven.length], ["needs", "Needs a PoC", lanes.needs.length],
    ["lead", "Leads", lanes.lead.length], ["crashes", "Crashes", null], ["queue", "Research queue", bq]];
  const board = seg !== "crashes" && seg !== "queue";
  const apShown = attack.filter((f) => triageOk(f, triage) && (seg === "all" || laneOf(f, pocsOf(f, pocs)) === seg));
  return html`
    <div class="pf-head">
      <div style="display:flex;flex-direction:column;gap:3px;min-width:0">
        <h1>${lanes.proven.length} proven · ${lanes.needs.length} need a PoC · ${lanes.lead.length} leads</h1>
        <span class="muted" style="font-size:13px">${tgt ? html`<span class="mono">${tgt.filename}</span> · ` : "All targets · "}
          ${plural(shown.length, "finding")}${group ? ` in ${plural(units.length, "issue")}` : ""} · ranked by what is proven; leads are never shown as proof.</span>
      </div>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <select value=${targetId || ""} onChange=${(e) => focusTarget(e.target.value || null)} aria-label="Target">
          <option value="">All targets</option>
          ${data.targets.map((t) => html`<option value=${t.id}>${t.filename}</option>`)}
        </select>
      </div>
    </div>
    <div class="seg pf-segs" role="group" aria-label="Show">
      ${SEGS.map(([k, l, n]) => html`<button class=${seg === k ? "on" : ""} aria-pressed=${seg === k ? "true" : "false"} onClick=${() => setSeg(k)}>
        ${l}${n != null ? html` <span class="dim">${n}</span>` : null}</button>`)}
    </div>
    ${board ? html`<div class="pf-bar">
      <input type="search" class="pf-search" placeholder="Search title, CWE, function, site…" value=${q}
        onInput=${(e) => setQ(e.target.value)} aria-label="Search findings" />
      <select value=${minSev} onChange=${(e) => setMinSev(e.target.value)} aria-label="Minimum severity">
        <option value="">Any severity</option>
        ${SEVS.map((s, i) => html`<option value=${s}>${s[0].toUpperCase() + s.slice(1)}${i < SEVS.length - 1 ? " and above" : ""}</option>`)}
      </select>
      <select value=${triage} onChange=${(e) => setTriage(e.target.value)} aria-label="Operator triage">
        ${TRIAGE.map(([v, l]) => html`<option value=${v}>${l}</option>`)}
      </select>
      ${facets.length ? html`<select value=${facet} onChange=${(e) => setFacet(e.target.value)} aria-label="More filters">
        <option value="">More filters…</option>
        ${facets.map((g) => html`<optgroup label=${g.label}>${g.opts.map((o) => html`<option value=${g.k + ":" + o.v}>${o.label} (${o.n})</option>`)}</optgroup>`)}
      </select>` : null}
      <label class="pf-check"><input type="checkbox" checked=${group} onChange=${(e) => setGroup(e.target.checked)} />Group into issues</label>
      ${filtering ? html`<button class="btn sm" onClick=${clear}>Clear filters</button>` : null}
    </div>` : null}
    ${board && (triageHidden || noiseHidden) ? html`<div class="pf-hidden">
      ${triageHidden ? html`<span>${plural(triageHidden, "finding")} ${triage === "hide_fp" ? "marked false positive" : "outside the triage filter"} hidden
        <button class="pf-mini" onClick=${() => { setTriage("all"); setHideNoise(false); }}>show</button></span>` : null}
      ${noiseHidden ? html`<span>${plural(noiseHidden, "lead")} hidden as noise${triage !== "hide_fp" ? " or false positive" : ""}
        <button class="pf-mini" onClick=${() => setHideNoise(false)}>show</button></span>` : null}
    </div>` : null}
    ${data.loading ? html`<div class="panel empty">Loading findings…</div>`
      : data.error && !scoped.length ? html`<div class="panel empty">Could not load the findings: ${data.error}
          <div style="margin-top:10px"><button class="btn sm" onClick=${() => data.reload()}>Retry</button></div></div>`
      : seg === "crashes" ? html`<div class="pf-stack">${scopeTargets.length
          ? scopeTargets.map((t) => html`<${TargetCrashes} key=${t.id} t=${t} open=${open} showName=${scopeTargets.length > 1} />`)
          : html`<div class="panel empty">No targets in this case.</div>`}</div>`
      : seg === "queue" ? html`<${ResearchQueue} backlog=${backlog} findings=${base} targetId=${targetId} open=${open} />`
      : !scoped.length ? html`<div class="panel empty">No findings yet. Start an analysis on the Run screen.</div>`
      : html`
        ${seg === "all" ? html`<${ChainStrip} targets=${scopeTargets} data=${data} open=${open} />` : null}
        ${apShown.map((f) => html`<${AttackPathCard} f=${f} pocs=${pocsOf(f, pocs)} findings=${base} open=${open} />`)}
        ${!shown.length ? html`<div class="panel empty">No findings match the filters.
            ${filtering ? html`<div style="margin-top:10px"><button class="btn sm" onClick=${clear}>Clear filters</button></div>` : null}</div>`
        : html`<div class="lanes">
          ${show("proven") ? html`<section class="lane" aria-label="Proven">
            <div class="lane-h blue"><span class="dot live"></span>PROVEN — A POC RAN</div>
            ${lanes.proven.length ? lanes.proven.map((u) => html`<${ProvenCard} key=${u.rep.id} u=${u} pocsBy=${pocs} open=${open} showTarget=${showTarget} />`)
              : html`<div class="panel empty" style="padding:22px">Nothing proven yet.</div>`}
          </section>` : null}
          ${show("needs") ? html`<section class="lane" aria-label="Needs a PoC">
            <div class="lane-h amber"><span class="dot" style="background:var(--amber)"></span>REAL, NO POC YET — WHAT IT TAKES</div>
            ${lanes.needs.length ? lanes.needs.map((u) => html`<${NeedsCard} key=${u.rep.id} u=${u} pocsBy=${pocs} backlog=${backlog} open=${open} showTarget=${showTarget} />`)
              : html`<div class="panel empty" style="padding:22px">None.</div>`}
          </section>` : null}
          ${show("lead") ? html`<section class="lane" aria-label="Leads">
            <div class="lane-h"><span class="dot" style="background:transparent;border:1px solid var(--tx3)"></span>LEADS — NOT VERIFIED
              <label class="pf-check" style="margin-left:auto;font-weight:400;letter-spacing:0">
                <input type="checkbox" checked=${hideNoise} onChange=${(e) => setHideNoise(e.target.checked)} />hide noise${noiseHidden ? ` (${noiseHidden})` : ""}</label></div>
            <div class="panel" style="overflow:hidden">
              ${lanes.lead.length ? lanes.lead.map((u) => html`<${LeadRow} key=${u.rep.id} u=${u} open=${open} showTarget=${showTarget} pocsBy=${pocs} />`)
                : html`<div class="empty" style="padding:22px">None.</div>`}
            </div>
          </section>` : null}
        </div>`}`}`;
}

// ── detail: PoC pieces ──────────────────────────────────────────────────────────────────────
function hexdump(bytes, max = 512) {
  const n = Math.min(bytes.length, max), rows = [];
  for (let i = 0; i < n; i += 16) {
    let hex = "", asc = "";
    for (let j = 0; j < 16; j++) {
      if (i + j < n) {
        const b = bytes[i + j];
        hex += b.toString(16).padStart(2, "0") + " ";
        asc += b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
      } else hex += "   ";
      if (j === 7) hex += " ";
    }
    rows.push(i.toString(16).padStart(8, "0") + "  " + hex + " " + asc);
  }
  if (bytes.length > max) rows.push(`… ${bytes.length - max} more bytes — download for the full input`);
  return rows.join("\n");
}

function Payload({ sha }) {
  const [st, setSt] = useState({ b: null, err: null, big: 0 });
  useEffect(() => {
    let live = true;
    setSt({ b: null, err: null, big: 0 });
    fetch("/artifacts/" + sha).then(async (r) => {
      if (!r.ok) throw new Error("HTTP " + r.status);
      const len = +(r.headers.get("content-length") || 0);
      if (len > (8 << 20)) { if (live) setSt({ b: null, err: null, big: len }); return; }
      const b = new Uint8Array(await r.arrayBuffer());
      if (live) setSt({ b, err: null, big: 0 });
    }).catch((e) => { if (live) setSt({ b: null, err: String(e.message || e), big: 0 }); });
    return () => { live = false; };
  }, [sha]);
  if (st.err) return html`<div class="dim pf-pad-s">Could not read the input: ${st.err}</div>`;
  if (st.big) return html`<div class="dim pf-pad-s">${fmtBytes(st.big)} — too large to preview; download it.</div>`;
  if (!st.b) return html`<div class="dim pf-pad-s">Reading input…</div>`;
  return html`<div><div class="dim" style="font-size:11.5px;margin:4px 0">${fmtBytes(st.b.length)}</div><pre class="pf-hex">${hexdump(st.b)}</pre></div>`;
}

// Re-run a recorded input in the sandbox N times (POST /targets/{id}/replay) and show the result.
function Replay({ tid, sha, caseId }) {
  const [times, setTimes] = useState(5);
  const [st, setSt] = useState({ busy: false, v: null, err: null });
  const go = async () => {
    setSt({ busy: true, v: null, err: null });
    try {
      const v = await api.replay(tid, { input_sha: sha, times });
      setSt({ busy: false, v, err: null });
      loadCaseSide(caseId);       // the verdict is persisted server-side; refresh every badge
    } catch (e) { setSt({ busy: false, v: null, err: String(e.message || e) }); }
  };
  const v = st.v;
  return html`<div class="pf-replay">
    <div class="row-c" style="flex-wrap:wrap;gap:6px">
      <button class="btn sm" disabled=${st.busy} onClick=${go} title="re-run this input against the target in the sandbox">${st.busy ? "Replaying…" : "Replay"}</button>
      <select value=${times} onChange=${(e) => setTimes(+e.target.value)} aria-label="Replay runs" disabled=${st.busy}>
        ${[1, 3, 5, 10].map((n) => html`<option value=${n}>${n}×</option>`)}
      </select>
      ${v ? html`<span class=${"chip " + (v.crashed === v.runs ? "on" : "pf-warn")}>crashed ${v.crashed}/${v.runs}${v.signal ? " · " + v.signal : ""}</span>` : null}
    </div>
    ${v ? html`<div class="dim" style="font-size:12px">${v.deterministic ? "Deterministic: the input crashed on every run."
      : v.crashed ? "Not deterministic: the input crashed on some runs only — treat as flaky evidence."
      : "The input did not crash in this sandbox on any run."}${v.input_mode ? ` Delivered via ${v.input_mode}.` : ""}</div>` : null}
    ${st.err ? html`<div class="pf-err">Replay failed: ${st.err}</div>` : null}
  </div>`;
}

const HEXKEY = /(^|_)(pc|addr|base|address)(_|$)|^addr_/;
function scalarRows(obj) {
  return Object.entries(obj || {}).filter(([, v]) => v != null && typeof v !== "object")
    .map(([k, v]) => [k, typeof v === "number" && HEXKEY.test(k) ? "0x" + v.toString(16) : String(v)]);
}

// The INNER files of a PoC bundle (GET /artifacts/{sha}/bundle): reproduce, payload, technique, files.
function BundleInspector({ sha }) {
  const [d, setD] = useState(null);
  const [err, setErr] = useState(null);
  const [tab, setTab] = useState("repro");
  const [view, setView] = useState(null);
  useEffect(() => {
    let live = true;
    setD(null); setErr(null); setView(null);
    api.bundle(sha).then((x) => { if (live) setD(x); }).catch((e) => { if (live) setErr(String(e.message || e)); });
    return () => { live = false; };
  }, [sha]);
  if (err) return html`<div class="pf-insp dim pf-pad-s">Bundle unavailable: ${err}</div>`;
  if (!d) return html`<div class="pf-insp dim pf-pad-s">Reading bundle…</div>`;
  const files = d.files || [];
  const base = (f) => f.name.split("/").pop();
  const byBase = (b) => files.find((f) => base(f) === b);
  const runner = byBase("runner.sh"), script = byBase("exploit.py"), prim = byBase("PRIMITIVE.txt"), readme = byBase("README.txt");
  const payload = files.find((f) => f.kind === "payload");
  const dir = files.length && files[0].name.includes("/") ? files[0].name.split("/")[0] : null;
  const tarName = `poc-${short(sha)}.tar.gz`;
  const meta = d.meta || {};
  const metaRows = scalarRows(meta), primRows = scalarRows(meta.primitive);
  const TABS = [["repro", "Reproduce"], payload ? ["payload", "Payload"] : null, ["technique", "Technique"], ["files", `Files (${files.length})`]].filter(Boolean);
  return html`<div class="pf-insp">
    <div class="pf-tabs" role="tablist">${TABS.map(([k, l]) => html`<button role="tab" aria-selected=${tab === k ? "true" : "false"}
      class=${"tab" + (tab === k ? " on" : "")} onClick=${() => setTab(k)}>${l}</button>`)}
      <a class="pf-mini" style="margin-left:auto" href=${d.download || "/artifacts/" + sha} download=${tarName}>Download bundle</a></div>
    ${tab === "repro" ? html`<div class="pf-insp-b">
      ${runner ? html`<div class="dim" style="font-size:12px">Offline: unpack the bundle and run its reproducer (in a sandbox / VM).</div>
        <pre class="pf-pre">${`$ tar -xzf ${tarName}${dir ? ` && cd ${dir}` : ""}\n$ sh ./runner.sh`}</pre>
        <div class="pf-cap">runner.sh</div><pre class="pf-pre">${runner.text}</pre>` : null}
      ${script ? html`<div class="pf-cap">exploit.py <button class="pf-mini" onClick=${() => saveText("exploit.py", script.text)}>save</button></div><pre class="pf-pre">${script.text}</pre>` : null}
      ${!runner && !script ? html`<div class="dim">This bundle has no runner.sh / exploit.py; see Files.</div>` : null}
    </div>` : null}
    ${tab === "payload" && payload ? html`<div class="pf-insp-b">
      <div class="pf-cap">${base(payload)} <span class="dim">(${fmtBytes(payload.size)}${payload.preview_len < payload.size ? `, first ${payload.preview_len} shown` : ""})</span></div>
      <pre class="pf-hex">${payload.hexdump}</pre></div>` : null}
    ${tab === "technique" ? html`<div class="pf-insp-b">
      ${metaRows.length ? html`<dl class="pf-kv">${metaRows.map(([k, v]) => html`<dt>${k}</dt><dd class="mono">${v}</dd>`)}</dl>` : null}
      ${primRows.length ? html`<div class="pf-cap">primitive</div><dl class="pf-kv">${primRows.map(([k, v]) => html`<dt>${k}</dt><dd class=${k === "note" ? "" : "mono"}>${v}</dd>`)}</dl>` : null}
      ${prim ? html`<div class="pf-cap">PRIMITIVE.txt</div><pre class="pf-pre">${prim.text}</pre>` : null}
      ${readme ? html`<details><summary class="pf-cap" style="cursor:pointer">README.txt</summary><pre class="pf-pre">${readme.text}</pre></details>` : null}
      ${!metaRows.length && !prim && !readme ? html`<div class="dim">No technique notes in this bundle.</div>` : null}
    </div>` : null}
    ${tab === "files" ? html`<div class="pf-insp-b">
      <div class="pf-tbl">${files.map((f) => html`<div class="pf-file">
        <span class="mono pf-trunc" title=${f.name}>${f.name}</span><span class="dim">${f.kind}</span><span class="dim">${fmtBytes(f.size)}</span>
        <span class="row-c" style="gap:4px;justify-content:flex-end">
          ${f.kind === "text" ? html`<button class="pf-mini" aria-pressed=${view === f.name ? "true" : "false"} onClick=${() => setView(view === f.name ? null : f.name)}>${view === f.name ? "hide" : "view"}</button>
            <button class="pf-mini" onClick=${() => saveText(base(f), f.text)}>save</button>`
            : f.kind === "payload" ? html`<button class="pf-mini" onClick=${() => setTab("payload")}>hexdump</button>`
            : html`<span class="dim" style="font-size:11px">in the bundle</span>`}
        </span></div>
        ${view === f.name ? html`<pre class="pf-pre" style="margin:4px 0 8px">${f.text || "(empty)"}</pre>` : null}`)}</div>
    </div>` : null}
  </div>`;
}

function PocItem({ p, f, tid }) {
  const [panel, setPanel] = useState(null);     // "bundle" | "payload" | null
  const vm = bus.verifs[f.case_id] || {};
  const v = p.input_sha ? vm[p.input_sha] : null;
  const r = ran(p);
  const tog = (k) => setPanel((x) => (x === k ? null : k));
  return html`<div class="poc">
    <div class="row-c" style="flex-wrap:wrap">
      <${LevelBadge} level=${lvlTxt(p.level)} constructed=${!r} />
      <span class=${"chip" + (r ? " on" : "")} title=${r ? "an execution fired the oracle" : "built by analysis — not executed here"}>
        ${r ? (p.provenance === "detonated" ? "detonated" : "verified") : (p.provenance || "unverified") + " · not executed"}</span>
      <${VerifyChip} v=${v} />
      <span class="dim" style="font-size:11px">${fmtTime(p.created_at)}</span>
    </div>
    ${p.signal ? html`<div class="mono dim" style="font-size:11.5px;word-break:break-word">${p.signal}</div>` : null}
    <div class="row-c" style="flex-wrap:wrap;gap:6px">
      ${p.input_sha ? html`<a class="btn sm" href=${"/artifacts/" + p.input_sha} download=${`poc-${short(p.input_sha)}.bin`}>Input</a>
        <button class="btn sm" aria-expanded=${panel === "payload" ? "true" : "false"} onClick=${() => tog("payload")}>Hexdump</button>` : null}
      ${p.bundle_sha ? html`<a class="btn sm" href=${"/artifacts/" + p.bundle_sha} download=${`poc-${short(p.bundle_sha)}.tar.gz`}>Bundle</a>
        <button class="btn sm" aria-expanded=${panel === "bundle" ? "true" : "false"} onClick=${() => tog("bundle")}>Inspect bundle</button>` : null}
      ${!p.input_sha && !p.bundle_sha ? html`<span class="dim" style="font-size:12px">no stored input or bundle</span>` : null}
    </div>
    ${p.input_sha ? html`<${Replay} tid=${tid} sha=${p.input_sha} caseId=${f.case_id} />` : null}
    ${panel === "payload" ? html`<${Payload} sha=${p.input_sha} />` : null}
    ${panel === "bundle" ? html`<${BundleInspector} sha=${p.bundle_sha} />` : null}
  </div>`;
}

// ── detail: triage (operator curation) ──────────────────────────────────────────────────────
function CurationPanel({ f, related }) {
  const cur = curOf(f) || {};
  const [note, setNote] = useState(cur.note || "");
  const [all, setAll] = useState(false);
  const [st, setSt] = useState({ busy: false, err: null, ok: null });
  const hist = useJSON(`/findings/${f.id}/curation`);
  useEffect(() => { setNote((curOf(f) || {}).note || ""); setAll(false); }, [f.id]);
  const save = async (status, n) => {
    setSt({ busy: true, err: null, ok: null });
    try {
      await saveCuration(all ? [f, ...related] : [f], status, n);
      setSt({ busy: false, err: null, ok: "Saved" });
      hist.reload();
      loadCaseSide(f.case_id);
    } catch (e) { setSt({ busy: false, err: String(e.message || e), ok: null }); }
  };
  const status = cur.status || null;
  const history = ((hist.data && hist.data.history) || []).slice().reverse();
  return html`<section class="panel pad">
    <h2>Triage</h2>
    <p class="dim" style="font-size:12px;margin:4px 0 8px">Your verdict sits beside the tool's state — it never changes the evidence or the level.</p>
    <div class="pf-tri" role="group" aria-label="Triage verdict">
      ${CUR_STATUSES.map((s) => html`<button class=${"pf-tri-b pf-cur-" + s + (status === s ? " on" : "")} aria-pressed=${status === s ? "true" : "false"}
        disabled=${st.busy} title=${status === s ? "click again to clear" : CUR_TIP[s]} onClick=${() => save(status === s ? null : s, note)}>${curLabel(s)}</button>`)}
    </div>
    <label class="field" style="margin-top:10px">Note
      <textarea class="pf-note" rows="3" maxlength="4000" value=${note} onInput=${(e) => setNote(e.target.value)}
        placeholder="why — e.g. unreachable from input, test-only code, reproduced manually…"></textarea></label>
    ${related.length ? html`<label class="pf-check" style="margin-top:6px"><input type="checkbox" checked=${all} onChange=${(e) => setAll(e.target.checked)} />
      also apply to the ${plural(related.length, "related finding")} in this issue</label>` : null}
    <div class="row-c" style="margin-top:8px;flex-wrap:wrap">
      <button class="btn sm" disabled=${st.busy || note === (cur.note || "")} onClick=${() => save(status, note)}>Save note</button>
      ${st.ok ? html`<span class="dim" style="font-size:12px">${st.ok}</span>` : null}
      ${st.err ? html`<span class="pf-err">Could not save: ${st.err}</span>` : null}
    </div>
    ${history.length ? html`<details style="margin-top:10px"><summary class="dim" style="font-size:12px;cursor:pointer">History (${history.length})</summary>
      <ul class="pf-hist">${history.map((h) => html`<li><span class="dim">${fmtTime(h.updated_at)}</span>
        <b>${h.status ? curLabel(h.status) : "cleared"}</b>${h.note ? html` — ${h.note}` : null}</li>`)}</ul></details>` : null}
  </section>`;
}

// ── detail: analysis pieces ─────────────────────────────────────────────────────────────────
function Ladder({ state }) {
  const at = Math.max(0, LADDER.indexOf(state || "candidate"));
  return html`<div class="pf-ladder" aria-label=${"confirmation ladder: " + state}>
    ${LADDER.map((r, i) => html`${i ? html`<span class=${"pf-arr" + (i <= at ? " on" : "")}>→</span>` : null}
      <span class=${"pf-rung" + (i <= at ? " on" : "") + (i === at ? " cur" : "")} title=${STATE_GLOSS[r]}>${r}</span>`)}
  </div>`;
}

function exploitRating(f) {
  const e = ev(f, "exploitability");
  if (!e) return null;
  const m = /exploitability:\s*([A-Z_]+)\s*\((\d+)\/100\)\s*(?:--\s*)?(.*)/s.exec(e.detail || "");
  return m ? { rating: m[1], score: +m[2], why: m[3] } : { text: e.detail };
}

function Effects({ f }) {
  const list = parseJSON((ev(f, "effects") || {}).detail || "[]", []);
  if (!Array.isArray(list) || !list.length) return null;
  return html`<section class="panel pad">
    <h2>End effects</h2>
    <p class="dim" style="font-size:12px;margin:4px 0 6px">What the defect can reach — demonstrated (a PoC gets there) or potential (the class implies it).</p>
    <ul class="pf-eff">${list.map((e) => html`<li class=${e.status === "demonstrated" ? "on" : ""}>
      <span class="row-c" style="flex-wrap:wrap"><b>${e.status === "demonstrated" ? "✓ " : "○ "}${e.title || e.kind}</b>
        <span class=${"chip" + (e.status === "demonstrated" ? " on" : "")}>${e.status}</span>
        ${e.proof && e.proof.sha ? html`<a class="pf-mini" href=${"/artifacts/" + e.proof.sha} download>${e.proof.type === "bundle" ? "proof PoC" : e.proof.type === "artifact" ? "captured bytes" : "proof input"}</a>` : null}</span>
      ${(e.proof && e.proof.note) || e.detail ? html`<span class="card-b">${(e.proof && e.proof.note) || e.detail}</span>` : null}
    </li>`)}</ul>
  </section>`;
}

// leaked 64-bit words, classified by the x86-64 Linux user-space layout (only shown for x86-64)
function classifyWord(w) {
  let v; try { v = BigInt(w); } catch (_e) { return null; }
  if (v === 0n) return null;
  const bytes = []; let t = v;
  for (let i = 0; i < 8; i++) { bytes.push(Number(t & 0xffn)); t >>= 8n; }
  const nz = bytes.filter((b) => b !== 0);
  if (nz.length && nz.every((b) => b >= 0x20 && b < 0x7f)) return { t: "ASCII bytes (echoed input?)", c: "ascii" };
  if (v >= 0x7fffff000000n && v < 0x800000000000n) return { t: "stack pointer", c: "ptr" };
  if (v >= 0x7f0000000000n && v < 0x7fffff000000n) return { t: "library pointer (libc / ld)", c: "ptr" };
  if (v >= 0x555500000000n && v < 0x565600000000n) return { t: "PIE image pointer", c: "ptr" };
  if (v >= 0x400000n && v < 0x500000n) return { t: "non-PIE image pointer", c: "ptr" };
  return { t: "data word", c: "data" };
}
function Disclosure({ f }) {
  if (!/x86-64|x86_64|amd64/i.test(f.target_arch || "")) return null;
  const seen = new Set(), words = [];
  for (const e of f.evidence || []) {
    if (!["effects", "injection", "disclosure", "dynamic", "leak"].includes(e.channel)) continue;
    for (const m of (e.detail || "").match(/0x[0-9a-fA-F]{6,16}\b/g) || []) if (!seen.has(m)) { seen.add(m); words.push(m); }
  }
  const rows = words.map((w) => ({ w, ...(classifyWord(w) || {}) })).filter((r) => r.t);
  if (rows.length < 2 || !rows.some((r) => r.c === "ptr")) return null;
  return html`<section class="panel pad">
    <h2>Disclosed words</h2>
    <p class="dim" style="font-size:12px;margin:4px 0 6px">Values quoted in the leak evidence, classified by the x86-64 address layout (a heuristic — verify before relying on one).</p>
    <div class="pf-tbl">${rows.map((r) => html`<div class="pf-kvrow"><span class="mono">${r.w}</span><span class=${r.c === "ptr" ? "" : "dim"}>${r.t}</span></div>`)}</div>
  </section>`;
}

function Customize({ f }) {
  const usage = ev(f, "builder-usage"), guide = ev(f, "customize"), script = ev(f, "exploit-script");
  if (!usage && !guide && !script) return null;
  return html`<section class="panel pad">
    <h2>Customize / retarget this PoC</h2>
    ${usage ? html`<pre class="pf-pre pf-wrap">${usage.detail}</pre>` : null}
    ${guide ? html`<div class="pf-cap">How to retarget it</div><pre class="pf-pre pf-wrap">${guide.detail}</pre>` : null}
    ${script ? html`<div class="pf-cap">Editable exploit builder <button class="pf-mini" onClick=${() => saveText("poc.py", script.detail)}>save poc.py</button></div>
      <pre class="pf-pre">${script.detail}</pre>` : null}
  </section>`;
}

// analyst notes by fault class, tuned by the target's real mitigations (proven findings only)
const NEXT_STEPS = {
  "stack-return-overwrite": (m) => ["The saved return address is overwritten — find the exact offset to the return address.",
    m.nx === "on" ? "NX is on: chain gadgets (ROP) or ret2libc." : m.nx === "off" ? "NX is off: a jump to shellcode on the stack may work." : null,
    m.pie === "off" ? "PIE is off: gadget and function addresses are fixed." : m.pie === "on" ? "PIE is on: leak a code address first to defeat ASLR." : null,
    m.canary === "on" ? "A stack canary is present: an info-leak is needed to read it first." : null],
  "heap-buffer-overflow": () => ["The overflow reaches adjacent heap memory — aim for a neighbouring object's pointer or size.",
    "Look for a function pointer, vtable or allocator metadata reachable after the overwrite."],
  "null-pointer-dereference": () => ["A NULL/near-NULL dereference is usually a denial of service.",
    "Escalate only if the offset from NULL is attacker-controlled into mapped memory."],
  "out-of-bounds-read": () => ["An out-of-bounds read leaks adjacent memory — use it as an info-leak.",
    "Leak a stack canary or a code/libc address, then pair it with a write primitive."],
  "control-flow-hijack": (m) => ["Execution was redirected — the instruction pointer is controlled.",
    m.pie === "off" ? "PIE is off: point it at a chosen gadget/function directly." : "Leak a code address, then aim the control."],
};
function AnalystNotes({ f, target, proven }) {
  if (!proven) return null;
  const rc = (ev(f, "root-cause") || {}).detail || "";
  const m = /^([a-z-]+)\s*\(/.exec(rc.trim());
  const fn = m && NEXT_STEPS[m[1]];
  if (!fn) return null;
  const steps = fn((target && target.mitigations) || {}).filter(Boolean);
  return html`<section class="panel pad">
    <h2>What an attacker does next</h2>
    <p class="dim" style="font-size:12px;margin:4px 0 0">Analyst notes for a ${m[1]} on this target's mitigations — guidance, not something lykos did.</p>
    <ul class="mit">${steps.map((s) => html`<li>${s}</li>`)}</ul>
  </section>`;
}

function StackFrame({ f, functions }) {
  const fn = functions ? functionAt(functions, f.function_addr || f.site_addr) : null;
  const d = useJSON(fn ? `/functions/${fn.id}` : null);
  const fr = d.data && d.data.frame;
  if (!fr || !(fr.vars || []).length) return null;
  const vars = fr.vars.slice().sort((a, b) => b.offset - a.offset);
  const x86 = /x86/i.test(f.target_arch || "");
  return html`<section class="panel pad">
    <h2>Stack frame — <span class="mono" style="font-weight:500">${d.data.name || fn.name}</span></h2>
    <p class="dim" style="font-size:12px;margin:4px 0 6px">Recovered locals, high addresses first${fr.frame_size ? ` · frame ${fr.frame_size} bytes` : ""}.</p>
    <div class="pf-frame">
      ${x86 ? html`<div class="pf-fr ret"><span class="mono">above frame</span><span>return address · saved frame pointer</span><span></span></div>` : null}
      ${vars.map((v) => html`<div class=${"pf-fr" + (v.is_buffer ? " buf" : "")}>
        <span class="mono">${v.offset < 0 ? "-0x" + (-v.offset).toString(16) : "+0x" + v.offset.toString(16)}</span>
        <span class="mono pf-trunc">${v.name}</span><span class="dim pf-trunc">${[v.type, v.size ? v.size + " B" : null, v.is_buffer ? "buffer" : null].filter(Boolean).join(" · ")}</span></div>`)}
    </div>
  </section>`;
}

function Reachability({ r, toCode, tid }) {
  const path = (r && r.path) || [];
  if (!path.length && !(r && r.attack_surface)) return null;
  return html`<section class="panel pad">
    <h2>Reachability</h2>
    ${r.attack_surface ? html`<p class="card-b" style="margin:6px 0">${r.attack_surface === "on"
      ? "On the fuzzed attack surface — higher remote-reachability priority."
      : "Off the fuzzed attack surface — lower remote-reachability priority, not dismissed."}</p>` : null}
    ${path.length ? html`<p class="dim" style="font-size:12px;margin:4px 0 6px">Path from an input source (control-flow reachability, not verified dataflow).</p>
      <ol class="pf-ap pf-reach">${path.map((hop, i) => html`
        ${i ? html`<li class="pf-ap-arrow" aria-hidden="true">→</li>` : null}
        <li class="pf-ap-node">${hop.addr ? html`<button class="pf-ap-btn" onClick=${() => toCode(tid, hop.addr)} title="view this function's code">
            <span class="mono">${hop.label}</span>${hop.sub ? html`<span class="dim">${hop.sub}</span>` : null}</button>`
          : html`<span class="mono">${hop.label}</span>${hop.sub ? html`<span class="dim">${hop.sub}</span>` : null}`}</li>`)}</ol>` : null}
  </section>`;
}

function Evidence({ f }) {
  const [full, setFull] = useState(false);
  const [raw, setRaw] = useState(false);
  const list = (f.evidence || []).filter((e) => e && e.channel !== "attack-path-steps");
  const chans = new Set(list.map((e) => e.channel)).size;
  const long = list.some((e) => String(e.detail || "").length > 600);
  return html`<section class="panel" style="overflow:hidden">
    <div class="pad" style="padding-bottom:8px;display:flex;flex-wrap:wrap;gap:6px 12px;align-items:baseline">
      <h2>Evidence trail</h2>
      <span class="dim" style="font-size:12px">${plural(list.length, "entry", "entries")} · ${plural(chans, "channel")}${(f.analysis && f.analysis.signals) ? ` · ${(f.analysis.signals || []).length} independent signals` : ""}</span>
      <span style="flex:1 1 auto"></span>
      ${long ? html`<button class="pf-mini" aria-pressed=${full ? "true" : "false"} onClick=${() => setFull((x) => !x)}>${full ? "shorten" : "full text"}</button>` : null}
      <button class="pf-mini" aria-pressed=${raw ? "true" : "false"} onClick=${() => setRaw((x) => !x)}>${raw ? "hide" : "raw"} JSON</button>
    </div>
    ${list.map((e) => {
      const t = String(e.detail || "(no detail)");
      return html`<div class="ev">
        <span class="chip" style="flex:none" title=${e.channel}>${CH_LABEL[e.channel] || e.channel}</span>
        <span class="pf-evt">${full || t.length <= 600 ? t : t.slice(0, 600) + "…"}</span></div>`;
    })}
    ${raw ? html`<pre class="pf-pre" style="margin:0;border-radius:0;border-left:0;border-right:0;border-bottom:0">${JSON.stringify(f, null, 2)}</pre>` : null}
  </section>`;
}

function Sites({ sites, toCode, tid }) {
  const list = (sites || []).filter((s) => s.site_addr || s.function_addr);
  if (list.length < 2) return null;
  return html`<details style="margin-top:8px"><summary class="dim" style="font-size:12px;cursor:pointer">${plural(list.length, "site")}</summary>
    <div class="pf-tbl" style="margin-top:4px">${list.map((s) => html`<div class="pf-kvrow">
      <button class="xref" onClick=${() => toCode(tid, s.site_addr || s.function_addr)}>${s.site_addr || s.function_addr}</button>
      <span class="dim pf-trunc">${[s.function_addr ? "in " + s.function_addr : null, s.state, s.detail].filter(Boolean).join(" · ")}</span></div>`)}</div>
  </details>`;
}

// ── the detail view ─────────────────────────────────────────────────────────────────────────
export function FindingDetail({ data, findingId, back, toCode, open = null }) {
  const [localId, setLocalId] = useState(null);
  useEffect(() => { setLocalId(null); }, [findingId]);
  const id = localId || findingId;
  // main.js may not pass `open`: then hop between findings here and keep the URL in step
  const go = open || ((x) => {
    setLocalId(x);
    try { const h = new URLSearchParams(location.hash.slice(1)); h.set("finding", x); history.replaceState(null, "", "#" + h.toString()); } catch (_e) { /* cosmetic */ }
    try { window.scrollTo(0, 0); } catch (_e) { /* cosmetic */ }
  });
  const base = data.findings.find((x) => x.id === id);
  useCaseSide(base ? base.case_id : caseOf(data), data.findings);
  const full = useJSON(id ? `/findings/${id}` : null);
  const fx = useJSON(base ? `/targets/${base.target_id}/functions` : null);
  if (!base) {
    return html`<div class="panel empty">${data.loading ? "Loading finding…" : "Finding not found."}
      <div style="margin-top:10px"><button class="btn sm" onClick=${back}>← Proof board</button></div></div>`;
  }
  const f = full.data && full.data.id === id ? { ...base, ...full.data } : base;
  const pocs = pocsOf(f, data.pocs);
  const a = f.analysis || {};
  const ex = f.exploitability || {};
  const bl = backlogFor(f, data.backlog);
  const lane = laneOf(f, pocs);
  const target = data.targets.find((t) => t.id === f.target_id);
  const peers = rankFindings(data.findings.filter((x) => x.target_id === f.target_id && x.detector !== "attack_path"), data.pocs);
  const related = f.detector === "attack_path" ? [] : peers.filter((x) => x.id !== f.id && clusterKey(x) === clusterKey(f));
  const rating = exploitRating(f);
  const functions = Array.isArray(fx.data) ? fx.data : fx.data && Array.isArray(fx.data.functions) ? fx.data.functions : null;
  const vs = verifsOf(f, pocs);
  const soundness = ev(f, "soundness"), repro = ev(f, "reproduce");
  return html`
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <button class="btn sm" onClick=${back}>← Proof board</button>
      ${localId ? html`<button class="btn sm" onClick=${() => go(findingId)}>← previous finding</button>` : null}
      <span class="mono dim pf-trunc" style="font-size:12px">${f.target_name || (target && target.filename) || ""}</span>
    </div>
    <div style="display:flex;flex-direction:column;gap:6px;min-width:0">
      <div class="row-c" style="flex-wrap:wrap"><${LevelBadge} level=${bestLevel(pocs)} />
        <span class=${"lvl" + (lane === "needs" ? " amber" : "")}>${f.state}</span>
        ${lane === "lead" ? html`<span class="chip">lead — not verified</span>` : null}
        <${CurChip} f=${f} />
        ${vs.length ? html`<${VerifyChip} v=${vs[0].v} />` : null}
        <${VerdictChip} f=${f} />
        <${ResolveChip} f=${f} />
        <${Meta} f=${f} /></div>
      <h1 class="pf-title">${f.title}</h1>
      ${f.cwe_name ? html`<span class="muted" style="font-size:13px">${f.cwe} — ${f.cwe_name}${f.cwe_desc ? html`<span class="dim"> · ${f.cwe_desc}</span>` : null}</span>` : null}
      <div class="row-c" style="flex-wrap:wrap"><${Ladder} state=${f.state} /><span class="dim" style="font-size:12px">${STATE_GLOSS[f.state] || ""}</span></div>
    </div>
    <div class="detail">
      <div style="flex:999 1 520px;min-width:0;display:flex;flex-direction:column;gap:14px">
        <section class="panel pad">
          <h2>Why it is ${f.state}</h2>
          <p class="card-b" style="margin:6px 0 0">${a.why_state || "—"}</p>
          ${a.to_promote ? html`<p class="next" style="margin-top:10px"><b>To promote it${a.next_state ? ` to ${a.next_state}` : ""}:</b> ${a.to_promote}</p>` : null}
          ${bl ? html`<p class="next" style="margin-top:10px"><b>Technique to build next:</b> ${bl.missing_technique}
            ${bl.reached ? html`<span class="dim"> (reached ${bl.reached}${bl.would_reach ? `, would reach ${bl.would_reach}` : ""})</span>` : null}</p>` : null}
        </section>
        ${resolveOf(f) ? html`<section class="panel pad">
          <h2>Resolution <${ResolveChip} f=${f} /></h2>
          <p class="card-b" style="margin:6px 0 0">${resolveOf(f).detail}</p>
          ${resolveOf(f).reach ? html`<p class="dim" style="margin:8px 0 0;font-size:12.5px">${resolveOf(f).reach}</p>` : null}
        </section>` : null}
        ${f.detector === "attack_path" ? html`<section class="panel pad"><h2>Attack path</h2>
          <p class="dim" style="font-size:12px;margin:4px 0 10px">The deepest attacker path the findings compose — each step a real finding (or a weaponization technique edge), with how far it is demonstrated.</p>
          <${AttackPathDiagram} f=${f} findings=${data.findings.filter((x) => x.target_id === f.target_id)} open=${go} /></section>` : null}
        <section class="panel pad">
          <h2>Proof of concept</h2>
          ${pocs.length ? pocs.map((p) => html`<${PocItem} key=${p.id} p=${p} f=${f} tid=${f.target_id} />`)
            : html`<p class="muted" style="margin:6px 0 0;font-size:13px">No PoC for this finding${lane === "needs" ? " yet — see what it takes above." : "."}</p>`}
          ${repro ? html`<div class="pf-cap" style="margin-top:10px">How to run it</div><pre class="pf-pre">${repro.detail}</pre>` : null}
          ${soundness ? html`<div class="pf-cap" style="margin-top:10px">Why this works</div><pre class="pf-pre pf-wrap">${soundness.detail}</pre>` : null}
        </section>
        <${Effects} f=${f} />
        ${f.prove_out && (f.prove_out.steps || []).length ? html`<section class="panel pad"><h2>Prove it out</h2>
          <p class="dim" style="font-size:12px;margin:4px 0 0">A directed plan to reach poc-backed.</p>
          <ol class="mit">${f.prove_out.steps.map((s) => html`<li>${s}</li>`)}</ol></section>` : null}
        <${Reachability} r=${f.reachability} toCode=${toCode} tid=${f.target_id} />
        <${Disclosure} f=${f} />
        <${AnalystNotes} f=${f} target=${target} proven=${lane === "proven"} />
        <${Customize} f=${f} />
        <${Evidence} f=${f} />
      </div>
      <aside style="flex:1 1 320px;min-width:0;display:flex;flex-direction:column;gap:14px">
        <${CurationPanel} f=${f} related=${related} />
        ${rating || ex.class_primitive || ex.ceiling || ex.demonstrated_level || (ex.mitigations_in_way || []).length ? html`<section class="panel pad">
          <h2>Exploitability</h2>
          ${rating ? html`<div class="row-c" style="flex-wrap:wrap;margin-top:6px">
            ${rating.rating ? html`<span class=${"chip pf-rate-" + (RATING_TONE[rating.rating] || "mid")}>${rating.rating.replace(/_/g, " ").toLowerCase()}${rating.score != null ? ` · ${rating.score}/100` : ""}</span>` : null}</div>
            ${rating.why || rating.text ? html`<p class="card-b" style="margin:6px 0">${rating.why || rating.text}</p>` : null}` : null}
          ${ex.class_primitive ? html`<p class="card-b" style="margin:6px 0"><span class="dim">Primitive (class):</span> ${ex.class_primitive}</p>` : null}
          ${ex.demonstrated_level ? html`<p class="card-b" style="margin:6px 0"><span class="dim">Demonstrated:</span> a verified PoC reached ${ex.demonstrated_level}</p>` : null}
          ${ex.ceiling ? html`<div class="next" style="margin:8px 0"><b>Reach today (lykos's tooling, not the target):</b> weaponized to ${ex.ceiling}${ex.ceiling_reason ? ` — ${ex.ceiling_reason}` : ""}
            ${ex.missing_technique ? html`<div style="margin-top:4px"><b>Technique to build next:</b> ${ex.missing_technique}</div>` : null}
            ${ex.ceiling_framing ? html`<div class="dim" style="margin-top:4px">${ex.ceiling_framing}</div>` : null}</div>` : null}
          ${ex.targets_live ? html`<p class="card-b" style="margin:6px 0"><span class="dim">Live target:</span> ${ex.targets_live}</p>` : null}
          ${(ex.mitigations_in_way || []).length ? html`<div class="dim" style="font-size:11.5px;letter-spacing:.04em;margin-top:6px">MITIGATIONS IN THE WAY</div>
            <ul class="mit">${ex.mitigations_in_way.map((m) => html`<li>${m}</li>`)}</ul>` : null}
        </section>` : null}
        <section class="panel pad">
          <h2>Where</h2>
          <p class="mono" style="margin:6px 0;font-size:12.5px;word-break:break-all">${f.site_addr ? "site " + f.site_addr : "no site address"}${f.function_addr ? " · function " + f.function_addr : ""}</p>
          ${f.site_addr || f.function_addr ? html`<button class="btn sm" onClick=${() => toCode(f.target_id, f.site_addr || f.function_addr)}>View code</button>` : null}
          <${Sites} sites=${f.sites} toCode=${toCode} tid=${f.target_id} />
          ${f.stage_label || f.detector ? html`<p class="dim" style="margin:8px 0 0;font-size:12px">Found by ${f.stage_label || f.stage || "—"} (${f.detector})${f.confidence != null ? ` · confidence ${Math.round(f.confidence * 100)}%` : ""}</p>` : null}
          ${f.verification && f.verification.noise_reason ? html`<p class="dim" style="margin:6px 0 0;font-size:12px">Review: ${f.verification.noise_reason}</p>` : null}
        </section>
        <${StackFrame} f=${f} functions=${functions} />
        ${related.length ? html`<section class="panel pad">
          <h2>Same issue · ${related.length}</h2>
          <p class="dim" style="font-size:12px;margin:4px 0 6px">${f.function_addr ? "Other findings in the same function" : "Other findings with the same CWE and title shape"} — grouped, nothing hidden.</p>
          <div class="pf-tbl">${related.map((r) => html`<button class="pf-rel-i" onClick=${() => go(r.id)} title=${r.title}>
            <span class="mono dim">${r.cwe || "—"}</span><span class="pf-trunc">${r.title || r.detector}</span>
            <span class="dim">${laneOf(r, pocsOf(r, data.pocs)) === "proven" ? "proven" : r.state}</span></button>`)}</div>
        </section>` : null}
      </aside>
    </div>`;
}
