// The binary/ELF overview: identity, architecture, security posture, invocation surface, and the
// analysis summary — everything known about the target as a whole, as its own view.
import { html } from "./html.js";

function fmtBytes(n) {
  if (n == null) return "—";
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

// label, description, and whether this mitigation being ABSENT favours the attacker (weak = good for us)
const MITS = [
  ["nx", "NX / DEP", "no exec stack/heap"],
  ["pie", "PIE / ASLR", "address randomization"],
  ["relro", "RELRO", "GOT write-protection"],
  ["bind_now", "BIND_NOW", "eager GOT binding"],
  ["canary", "Stack canary", "stack-overflow guard"],
  ["fortify", "FORTIFY", "libc bounds checks"],
  ["seccomp", "seccomp", "syscall filter"],
];
function posture(v) {
  if (v === "partial") return "part";
  return (v === "on" || v === "full" || v === true) ? "on" : "off";  // off = weaker = attacker-favourable
}

export function SecurityPosture({ m }) {
  if (!m) return null;
  return html`<div class="posture">${MITS.map(([k, label, desc]) => {
    const v = m[k]; if (v == null) return null;
    const p = posture(v);
    return html`<div class=${"pm " + p} title=${p === "off" ? "absent — favours exploitation" : "present"}>
      <div class="pm-top"><span class="pm-l">${label}</span>
        <span class="pm-v">${typeof v === "boolean" ? (v ? "on" : "off") : v}</span></div>
      <div class="pm-d">${desc}</div></div>`;
  })}</div>`;
}

function KV({ k, v, mono }) {
  return (v == null || v === "") ? null
    : html`<div class="kv"><span class="k">${k}</span><span class=${"vv" + (mono ? " mono" : "")}>${v}</span></div>`;
}

export function BinaryOverview({ target, advice, findings, pocs }) {
  if (!target) return html`<div class="pane-pad muted">No target loaded.</div>`;
  const t = target;
  const confirmed = (findings || []).filter((f) => f.state === "poc-backed" || f.state === "confirmed").length;
  const withPoc = (pocs || []).filter((p) => p.input_sha).length;
  const deps = t.deps ? (Array.isArray(t.deps) ? t.deps.join(", ") : String(t.deps)) : "none resolved";
  return html`<div class="overview">
    <div class="ov-head">
      <div class="ov-title">${t.filename}</div>
      <div class="ov-sub">${[String(t.file_type || "").toUpperCase(), `${t.arch}/${t.bits}`, t.endianness,
        t.linking, t.stripped ? "stripped" : "with symbols"].filter(Boolean).join("  ·  ")}</div>
    </div>

    <div class="cards">
      <div class="card">
        <div class="card-h">Identity</div>
        <${KV} k="Size" v=${fmtBytes(t.size)} />
        <${KV} k="Entropy" v=${t.entropy != null ? t.entropy.toFixed(2) : null} />
        <${KV} k="Toolchain" v=${t.toolchain_hint} />
        <${KV} k="SHA-256" v=${t.sha256} mono=${true} />
        <${KV} k="MD5" v=${t.md5} mono=${true} />
      </div>
      <div class="card">
        <div class="card-h">Invocation & surface</div>
        <${KV} k="Input" v=${advice && advice.input_mode} />
        <${KV} k="Shape" v=${advice && advice.shape} />
        <${KV} k="Linking" v=${t.linking} />
        <${KV} k="Dependencies" v=${deps} />
      </div>
      <div class="card">
        <div class="card-h">Findings</div>
        <${KV} k="Total" v=${(findings || []).length} />
        <${KV} k="Confirmed / PoC-backed" v=${confirmed} />
        <${KV} k="With a PoC payload" v=${withPoc} />
      </div>
    </div>

    <div class="sect-h mt">Security posture <span class="muted">— green = absent, favours exploitation</span></div>
    <${SecurityPosture} m=${t.mitigations} />

    ${advice && advice.headline ? html`<div class="headline">
      <span class="hl-k">Analysis</span> ${advice.headline}</div>` : null}
  </div>`;
}
