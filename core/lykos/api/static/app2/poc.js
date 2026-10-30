// The PoC spine (doc 58/59): the validated deliverable — provenance, the payload as a HEXDUMP code
// snippet, the repro as a terminal block, and "why this works" as a clean fact list — or an honest
// "no PoC yet" with a pointer to the Status/Evidence that explain it.
import { useState, useEffect } from "preact/hooks";
import { html } from "./html.js";
import { artifactUrl, fetchBytes } from "./store.js";

const LADDER = ["candidate", "corroborated", "confirmed", "poc-backed"];
const LADDER_GLOSS = {
  candidate: "a detector flagged it",
  corroborated: "a second signal agrees (recipe / dataflow)",
  confirmed: "a sound PoC was constructed — proven by analysis, no execution needed",
  "poc-backed": "detonated — an execution fired the oracle",
};

export function ProvBadge({ provenance, verified }) {
  if (provenance === "detonated" || (verified && !provenance))
    return html`<span class="pb det" title=${LADDER_GLOSS["poc-backed"]}>● detonated</span>`;
  if (provenance === "constructed")
    return html`<span class="pb con" title=${LADDER_GLOSS.confirmed}>● constructed</span>`;
  return null;
}

export function ConfirmationLadder({ state }) {
  const at = Math.max(0, LADDER.indexOf(state || "candidate"));
  return html`<div class="ladder">
    ${LADDER.map((rung, i) => html`
      <span class=${"rung" + (i <= at ? " on" : "") + (i === at ? " cur" : "")} title=${LADDER_GLOSS[rung]}>
        ${rung}</span>${i < LADDER.length - 1 ? html`<span class=${"arr" + (i < at ? " on" : "")}>→</span>` : null}`)}
  </div>`;
}

function hexdump(bytes, max = 320) {
  const n = Math.min(bytes.length, max);
  const rows = [];
  for (let i = 0; i < n; i += 16) {
    const off = i.toString(16).padStart(8, "0");
    let hex = "", asc = "";
    for (let j = 0; j < 16; j++) {
      if (i + j < n) {
        const b = bytes[i + j];
        hex += b.toString(16).padStart(2, "0") + " ";
        asc += (b >= 32 && b < 127) ? String.fromCharCode(b) : ".";
      } else hex += "   ";
      if (j === 7) hex += " ";
    }
    rows.push(off + "  " + hex + " " + asc);
  }
  let out = rows.join("\n");
  if (bytes.length > max) out += `\n… ${bytes.length - max} more bytes (download for the full payload)`;
  return out;
}

const evChan = (f, ch) => (f.evidence || []).find((e) => (e.channel || "") === ch);

function Soundness({ detail }) {
  const lines = detail.split("\n").map((l) => l.trim()).filter(Boolean);
  const facts = lines.filter((l) => l.startsWith("- ")).map((l) => l.slice(2));
  const head = lines.find((l) => !l.startsWith("- ")) || "";
  return html`<div class="sound">
    ${head ? html`<div class="sound-h">${head}</div>` : null}
    ${facts.length ? html`<ul class="facts">${facts.map((f) => html`<li>${f}</li>`)}</ul>` : null}
  </div>`;
}

// The exact steps the tester runs to use the payload and see the effect.
function Steps({ repro, signal, sha, bytes }) {
  let cmd = null, note = null;
  if (repro) {
    const lines = repro.split("\n").map((l) => l.trim()).filter(Boolean);
    cmd = lines.find((l) => !l.startsWith("#")) || null;
    note = lines.filter((l) => l.startsWith("#")).map((l) => l.replace(/^#\s?/, "")).join(" ");
  }
  let i = 0;
  const num = () => ++i;
  return html`<ol class="steps">
    <li><span class="st-n">${num()}</span><div class="st-b">
      Download the payload — <a class="lk" href=${artifactUrl(sha)} download=${`poc-${sha.slice(0, 12)}.bin`}>poc.bin</a>
      ${bytes ? html`<span class="muted"> (${bytes.length} bytes)</span>` : null}</div></li>
    ${cmd ? html`<li><span class="st-n">${num()}</span><div class="st-b">
      Run the target against it:<pre class="cmd"><span class="t-p">$</span> ${cmd}</pre></div></li>` : null}
    <li><span class="st-n">${num()}</span><div class="st-b">
      Observe the effect — <span class="st-eff">${signal || "the finding's effect fires"}</span></div></li>
    ${note ? html`<li class="st-note muted">${note}</li>` : null}
  </ol>`;
}

export function PocDeliverable({ finding, pocs }) {
  const mine = (pocs || []).filter((p) => p.finding_id === finding.id);
  const rank = (p) => (p.provenance === "detonated" || p.verified ? 2 : p.provenance === "constructed" ? 1 : 0);
  const best = mine.slice().sort((a, b) => rank(b) - rank(a))[0];
  const sound = evChan(finding, "soundness");
  const repro = evChan(finding, "reproduce");
  const sha = best && best.input_sha;
  const [bytes, setBytes] = useState(null);
  useEffect(() => {
    let on = true; setBytes(null);
    if (sha) fetchBytes(sha).then((b) => { if (on) setBytes(b); });
    return () => { on = false; };
  }, [sha]);

  if (!sha) {
    return html`<div class="deliver none">
      <div class="none-h">No PoC constructed yet</div>
      <div class="muted">${finding.state === "corroborated"
        ? "A recipe/dataflow signal corroborates this; the trigger wasn't closed here. The Status and Evidence trail below carry the computed recipe and what would advance it."
        : "A detector flagged this; it isn't corroborated or weaponized yet."}</div>
    </div>`;
  }
  const lvl = String(best.level || "").replace(/^L?/, "L");
  return html`<div class="deliver">
    <div class="dl-top">
      <span class="dl-lvl">${lvl}</span>
      <${ProvBadge} provenance=${best.provenance} verified=${best.verified} />
      ${best.signal ? html`<span class="dl-sig mono">${best.signal}</span>` : null}
      <a class="btn sm" href=${artifactUrl(sha)} download=${`poc-${sha.slice(0, 12)}.bin`}>⬇ payload</a>
    </div>
    <div class="blk"><div class="blk-h">How to use this PoC</div>
      <${Steps} repro=${repro && repro.detail} signal=${best.signal} sha=${sha} bytes=${bytes} /></div>
    <div class="blk"><div class="blk-h">Payload ${bytes ? html`<span class="muted">· ${bytes.length} bytes</span>` : null}</div>
      <pre class="hex">${bytes ? hexdump(bytes) : "loading…"}</pre></div>
    ${sound ? html`<div class="blk"><div class="blk-h">Why this works</div><${Soundness} detail=${sound.detail} /></div>` : null}
  </div>`;
}
