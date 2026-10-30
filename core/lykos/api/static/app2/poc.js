// The new model's spine (doc 58/59): per finding, the validated PoC DELIVERABLE -- payload + a
// few-line repro + the soundness argument + a provenance badge -- or an honest dead-end. These are
// the shared blocks the remodeled finding card leads with; they replace the old "prove it out plan".
import { html } from "./html.js";
import { artifactUrl } from "./store.js";

const LADDER = ["candidate", "corroborated", "confirmed", "poc-backed"];
const LADDER_GLOSS = {
  candidate: "a detector flagged it",
  corroborated: "a second signal agrees (recipe / dataflow)",
  confirmed: "a sound PoC was CONSTRUCTED — proven by analysis, no execution needed",
  "poc-backed": "DETONATED — an execution fired the oracle",
};

// provenance badge: detonated (oracle fired) vs constructed (sound, not run here).
export function ProvBadge({ provenance, verified }) {
  if (provenance === "detonated" || (verified && !provenance))
    return html`<span class="b2 det" title=${LADDER_GLOSS["poc-backed"]}>✓ detonated</span>`;
  if (provenance === "constructed")
    return html`<span class="b2 con" title=${LADDER_GLOSS.confirmed}>· constructed (sound)</span>`;
  return null;
}

// candidate → corroborated → confirmed → poc-backed, with the reached rung lit.
export function ConfirmationLadder({ state }) {
  const at = Math.max(0, LADDER.indexOf(state || "candidate"));
  return html`<div class="ladder2">
    ${LADDER.map((rung, i) => html`
      <span class=${"rung" + (i <= at ? " on" : "") + (i === at ? " cur" : "")}
            title=${LADDER_GLOSS[rung]}>${rung}</span>`)}
  </div>`;
}

const evChan = (f, ch) => (f.evidence || []).find((e) => (e.channel || "") === ch);

// The deliverable: lead with the lightweight PoC when one exists, else the honest state.
export function PocDeliverable({ finding, pocs }) {
  const mine = (pocs || []).filter((p) => p.finding_id === finding.id);
  // best PoC: a detonated one outranks a constructed one; both outrank nothing.
  const rank = (p) => (p.provenance === "detonated" || p.verified ? 2 : p.provenance === "constructed" ? 1 : 0);
  const best = mine.slice().sort((a, b) => rank(b) - rank(a))[0];
  const sound = evChan(finding, "soundness");
  const repro = evChan(finding, "reproduce");
  if (!best || !best.input_sha) {
    // no constructed payload -> honest dead-end, not a fabricated "plan".
    return html`<div class="deliver none">
      <div class="dl-h">No PoC constructed</div>
      ${sound ? html`<pre class="sound">${sound.detail}</pre>` : html`<div class="muted">
        This finding has not reached a constructed PoC. ${finding.state === "corroborated"
          ? "A recipe/dataflow signal corroborates it; the trigger could not be closed here." : ""}</div>`}
    </div>`;
  }
  const lvl = String(best.level || "").replace(/^L?/, "L");
  return html`<div class="deliver">
    <div class="dl-h">
      <span class="lvl">${lvl}</span>
      <${ProvBadge} provenance=${best.provenance} verified=${best.verified} />
      ${best.signal ? html`<span class="sig">${best.signal}</span>` : null}
    </div>
    <div class="dl-row">
      <a class="btn" href=${artifactUrl(best.input_sha)} download=${`poc-${(best.input_sha||"").slice(0,12)}.bin`}>⬇ payload</a>
      <span class="muted mono">${(best.input_sha || "").slice(0, 16)}…</span>
    </div>
    ${repro ? html`<pre class="repro2">${repro.detail}</pre>` : null}
    ${sound ? html`<details class="sfold"><summary>soundness argument</summary>
      <pre class="sound">${sound.detail}</pre></details>` : null}
  </div>`;
}
