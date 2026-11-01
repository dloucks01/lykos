// Real technical substance for a finding: the disassembly of its function (sink highlighted), the
// stack-frame memory layout, and cross-references — all from the recovered function detail.
import { html } from "./html.js";

const hx = (n) => (n == null ? "" : (n < 0 ? "-0x" + (-n).toString(16) : "0x" + n.toString(16)));
const norm = (a) => (a == null ? null : (typeof a === "string" ? parseInt(a, 16) : a));

export function Disasm({ ir, siteAddr, signature, source }) {
  if (source) {
    return html`<div class="code">
      ${signature ? html`<div class="code-sig">${signature}</div>` : null}
      <pre class="src">${source}</pre></div>`;
  }
  if (!ir || !ir.blocks || !ir.blocks.length) return html`<div class="muted pane-pad">no disassembly recovered</div>`;
  const site = norm(siteAddr);
  const lines = [];
  ir.blocks.forEach((b, bi) => {
    if (bi > 0) lines.push({ sep: true });
    (b.instructions || []).forEach((ins) => {
      const a = norm(ins.addr);
      lines.push({ a, text: ins.text, site: site != null && a === site });
    });
  });
  return html`<div class="code">
    ${signature ? html`<div class="code-sig">${signature}</div>` : null}
    <pre class="disasm">${lines.map((l) => l.sep
      ? html`<div class="dsep"></div>`
      : html`<div class=${"dl" + (l.site ? " site" : "")}>
          <span class="da">${hx(l.a)}</span><span class="dt">${l.text}</span>
          ${l.site ? html`<span class="dmark">◄ sink</span>` : null}</div>`)}</pre></div>`;
}

// The stack frame as a memory diagram: high addresses (return addr / saved rbp) on top, locals below.
export function StackFrame({ frame }) {
  if (!frame || !frame.vars || !frame.vars.length) return html`<div class="muted">no frame recovered</div>`;
  const vars = frame.vars.slice().sort((a, b) => b.offset - a.offset);
  const rows = [
    { name: "return address", off: 8, type: "saved rip", kind: "ret" },
    { name: "saved rbp", off: 0, type: "", kind: "sbp" },
    ...vars.map((v) => ({
      name: v.name, off: v.offset,
      type: (v.type || "") + (v.size ? ` · ${v.size}B` : ""),
      kind: v.is_buffer ? "buf" : "var",
    })),
  ];
  return html`<div class="stack">
    ${rows.map((r) => html`<div class=${"srow k-" + r.kind}>
      <span class="soff">rbp${hx(r.off)}</span>
      <span class="sname">${r.name}</span>
      <span class="stype">${r.type}</span></div>`)}
    <div class="srow k-rsp"><span class="soff">rsp→</span><span class="sname">top of stack</span><span class="stype"></span></div>
  </div>`;
}

export function XRefs({ callers, callees }) {
  const cr = callers || [], ce = callees || [];
  if (!cr.length && !ce.length) return null;
  return html`<div class="xrefs">
    <div class="xr">
      <div class="xr-h">called by</div>
      ${cr.length ? cr.map((c) => html`<div class="xr-i">${c.src_name || hx(norm(c.src_addr))}</div>`)
        : html`<div class="xr-none">entry point / not referenced</div>`}
    </div>
    <div class="xr">
      <div class="xr-h">calls</div>
      ${ce.length ? ce.map((c) => html`<div class="xr-i">
        <span class="xr-site">${hx(norm(c.site_addr))}</span> ${c.dst_name || hx(norm(c.dst_addr))}
        ${c.external ? html`<span class="xr-ext">ext</span>` : null}</div>`)
        : html`<div class="xr-none">leaf</div>`}
    </div>
  </div>`;
}
