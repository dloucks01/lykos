// Drive a target by hand: the interactive detonation console (server: api/console.py over the
// /console WebSocket). The target runs in the sandbox behind a PTY; the operator types what a
// menu or protocol handshake needs, and can save everything sent as a reusable seed -- the inputs
// the one-shot dynamic stages cannot reach on their own.
//
// Binary protocols: input is typed as a text line, hex bytes or an escape string (\x00\xff\n),
// and hex / escape send EXACTLY those bytes (no implicit newline). The stdin channel is picked at
// Start: "terminal" (a tty: line editing, Ctrl-C / Ctrl-D keys) or "exact bytes" (a pipe: every
// byte reaches the target as-is and EOF really closes stdin). Output reads as text or as a hex
// transcript of what was sent and received. Wire protocol: JSON text frames ({"t":"in","b64"},
// {"t":"eof"}, {"t":"signal"}, {"t":"save"}), `stdin=pipe|pty` on the /console URL.
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { html } from "../app2/html.js";

const MAX_OUT = 200000;
const MAX_HEX = 64 * 1024;      // bytes kept for the hex transcript (newest win)

function b64ToBytes(b64) {
  try { return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)); } catch (_e) { return new Uint8Array(0); }
}
function bytesToB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

// "de ad be ef", "deadbeef", "0xde,0xad", "\xde\xad" -> bytes. Throws on anything else.
export function parseHex(s) {
  const t = String(s || "").replace(/0x|\\x/gi, "").replace(/[\s,:;-]+/g, "");
  if (!t) return new Uint8Array(0);
  if (/[^0-9a-f]/i.test(t)) throw new Error("hex bytes only (0-9, a-f), e.g. de ad be ef");
  if (t.length % 2) throw new Error("odd number of hex digits");
  const out = new Uint8Array(t.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(t.substr(i * 2, 2), 16);
  return out;
}

const ESC = { n: 10, r: 13, t: 9, "0": 0, a: 7, b: 8, f: 12, v: 11, e: 27, "\\": 92, "'": 39, '"': 34 };
// C-style escapes -> bytes: \xHH \n \r \t \0 \a \b \f \v \e \\ \' \"; other text as UTF-8.
export function parseEscapes(s) {
  const out = [];
  const enc = new TextEncoder();
  const str = String(s || "");
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (c !== "\\") { const cp = str.codePointAt(i); const ch = String.fromCodePoint(cp); out.push(...enc.encode(ch)); i += ch.length - 1; continue; }
    const n = str[i + 1];
    if (n === undefined) throw new Error("a trailing \\ escapes nothing (use \\\\ for a backslash)");
    if (n === "x" || n === "X") {
      const h = str.substr(i + 2, 2);
      if (!/^[0-9a-f]{2}$/i.test(h)) throw new Error(`\\x needs two hex digits (at ${i})`);
      out.push(parseInt(h, 16)); i += 3; continue;
    }
    if (!(n in ESC)) throw new Error(`unknown escape \\${n} (at ${i})`);
    out.push(ESC[n]); i += 1;
  }
  return Uint8Array.from(out);
}

// Classic `offset  hex  |ascii|`, 16 bytes a row, offsets in the direction's own stream.
function hexRows(bytes, base) {
  const rows = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const ch = bytes.subarray(off, off + 16);
    let hx = "";
    for (let i = 0; i < 16; i++) hx += (i < ch.length ? ch[i].toString(16).padStart(2, "0") : "  ") + (i === 7 ? "  " : " ");
    let as = "";
    for (const b of ch) as += b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
    rows.push(`${(base + off).toString(16).padStart(8, "0")}  ${hx} |${as}|`);
  }
  return rows.join("\n");
}

const MODES = [["text", "Text line"], ["hex", "Hex bytes"], ["esc", "Escape string"]];
const PLACEHOLDER = {
  text: "type input, Enter to send",
  hex: "hex bytes, e.g.  47 49 46 38 39 61  (exact, no newline added)",
  esc: "escapes, e.g.  GIF89a\\x01\\x00\\n  (exact, no newline added)",
};

export function InteractiveConsole({ targets = [], caseId }) {
  const [tid, setTid] = useState(targets[0] ? targets[0].id : "");
  const [argv, setArgv] = useState("");
  const [stdinMode, setStdinMode] = useState("pty");   // picked before Start
  const [chan, setChan] = useState("pty");             // what the running session really uses
  const [status, setStatus] = useState("disconnected");
  const [out, setOut] = useState("");
  const [segs, setSegs] = useState([]);                // hex transcript: [{dir, bytes, base}]
  const [view, setView] = useState("text");
  const [line, setLine] = useState("");
  const [inMode, setInMode] = useState("text");
  const [nl, setNl] = useState(true);
  const [saved, setSaved] = useState(null);
  const [sentN, setSentN] = useState(0);
  const [stdinClosed, setStdinClosed] = useState(false);
  const [sockOpen, setSockOpen] = useState(false);     // "save as seed" needs the session's socket
  const ws = useRef(null);
  const box = useRef(null);
  const offs = useRef({ in: 0, out: 0 });
  // keep the pick valid: a removed target (or another case's list) falls back to the first one
  useEffect(() => {
    if (!targets.some((t) => t.id === tid)) setTid(targets[0] ? targets[0].id : "");
  }, [targets]);
  useEffect(() => () => { try { ws.current && ws.current.close(); } catch (_e) { /* closed */ } }, []);
  useEffect(() => { if (box.current) box.current.scrollTop = box.current.scrollHeight; }, [out, segs, view]);
  const append = (s) => setOut((o) => { const n = o + s; return n.length > MAX_OUT ? n.slice(-150000) : n; });
  const record = (dir, bytes) => {
    if (!bytes.length) return;
    const base = offs.current[dir];
    offs.current[dir] += bytes.length;
    setSegs((cur) => {
      let next = cur.slice();
      const last = next[next.length - 1];
      if (last && last.dir === dir) {
        const m = new Uint8Array(last.bytes.length + bytes.length);
        m.set(last.bytes); m.set(bytes, last.bytes.length);
        next[next.length - 1] = { ...last, bytes: m };
      } else next.push({ dir, bytes, base });
      let total = next.reduce((a, x) => a + x.bytes.length, 0);
      while (total > MAX_HEX && next.length > 1) { total -= next[0].bytes.length; next = next.slice(1); }
      if (total > MAX_HEX) {                          // one huge segment: keep its tail
        const x = next[0], cut = x.bytes.length - MAX_HEX;
        next[0] = { ...x, bytes: x.bytes.slice(cut), base: x.base + cut };
      }
      return next;
    });
  };
  const sendObj = (o) => {
    if (ws.current && ws.current.readyState === 1) { ws.current.send(JSON.stringify(o)); return true; }
    return false;
  };

  const connect = () => {
    try { ws.current && ws.current.close(); } catch (_e) { /* closed */ }
    setOut(""); setSegs([]); setSaved(null); setSentN(0); setStdinClosed(false); setSockOpen(false);
    offs.current = { in: 0, out: 0 };
    setChan(stdinMode);
    // `args` is shell-quoted ("-c @@", `--name "a b"`), split on the server like the CLI's --argv
    const qs = `target_id=${encodeURIComponent(tid)}&stdin=${stdinMode}`
      + (argv.trim() ? `&args=${encodeURIComponent(argv.trim())}` : "");
    const proto = location.protocol === "https:" ? "wss" : "ws";
    setStatus("connecting…");
    const w = new WebSocket(`${proto}://${location.host}/console?${qs}`);
    // One decoder per connection, in streaming mode: a multi-byte character split across two PTY
    // reads is joined instead of turning into two U+FFFD.
    const dec = new TextDecoder();
    ws.current = w;
    // Every handler checks it still belongs to the CURRENT socket: after a Restart the old one's
    // late close used to mark the new, running process "disconnected" (and lock the input).
    const mine = () => ws.current === w;
    w.onopen = () => { if (mine()) { setStatus("running"); setSockOpen(true); } };
    w.onclose = () => { if (mine()) { setSockOpen(false); setStatus((s) => (s === "exited" ? s : "disconnected")); } };
    w.onerror = () => { if (mine()) setStatus("error"); };
    w.onmessage = (ev) => {
      if (!mine()) return;
      let m; try { m = JSON.parse(ev.data); } catch (_e) { return; }
      if (m.t === "out") {
        const b = b64ToBytes(m.b64);
        append(dec.decode(b, { stream: true }));
        record("out", b);
      } else if (m.t === "info") {
        if (m.stdin) setChan(m.stdin);
        append(`\n[·] ${m.msg}\n`);
      } else if (m.t === "eof") {
        if (m.closed) { setStdinClosed(true); append("\n[·] stdin closed (EOF)\n"); }
        else append("\n[·] sent ^D (end of input)\n");
      } else if (m.t === "exit") { append(`\n[exited${m.code != null ? " code " + m.code : ""}${m.signal != null ? " signal " + m.signal : ""}]\n`); setStatus("exited"); }
      else if (m.t === "saved") {
        setSaved(m);
        // the seed is one of the case's seeds now: the seed lists / run picker re-read
        try { document.dispatchEvent(new CustomEvent("lykos:seeds-changed", { detail: { caseId, added: [m.sha] } })); } catch (_e) { /* no DOM */ }
      }
    };
  };

  // What the input box would send right now, or the parse error.
  const parsed = useMemo(() => {
    try {
      if (inMode === "hex") return { bytes: parseHex(line) };
      if (inMode === "esc") return { bytes: parseEscapes(line) };
      return { bytes: new TextEncoder().encode(nl ? line + "\n" : line) };
    } catch (e) { return { error: e.message || String(e) }; }
  }, [line, inMode, nl]);
  const sendInput = () => {
    if (parsed.error || !parsed.bytes || !parsed.bytes.length) return;
    if (!sendObj({ t: "in", b64: bytesToB64(parsed.bytes) })) return;
    record("in", parsed.bytes);
    setSentN((n) => n + parsed.bytes.length);
    // the terminal echoes what it is sent; a pipe does not, so say what went out
    if (chan === "pipe") append(`\n[→ sent ${parsed.bytes.length} B]\n`);
    setLine("");
  };
  const sendEof = () => sendObj({ t: "eof" });
  const live = status === "running";
  const pipe = chan === "pipe";
  const onKey = (e) => {
    if (e.key === "Enter") { e.preventDefault(); sendInput(); return; }
    // key passthrough: Ctrl-C interrupts the target (unless text is selected -- that is a copy),
    // Ctrl-D ends input, like at a terminal
    if (e.ctrlKey && !e.altKey && !e.metaKey && (e.key === "c" || e.key === "C")) {
      const el = e.target;
      if (el && el.selectionStart !== el.selectionEnd) return;
      e.preventDefault(); sendObj({ t: "signal", sig: "INT" });
    } else if (e.ctrlKey && !e.altKey && !e.metaKey && (e.key === "d" || e.key === "D")) {
      e.preventDefault(); sendEof();
    }
  };

  const hexView = segs.length
    ? segs.map((s, i) => html`<div key=${i} style="margin:0 0 6px">
        <div style=${`font-weight:600;color:${s.dir === "in" ? "var(--blue)" : "var(--tx2)"}`}>${s.dir === "in" ? "→ sent" : "← received"} ${s.bytes.length} B${" "}<span class="dim" style="font-weight:400">@ 0x${s.base.toString(16)}</span></div>
        <div>${hexRows(s.bytes, s.base)}</div></div>`)
    : html`<span class="dim">The bytes sent and received appear here, as a hex dump.</span>`;
  const inputDisabled = !live || stdinClosed;
  const nBytes = parsed.bytes ? parsed.bytes.length : 0;
  return html`<section class="panel pad" style="display:flex;flex-direction:column;gap:10px">
    <div class="row-c" style="flex-wrap:wrap;gap:10px">
      <h2>Drive a target by hand</h2>
      <span class="dim" style="font-size:12px">sandboxed, behind a terminal — for menus, handshakes and binary protocols the automated stages cannot reach</span>
    </div>
    <div class="row-c" style="flex-wrap:wrap;gap:10px">
      <select value=${tid} onChange=${(e) => setTid(e.target.value)} aria-label="Target">
        ${targets.map((t) => html`<option value=${t.id}>${t.filename}</option>`)}
      </select>
      <input type="text" class="mono" placeholder="arguments, shell-quoted (e.g. -v 'a b')" value=${argv}
        onInput=${(e) => setArgv(e.target.value)} style="flex:1 1 200px" aria-label="Arguments" />
      <select value=${stdinMode} onChange=${(e) => setStdinMode(e.target.value)} aria-label="Stdin channel"
        title="Terminal: a tty with line editing and Ctrl-C/Ctrl-D keys (control bytes are interpreted). Exact bytes: stdin is a pipe — every byte reaches the target as-is and EOF really closes it. Applies at Start.">
        <option value="pty">stdin: terminal</option>
        <option value="pipe">stdin: exact bytes (pipe)</option>
      </select>
      <button class="btn sm primary" onClick=${connect} disabled=${!tid}>${live ? "Restart" : "Start"}</button>
      <span class=${"chip" + (live ? " on" : "")}>${live ? html`<span class="dot live"></span>` : null}${status}${live || status === "exited" ? ` · ${pipe ? "pipe" : "tty"}` : ""}</span>
    </div>
    <div class="row-c" style="flex-wrap:wrap;gap:8px">
      <div class="seg" role="tablist" aria-label="Output view">
        <button role="tab" aria-selected=${view === "text"} class=${view === "text" ? "on" : ""} onClick=${() => setView("text")}>Text</button>
        <button role="tab" aria-selected=${view === "hex"} class=${view === "hex" ? "on" : ""} onClick=${() => setView("hex")}>Hex dump</button>
      </div>
      <span class="dim" style="font-size:12px">${view === "hex" ? `sent ${sentN} B · received ${offs.current.out} B${offs.current.out + offs.current.in > MAX_HEX ? ` · last ${MAX_HEX / 1024} KiB shown` : ""}` : "output as text"}</span>
    </div>
    <pre ref=${box} class="mono" data-view=${view} style="margin:0;height:260px;overflow:auto;background:var(--term);border:1px solid var(--border);border-radius:10px;padding:10px 12px;font-size:12px;${view === "hex" ? "white-space:pre" : "white-space:pre-wrap;word-break:break-word"}">${view === "hex" ? hexView : (out || html`<span class="dim">Output appears here once the target starts.</span>`)}</pre>
    <div class="row-c" style="flex-wrap:wrap;gap:8px">
      <div class="seg" role="tablist" aria-label="Input mode">
        ${MODES.map(([k, l]) => html`<button role="tab" aria-selected=${inMode === k} class=${inMode === k ? "on" : ""} onClick=${() => setInMode(k)}>${l}</button>`)}
      </div>
      ${inMode === "text" ? html`<label class="muted" style="font-size:12px;display:flex;gap:5px;align-items:center">
        <input type="checkbox" checked=${nl} onChange=${(e) => setNl(e.target.checked)} />append newline</label>` : null}
      <span class=${parsed.error && line ? "rs-amber" : "dim"} style=${`font-size:12px${parsed.error && line ? ";color:var(--amber, #b7791f)" : ""}`} aria-live="polite">
        ${parsed.error ? (line ? parsed.error : "") : `${nBytes} byte${nBytes === 1 ? "" : "s"} to send`}</span>
    </div>
    <div class="row-c" style="flex-wrap:wrap;gap:8px">
      <input type="text" class="mono" placeholder=${!live ? "start the target first" : stdinClosed ? "stdin is closed — Restart to send more" : PLACEHOLDER[inMode]}
        value=${line} disabled=${inputDisabled} onInput=${(e) => setLine(e.target.value)}
        onKeyDown=${onKey} style="flex:1 1 260px" aria-label="Input to send" spellcheck="false" />
      <button class="btn sm" disabled=${inputDisabled || !!parsed.error || !nBytes} onClick=${sendInput}>Send</button>
      <button class="btn sm" disabled=${inputDisabled} onClick=${sendEof}
        title=${pipe ? "close the target's stdin (it reads end-of-file)" : "send ^D: end of input for a line-reading target (Ctrl-D in the box)"}>${pipe ? "Close stdin" : "EOF ^D"}</button>
      <button class="btn sm" disabled=${!live} onClick=${() => sendObj({ t: "signal", sig: "INT" })} title="SIGINT to the target (Ctrl-C in the box)">Ctrl-C</button>
      <button class="btn sm" disabled=${!live} onClick=${() => sendObj({ t: "signal", sig: "TERM" })}>Terminate</button>
      <button class="btn sm" disabled=${!sockOpen || !(live || status === "exited")} onClick=${() => sendObj({ t: "save" })}
        title=${sockOpen ? "save every byte sent so far, exactly and in order, as a seed the next analysis starts from"
          : "the session has closed; Start again to record a new one"}>Save as seed</button>
    </div>
    ${!pipe && inMode !== "text" ? html`<div class="dim" style="font-size:11.5px">At a terminal some bytes are keys (^C interrupts, ^D ends a line, DEL erases, CR becomes LF). For a binary protocol pick${" "}<b>stdin: exact bytes</b> and Start again.</div>` : null}
    ${saved ? html`<span class="chip on" style="align-self:flex-start">seed saved · ${saved.bytes} B · ${String(saved.sha || "").slice(0, 12)}</span>` : null}
  </section>`;
}
