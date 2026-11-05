// Drive a target by hand: the interactive detonation console (server: api/console.py over the
// /console WebSocket). The target runs in the sandbox behind a PTY; the operator types what a
// menu or protocol handshake needs, and can save everything sent as a reusable seed -- the inputs
// the one-shot dynamic stages cannot reach on their own.
import { useEffect, useRef, useState } from "preact/hooks";
import { html } from "../app2/html.js";

const MAX_OUT = 200000;

function b64ToText(b64) {
  try { return new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))); }
  catch (_e) { return ""; }
}
function textToB64(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function InteractiveConsole({ targets = [] }) {
  const [tid, setTid] = useState(targets[0] ? targets[0].id : "");
  const [argv, setArgv] = useState("");
  const [status, setStatus] = useState("disconnected");
  const [out, setOut] = useState("");
  const [line, setLine] = useState("");
  const [nl, setNl] = useState(true);
  const [saved, setSaved] = useState(null);
  const ws = useRef(null);
  const box = useRef(null);
  useEffect(() => { if (!tid && targets[0]) setTid(targets[0].id); }, [targets]);
  useEffect(() => () => { try { ws.current && ws.current.close(); } catch (_e) { /* closed */ } }, []);
  useEffect(() => { if (box.current) box.current.scrollTop = box.current.scrollHeight; }, [out]);
  const append = (s) => setOut((o) => { const n = o + s; return n.length > MAX_OUT ? n.slice(-150000) : n; });
  const send = (o) => { if (ws.current && ws.current.readyState === 1) ws.current.send(JSON.stringify(o)); };

  const connect = () => {
    try { ws.current && ws.current.close(); } catch (_e) { /* closed */ }
    setOut(""); setSaved(null);
    const qs = `target_id=${encodeURIComponent(tid)}` + (argv.trim() ? `&argv=${encodeURIComponent(argv.trim())}` : "");
    const proto = location.protocol === "https:" ? "wss" : "ws";
    setStatus("connecting…");
    const w = new WebSocket(`${proto}://${location.host}/console?${qs}`);
    ws.current = w;
    w.onopen = () => setStatus("running");
    w.onclose = () => setStatus((s) => (s === "exited" ? s : "disconnected"));
    w.onerror = () => setStatus("error");
    w.onmessage = (ev) => {
      let m; try { m = JSON.parse(ev.data); } catch (_e) { return; }
      if (m.t === "out") append(b64ToText(m.b64));
      else if (m.t === "info") append(`\n[·] ${m.msg}\n`);
      else if (m.t === "exit") { append(`\n[exited${m.code != null ? " code " + m.code : ""}${m.signal != null ? " signal " + m.signal : ""}]\n`); setStatus("exited"); }
      else if (m.t === "saved") setSaved(m);
    };
  };
  const sendLine = () => { send({ t: "in", b64: textToB64(nl ? line + "\n" : line) }); setLine(""); };
  const live = status === "running";
  return html`<section class="panel pad" style="display:flex;flex-direction:column;gap:10px">
    <div class="row-c" style="flex-wrap:wrap;gap:10px">
      <h2>Drive a target by hand</h2>
      <span class="dim" style="font-size:12px">sandboxed, behind a terminal — for menus and handshakes the automated stages cannot reach</span>
    </div>
    <div class="row-c" style="flex-wrap:wrap;gap:10px">
      <select value=${tid} onChange=${(e) => setTid(e.target.value)} aria-label="Target">
        ${targets.map((t) => html`<option value=${t.id}>${t.filename}</option>`)}
      </select>
      <input type="text" class="mono" placeholder="arguments (comma-separated)" value=${argv}
        onInput=${(e) => setArgv(e.target.value)} style="flex:1 1 200px" aria-label="Arguments" />
      <button class="btn sm primary" onClick=${connect} disabled=${!tid}>${live ? "Restart" : "Start"}</button>
      <span class=${"chip" + (live ? " on" : "")}>${live ? html`<span class="dot live"></span>` : null}${status}</span>
    </div>
    <pre ref=${box} class="mono" style="margin:0;height:260px;overflow:auto;background:var(--term);border:1px solid var(--border);border-radius:10px;padding:10px 12px;font-size:12px;white-space:pre-wrap;word-break:break-word">${out || html`<span class="dim">Output appears here once the target starts.</span>`}</pre>
    <div class="row-c" style="flex-wrap:wrap;gap:8px">
      <input type="text" class="mono" placeholder=${live ? "type input, Enter to send" : "start the target first"}
        value=${line} disabled=${!live} onInput=${(e) => setLine(e.target.value)}
        onKeyDown=${(e) => { if (e.key === "Enter") { e.preventDefault(); sendLine(); } }}
        style="flex:1 1 260px" aria-label="Input to send" />
      <label class="muted" style="font-size:12px;display:flex;gap:5px;align-items:center">
        <input type="checkbox" checked=${nl} onChange=${(e) => setNl(e.target.checked)} />newline</label>
      <button class="btn sm" disabled=${!live} onClick=${sendLine}>Send</button>
      <button class="btn sm" disabled=${!live} onClick=${() => send({ t: "eof" })}>EOF</button>
      <button class="btn sm" disabled=${!live} onClick=${() => send({ t: "signal", sig: "INT" })}>Ctrl-C</button>
      <button class="btn sm" disabled=${!live} onClick=${() => send({ t: "signal", sig: "TERM" })}>Terminate</button>
      <button class="btn sm" disabled=${status === "disconnected"} onClick=${() => send({ t: "save" })}
        title="save every byte sent so far as a seed the next analysis starts from">Save as seed</button>
    </div>
    ${saved ? html`<span class="chip on" style="align-self:flex-start">seed saved · ${saved.bytes} B · ${String(saved.sha || "").slice(0, 12)}</span>` : null}
  </section>`;
}
