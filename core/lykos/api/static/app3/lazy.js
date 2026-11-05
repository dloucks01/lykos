// Modules loaded on demand, so a panel that is missing or fails to load degrades to a message
// instead of taking the whole workbench down.
import { useEffect, useState } from "preact/hooks";
import { html } from "../app2/html.js";

export function Lazy({ path, name, props = {}, fallback = null }) {
  const [C, setC] = useState(null);
  const [err, setErr] = useState(null);
  useEffect(() => {
    let live = true;
    import(path).then((m) => { if (live) setC(() => m[name] || null); })
      .catch((e) => { if (live) setErr(String(e.message || e)); });
    return () => { live = false; };
  }, [path, name]);
  if (C) return html`<${C} ...${props} />`;
  if (err) return fallback || html`<div class="panel empty">This panel could not load (${err}).</div>`;
  return null;
}


// The module object itself (or null while loading / when it is missing).
export function useModule(path) {
  const [m, setM] = useState(null);
  useEffect(() => {
    let live = true;
    import(path).then((x) => { if (live) setM(x); }).catch(() => { if (live) setM(null); });
    return () => { live = false; };
  }, [path]);
  return m;
}
