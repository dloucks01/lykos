// Thin REST client for the lykos API. Every server route the workbench uses lives here as
// one async function, so a route change is edited in one place and the UI never builds a URL
// or reads a response shape inline. All calls are same-origin; the server binds localhost.

async function _req(method, path, { body, headers, raw } = {}) {
  const opts = { method, headers: { ...(headers || {}) } };
  if (body !== undefined) {
    if (body instanceof Blob || body instanceof ArrayBuffer || body instanceof Uint8Array) {
      opts.body = body;
    } else {
      opts.body = JSON.stringify(body);
      opts.headers["Content-Type"] = "application/json";
    }
  }
  const res = await fetch(path, opts);
  if (raw) {
    if (!res.ok) throw await _err(res);
    return res;
  }
  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = { error: text }; }
  }
  if (!res.ok) {
    const msg = (data && (data.error || data.message)) || `${res.status} ${res.statusText}`;
    const e = new Error(msg);
    e.status = res.status;
    e.data = data;
    throw e;
  }
  return data;
}

async function _err(res) {
  let msg = `${res.status} ${res.statusText}`;
  try {
    const d = await res.json();
    if (d && d.error) msg = d.error;
  } catch { /* keep status line */ }
  const e = new Error(msg);
  e.status = res.status;
  return e;
}

export const api = {
  // ---- health ----
  health: () => _req("GET", "/health"),

  // ---- cases ----
  listCases: () => _req("GET", "/cases"),
  getCase: (id) => _req("GET", `/cases/${id}`),
  createCase: (name, extra = {}) => _req("POST", "/cases", { body: { name, ...extra } }),

  // ---- targets ----
  listTargets: (caseId) => _req("GET", `/cases/${caseId}/targets`),
  getTarget: (id) => _req("GET", `/targets/${id}`),

  // Upload a file to a case. Accepts a File/Blob; the filename rides in a header so the
  // server does not need multipart parsing for the common single-file case.
  uploadTarget: (caseId, file) => _req("POST", `/cases/${caseId}/targets`, {
    body: file,
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Filename": (file && file.name) || "upload.bin",
    },
  }),

  // ---- per-target reads ----
  advice: (id) => _req("GET", `/targets/${id}/advice`),
  targetSource: (id) => _req("GET", `/targets/${id}/source`),
  capabilities: (id) => _req("GET", `/targets/${id}/capabilities`),
  targetFindings: (id) => _req("GET", `/targets/${id}/findings`),
  functions: (id) => _req("GET", `/targets/${id}/functions`),
  callgraph: (id) => _req("GET", `/targets/${id}/callgraph`),
  strings: (id, { limit = 500, offset = 0 } = {}) =>
    _req("GET", `/targets/${id}/strings?limit=${limit}&offset=${offset}`),
  dynresults: (id) => _req("GET", `/targets/${id}/dynresults`),
  pocs: (id) => _req("GET", `/targets/${id}/pocs`),
  getFunction: (id) => _req("GET", `/functions/${id}`),
  getFinding: (id) => _req("GET", `/findings/${id}`),

  // Propose (and optionally verify by running) a command line for the target.
  invocation: (id, opts = {}) => _req("POST", `/targets/${id}/invocation`, { body: opts }),

  // Re-run a crashing input N times to confirm the finding is a true, deterministic crash.
  replay: (id, opts = {}) => _req("POST", `/targets/${id}/replay`, { body: opts }),

  // ---- runs ----
  createRun: (stage, { targetId, caseId, params } = {}) => _req("POST", "/runs", {
    body: {
      stage,
      ...(targetId ? { target_id: targetId } : {}),
      ...(caseId ? { case_id: caseId } : {}),
      ...(params ? { params } : {}),
    },
  }),
  getRun: (id) => _req("GET", `/runs/${id}`),
  runOutput: (id) => _req("GET", `/runs/${id}/output`),
  cancelRun: (id) => _req("POST", `/runs/${id}/cancel`),
  listRuns: (caseId) => _req("GET", `/cases/${caseId}/runs`),

  // ---- case-level findings + report ----
  caseFindings: (caseId) => _req("GET", `/cases/${caseId}/findings`),
  systemmap: (caseId) => _req("GET", `/cases/${caseId}/systemmap`),
  // The false-positive review verdicts for a case: { input_sha: {runs, crashed, signal,
  // deterministic} }. Lets a reopened case restore its VerifyBadges (the live run gets them from
  // the event stream).
  verifications: (caseId) => _req("GET", `/cases/${caseId}/verifications`),

  // Server-side background Autopilot: keeps running after the tab closes.
  startBackground: (caseId, targetIds) => _req("POST", `/cases/${caseId}/autopilot`, { body: { target_ids: targetIds } }),
  backgroundStatus: (caseId) => _req("GET", `/cases/${caseId}/autopilot`),
  cancelBackground: (caseId) => _req("POST", `/cases/${caseId}/autopilot/cancel`),
  events: (caseId, after = 0) => _req("GET", `/cases/${caseId}/events?after=${after}`),
  reportUrl: (caseId, fmt = "html") => `/cases/${caseId}/report?format=${fmt}`,
  artifactUrl: (sha) => `/artifacts/${sha}`,
  // Inner contents of a PoC bundle (.tar.gz): { level, exploit, meta, run_cmd, files:[{name,
  // size, kind, text?|hexdump?}], download }. Lets the UI show the exploit -- repro script,
  // payload hexdump, technique notes -- inline instead of only offering the tarball.
  bundle: (sha) => _req("GET", `/artifacts/${sha}/bundle`),
};

// Poll a run until it reaches a terminal status. Resolves with the final run record.
// `onTick` is called with each poll's run record so the UI can show live status.
export async function waitForRun(runId, { onTick, intervalMs = 700, timeoutMs = 20 * 60 * 1000 } = {}) {
  const TERMINAL = new Set(["done", "error", "cancelled", "canceled", "failed", "skipped"]);
  const start = Date.now();
  for (;;) {
    const run = await api.getRun(runId);
    if (onTick) onTick(run);
    if (TERMINAL.has(run.status)) return run;
    if (Date.now() - start > timeoutMs) {
      const e = new Error(`run ${runId} did not finish within the time budget`);
      e.run = run;
      throw e;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}
