"""Offline, deterministic SVG figures for the report and GUI (doc 49, Theme 4).

The GUI renders a live call graph and coverage bars with interactive JavaScript, but those never
reach the air-gapped HTML/PDF report. This module draws the same data as a plain, self-contained
``<svg>`` string that embeds anywhere -- the report, the PDF, a standalone browser -- with **no**
external request, font, or script. It is the shared, stdlib-only figure engine the roadmap calls
for: a general layered-DAG layout plus concrete figures built on it.

Guarantees every figure here keeps, because a report figure is reviewed in git and embedded in a
byte-stable PDF:

* **Deterministic** -- identical input produces identical output, every run. No randomness, no
  physics simulation; a fixed layered layout with stable tie-breaks and integer coordinates.
* **Air-gap safe** -- only inline markup; fonts are generic families (``system-ui``, ``monospace``),
  never a web font or CDN. Nothing here emits ``http(s)://``.
* **Theme-robust** -- colours are CSS custom properties with a light default and a
  ``prefers-color-scheme: dark`` override, inlined in the SVG, so one figure reads on the light
  report page and the dark GUI alike.
* **Bounded** -- a figure caps how many nodes it draws and says "+N more" rather than emitting a
  monstrous SVG for a 5,000-node graph.

All text is escaped; a function name is data, never markup.
"""
from __future__ import annotations

from typing import Iterable, Optional

# -- geometry (all integers, so output is byte-stable) ----------------------------------------
_NODE_H = 28
_NODE_VPAD = 16          # vertical gap between stacked nodes in a column
_COL_W = 190             # horizontal distance between ranks (column pitch)
_NODE_W = 150            # fixed node box width
_MARGIN = 16
_CHAR_W = 7              # approx monospace advance, for truncation only (not layout)
_MAX_LABEL = 22          # characters shown in a node before an ellipsis
_MAX_NODES = 48          # hard cap on drawn nodes; the rest fold into a "+N more" note

# The one place colours live. Inlined into every figure's <style> so it is standalone and themes
# itself; callers never pass raw colours.
_STYLE = """
<style>
svg.lyk-fig{--fg:#1b2430;--muted:#5b6b7d;--line:#9fb0c3;--box:#f4f7fb;--box-br:#c4d2e3;
--accent:#1f6feb;--accent-box:#e3efff;--warn:#b9770e;--bad:#c0392b;--good:#1f8a4c;
font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
@media (prefers-color-scheme:dark){svg.lyk-fig{--fg:#e6edf3;--muted:#9aa7b4;--line:#45586c;
--box:#161b22;--box-br:#30404f;--accent:#58a6ff;--accent-box:#122a44;--warn:#d9a441;
--bad:#f07167;--good:#4cc38a}}
svg.lyk-fig .edge{stroke:var(--line);stroke-width:1.4;fill:none}
svg.lyk-fig .node{fill:var(--box);stroke:var(--box-br);stroke-width:1.2;rx:5}
svg.lyk-fig .node.focus{fill:var(--accent-box);stroke:var(--accent);stroke-width:2}
svg.lyk-fig .nlabel{fill:var(--fg);font-size:12px}
svg.lyk-fig .nsub{fill:var(--muted);font-size:10px}
svg.lyk-fig .cap{fill:var(--muted);font-size:11px}
svg.lyk-fig .bar-bg{fill:var(--box);stroke:var(--box-br);stroke-width:1}
svg.lyk-fig .bar-fill.good{fill:var(--good)}svg.lyk-fig .bar-fill.warn{fill:var(--warn)}
svg.lyk-fig .bar-fill.bad{fill:var(--bad)}
</style>"""


def esc(s) -> str:
    """Escape text for SVG/XML content and attribute values. A label is data, never markup."""
    return (str("" if s is None else s)
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def _clip(label: str) -> str:
    label = str(label or "")
    return label if len(label) <= _MAX_LABEL else label[: _MAX_LABEL - 1] + "…"


def _svg_open(w: int, h: int, title: str, desc: str = "") -> str:
    return (f'<svg class="lyk-fig" xmlns="http://www.w3.org/2000/svg" '
            f'viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" '
            f'aria-label="{esc(title)}">{_STYLE}'
            f'<title>{esc(title)}</title>' + (f'<desc>{esc(desc)}</desc>' if desc else ""))


# -- layered DAG layout -----------------------------------------------------------------------

def _rank_nodes(node_ids: list[str], edges: list[tuple[str, str]]) -> dict[str, int]:
    """Assign each node a column (rank): a source is 0, and a node is one past the deepest caller
    that reaches it. Cycles (recursion) are handled by a bounded relaxation that never loops
    forever and clamps the depth -- a back-edge simply does not push its target further right.

    Deterministic: nodes are relaxed in sorted order for a fixed number of passes.
    """
    ids = set(node_ids)
    adj: dict[str, list[str]] = {n: [] for n in node_ids}
    indeg: dict[str, int] = {n: 0 for n in node_ids}
    seen_edges = set()
    for s, d in edges:
        if s in ids and d in ids and s != d and (s, d) not in seen_edges:
            seen_edges.add((s, d))
            adj[s].append(d)
            indeg[d] += 1
    rank = {n: 0 for n in node_ids}
    # Longest-path relaxation, bounded to len(nodes) passes so a cycle cannot spin.
    for _ in range(max(1, len(node_ids))):
        changed = False
        for s in sorted(node_ids):
            for d in sorted(adj[s]):
                if rank[d] < rank[s] + 1:
                    rank[d] = rank[s] + 1
                    changed = True
        if not changed:
            break
    # Clamp so one deep chain cannot make the figure absurdly wide.
    cap = min(max(rank.values(), default=0), 7)
    return {n: min(r, cap) for n, r in rank.items()}


def layered_dag_svg(nodes: list[dict], edges: list[tuple[str, str]], *, title: str,
                    caption: str = "", focus: Optional[str] = None) -> str:
    """A left-to-right layered DAG. ``nodes`` are ``{id, label, sub?}``; ``edges`` are
    ``(src_id, dst_id)``. Layout is deterministic: columns by rank, rows sorted within a column,
    integer coordinates. ``focus`` highlights one node id."""
    by_id = {n["id"]: n for n in nodes}
    ids = list(by_id)
    rank = _rank_nodes(ids, edges)
    # group by column, sorted within a column by label then id for a stable row order
    cols: dict[int, list[str]] = {}
    for nid in ids:
        cols.setdefault(rank[nid], []).append(nid)
    for r in cols:
        cols[r].sort(key=lambda n: (str(by_id[n].get("label") or ""), n))
    ncols = (max(cols) + 1) if cols else 1
    nrows = max((len(v) for v in cols.values()), default=1)
    width = _MARGIN * 2 + (ncols - 1) * _COL_W + _NODE_W
    cap_h = 22 if caption else 0
    height = _MARGIN * 2 + nrows * (_NODE_H + _NODE_VPAD) - _NODE_VPAD + cap_h

    # centre each column vertically within the tallest column
    pos: dict[str, tuple[int, int]] = {}
    for r, members in cols.items():
        col_h = len(members) * (_NODE_H + _NODE_VPAD) - _NODE_VPAD
        y0 = _MARGIN + (height - cap_h - _MARGIN * 2 - col_h) // 2
        x = _MARGIN + r * _COL_W
        for i, nid in enumerate(members):
            pos[nid] = (x, y0 + i * (_NODE_H + _NODE_VPAD))

    parts = [_svg_open(width, height, title, caption)]
    # edges first (under the boxes); only edges between drawn nodes
    drawn = set(pos)
    seen = set()
    for s, d in edges:
        if s in drawn and d in drawn and s != d and (s, d) not in seen:
            seen.add((s, d))
            sx, sy = pos[s]
            dx, dy = pos[d]
            x1, y1 = sx + _NODE_W, sy + _NODE_H // 2
            x2, y2 = dx, dy + _NODE_H // 2
            mx = (x1 + x2) // 2
            parts.append(f'<path class="edge" d="M{x1},{y1} C{mx},{y1} {mx},{y2} {x2},{y2}"/>')
    # nodes
    for nid, (x, y) in pos.items():
        n = by_id[nid]
        cls = "node focus" if (focus is not None and nid == focus) else "node"
        parts.append(f'<rect class="{cls}" x="{x}" y="{y}" width="{_NODE_W}" height="{_NODE_H}" rx="5"/>')
        sub = n.get("sub")
        ty = y + (_NODE_H // 2 + 4) if not sub else y + 12
        parts.append(f'<text class="nlabel" x="{x + 8}" y="{ty}">{esc(_clip(n.get("label")))}</text>')
        if sub:
            parts.append(f'<text class="nsub" x="{x + 8}" y="{y + 24}">{esc(_clip(sub))}</text>')
    if caption:
        parts.append(f'<text class="cap" x="{_MARGIN}" y="{height - 6}">{esc(caption)}</text>')
    parts.append("</svg>")
    return "".join(parts)


# -- concrete figures -------------------------------------------------------------------------

def call_graph_svg(edges: Iterable[dict], *, focus_addr: Optional[str] = None,
                   title: str = "Call graph") -> Optional[str]:
    """A call-graph slice from CallEdge rows ``{src_addr, dst_addr, dst_name}``. With ``focus_addr``
    the slice is the focus node plus its direct callers and callees (the GUI's "ego graph");
    otherwise the busiest region, capped at ``_MAX_NODES``. Returns None if there is nothing to draw.
    """
    rows = [e for e in edges if e.get("src_addr") and e.get("dst_addr")]
    if not rows:
        return None
    name: dict[str, str] = {}
    adj: list[tuple[str, str]] = []
    deg: dict[str, int] = {}
    for e in rows:
        s, d = str(e["src_addr"]), str(e["dst_addr"])
        adj.append((s, d))
        deg[s] = deg.get(s, 0) + 1
        deg[d] = deg.get(d, 0) + 1
        if e.get("dst_name"):
            name.setdefault(d, str(e["dst_name"]))

    if focus_addr is not None:
        focus_addr = str(focus_addr)
        keep = {focus_addr}
        for s, d in adj:
            if s == focus_addr:
                keep.add(d)
            if d == focus_addr:
                keep.add(s)
        total = len({n for e in adj for n in e})
    else:
        # the most-connected nodes, deterministic tie-break by addr
        ranked = sorted(deg, key=lambda n: (-deg[n], n))
        keep = set(ranked[:_MAX_NODES])
        total = len(deg)

    hidden = total - len(keep)
    sub_edges = [(s, d) for s, d in adj if s in keep and d in keep]
    nodes = [{"id": n, "label": name.get(n, n), "sub": (n if name.get(n) else "")}
             for n in sorted(keep)]
    cap = f"{len(keep)} of {total} functions" + (f"  ·  +{hidden} more not shown" if hidden > 0 else "")
    return layered_dag_svg(nodes, sub_edges, title=title, caption=cap, focus=focus_addr)


def _cov_tone(pct) -> str:
    try:
        p = float(pct)
    except (TypeError, ValueError):
        return "warn"
    return "good" if p >= 60 else "warn" if p >= 25 else "bad"


def coverage_bars_svg(rows: list[dict], *, title: str = "Fuzzing coverage") -> Optional[str]:
    """Horizontal coverage bars from ``[{name, pct, detail?}]`` -- the per-binary coverage the GUI
    draws, as a static figure for the report. Returns None if there is nothing to draw."""
    rows = [r for r in rows if r.get("name")]
    if not rows:
        return None
    bar_w, row_h, lbl_w, val_w = 260, 22, 150, 70
    width = _MARGIN * 2 + lbl_w + bar_w + val_w
    height = _MARGIN * 2 + len(rows) * (row_h + 8) - 8
    parts = [_svg_open(width, height, title)]
    for i, r in enumerate(rows):
        y = _MARGIN + i * (row_h + 8)
        pct = r.get("pct")
        parts.append(f'<text class="nlabel" x="{_MARGIN}" y="{y + 15}">{esc(_clip(r["name"]))}</text>')
        bx = _MARGIN + lbl_w
        parts.append(f'<rect class="bar-bg" x="{bx}" y="{y}" width="{bar_w}" height="{row_h}" rx="4"/>')
        if pct is not None:
            try:
                w = max(2, min(bar_w, int(round(bar_w * float(pct) / 100))))
            except (TypeError, ValueError):
                w = 2
            parts.append(f'<rect class="bar-fill {_cov_tone(pct)}" x="{bx}" y="{y}" '
                         f'width="{w}" height="{row_h}" rx="4"/>')
        val = f"{pct}%" if pct is not None else "—"
        detail = r.get("detail")
        parts.append(f'<text class="nsub" x="{bx + bar_w + 8}" y="{y + 15}">'
                     f'{esc(val)}{esc("  " + detail if detail else "")}</text>')
    parts.append("</svg>")
    return "".join(parts)
