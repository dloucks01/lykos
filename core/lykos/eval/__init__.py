"""Phase 10 — validation & benchmark harness (doc 14).

Measures detection quality honestly against a labeled good/bad corpus: per-CWE precision,
recall, F1, and the false-positive rate, at each finding state. `corpus` holds a bundled,
compilable micro-corpus (Juliet-style good/bad pairs) and a directory loader; `metrics`
scores outcomes deterministically; `harness` compiles each case, runs the real pipeline
(triage -> disassemble -> detect), and matches findings to ground truth.

Deterministic and offline. The bundled corpus is small but real (actually compiled and
analyzed); the same harness can score a full Juliet/LAVA-M drop pointed at it via a directory.
"""
