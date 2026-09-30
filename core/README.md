# lykos — core

The platform package. **Stdlib only** — no pip packages, no network, at runtime.

This directory is a `PYTHONPATH` root, not an installable distribution. Run lykos from the repo
root with `./start` (UI) or `./lykos ...` (CLI) -- they set this directory on `PYTHONPATH` for
you -- or build the single-file zipapp with `make bundle` (`dist/lykos.pyz`, which runs the same way).

```
lykos/
  cli.py           the `lykos` command: db, serve, doctor, eval, archgate, realgate, dashboard
  toolchain.py     one inventory of every external engine -- what `lykos doctor` reports
  casestore.py     a case = one sqlite DB + a content-addressed artifact store
  jobs/            job queue, worker pool, stage registry
  db/              schema, migrations, DAOs, models
  api/             HTTP + WebSocket server, and static/index.html (the analyst UI)
  analyze/         the analysis stages
    detect/        static CWE detection: rules, taint, bounds
    dynamic/       the sandbox and its execution tiers
    fuzz/          black-box, structure-aware, coverage-guided and directed fuzzing
    debug/         GDB / qemu-gdbstub / ptrace backends, monitors, root cause
    poc/           primitives, PoC bundles, exploit and injection synthesis
    link/          multi-binary: symbol resolution, IPC, cross-component taint
    firmware/      carving, headerless identification, rehosting
    symbolic/      concolic execution (angr, SymQEMU)
    fingerprint/   component + CVE fingerprinting
  eval/            benchmark corpora and the quality gates
```

The tests live at the repository root (`../tests`), not here, because they exercise the
platform end to end rather than this package in isolation.

See the root `README.md` for commands and `docs/02-architecture.md` for how the pieces fit.
