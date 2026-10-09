# Quick start

New to lykos? This is the five-minute path from a fresh install to your first finding.
It assumes lykos is already on this machine. Moving it to another machine is
`git clone` plus `./lykos doctor` — the core is Python-stdlib-only, so the repo
runs on its own and doctor names anything else worth installing. For a machine with
no network, build the toolchain bundle first:
[docs/offline-packaging.md](docs/offline-packaging.md).

## What lykos is

You give it a compiled program — a stripped ELF, a cross-architecture binary, firmware, a
JAR, or a Windows PE. It recovers the program's structure, looks for security defects, then
tries to **prove** each one by actually reproducing it, and writes you a report. It runs
entirely offline and never opens a network connection.

The key idea: a defect is not "found" until lykos can demonstrate it. Every finding carries a
state that says how far it has been proven, and **you** decide when to trust it.

## 1. Check what this host can do

```sh
cd lykos
./lykos doctor
```

`doctor` prints every analysis engine, whether it is installed, and the exact install line for
anything missing. Nothing here needs installing to start: the core is Python-stdlib-only. The
heavy engines (Ghidra, AFL++, QEMU, GDB, angr) are optional and only unlock extra capabilities.
`doctor` is how you tell "the tool declined because an engine is absent" from a real problem.

## 2. Analyse something, from the shell

```sh
./lykos analyze /path/to/binary --budget 600
```

That runs the whole pipeline on one file and prints two things: **what the run did** and **what
it found**, in that order. The first half is the part worth reading even when the second is
empty — whether the program ever started, how many times it was executed and how fast, where
the time went, and which stages ran out of budget:

```
-- what this run did -----------------------------------------------
  baseline     ran, exited normally
  executions   10,792  (51.6/s)
               directed       9,281
               env_fuzz       1,511
  stages       done 24, error 2, skipped 11
  out of time  synthesize_poc
  budget       297.7s of 400s
  dearest      directed_fuzz 164.7s, build_exploit 69.1s, env_fuzz 22.3s
```

No findings after a campaign that ran is a result. No findings after one that did not is not,
and this is how you tell them apart. `--budget` is a wall clock, divided among the recovery,
search and proving phases; raise it and the campaigns get proportionally more.

If the program needs arguments or a sample input, say so — this is the one thing worth getting
right, because a program handed its input on the wrong channel looks exactly like a program
with no bugs:

```sh
./lykos analyze ./parser --argv '-c @@' --seed good1.conf --seed good2.conf --report out.html
```

`@@` is where the input file goes. `--seed` is a valid sample input (repeatable); for any
format parser, give it a couple of real ones so the fuzzer starts from real structure.

## 3. Or start the console

```sh
./start
```

This starts the local server and prints a URL. Open it in a browser on this machine:

```
http://127.0.0.1:8787
```

It binds to loopback only, so nothing outside this machine can reach it. You will see the
**Lykos Console**. The interface highlights the recommended next step at each stage, so you can
follow it without hunting through menus.

## 4. Analyze your first binary

In the console:

1. **Create a case.** A case is one investigation. It holds your binaries, every run, and all
   findings, so you can close the tool and come back to it.
2. **Upload a target.** Drop in the binary you want to analyze. lykos identifies its format and
   architecture automatically.
3. **Tell it how the target takes input.** This is the one step worth getting right. In the
   invocation box, give the command line the program expects and put `@@` where the input goes —
   a tool that reads a file with `-c` becomes `-c @@`. For a file-format parser (PDF, image,
   document), attach a couple of valid sample files as **seeds** so the fuzzer starts from real
   structure. Skip this and a program that wants a flag just prints its usage and exits, which
   looks exactly like a run that found nothing.

   Not sure it is wired up right? Use **Run once** to detonate the target on a single input as a
   smoke test before committing to a full campaign.
4. **Start the run.** lykos works through its pipeline: recover structure, flag candidate
   defects, then fuzz and execute the program to try to confirm them. Progress streams live.

## 5. Read the findings board

The board is the heart of the tool. Each finding is a card, and cards move across lanes as the
evidence gets stronger:

| Lane | What it means |
|---|---|
| **Unproven** | A pattern matched. Nothing has demonstrated it yet — treat with suspicion. |
| **Corroborated** | A second channel agrees (data-flow or taint analysis backs the pattern). |
| **Demonstrated** | lykos reproduced it, and ran the reproducer. This is real. |
| **PoC-backed** | A proof-of-concept input is attached and verified. |

Click any card for its evidence trail: the CWE class, the functions involved, and one-click
jumps to the disassembly, the crash, or the proof-of-concept. Filter by CWE, severity, or state
to cut a long list down.

Static analysis over-reports on purpose, so **Unproven** cards are leads, not verdicts. The ones
that reached **Demonstrated** or **PoC-backed** are the ones lykos stands behind.

## 6. Export

When you are done, export the case as a report (HTML, PDF, or SARIF) or as a self-contained
`.tar.gz` archive you can carry to another machine or hand to a colleague.

## Where to go next

- **[README.md](README.md)** — what lykos is and the design principles behind it.
- **`docs/`** — one numbered document per subsystem: static analysis, the sandbox, fuzzing,
  crash triage and PoC synthesis, the data model, and more.
- **`make help`** — every available command, including the quality gates (`make test`,
  `make eval`) and the packaging targets for air-gap transfer.
