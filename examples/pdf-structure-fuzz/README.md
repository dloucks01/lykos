# Structure-aware fuzzing demo — mock PDF parser

A minimal, self-contained example showing why the **structure-aware mutation
layer** (`core/lykos/analyze/fuzz/structure.py`) finds a format-parser overflow
that byte-level havoc misses on the same seed and budget.

## Files

| File | What it is |
|------|-----------|
| `pdfparse.c` | Source of a mock PDF-shaped parser with a stack overflow. |
| `build.sh` | Builds `./pdfparse` (`gcc -O0 -fno-stack-protector -no-pie`). |
| `seed.pdf` | A **valid** 24-byte input: `%PDF` + u32-LE `len(16)` + 16 bytes → exits clean. |
| `crash_input.pdf` | The fuzzer's **minimized** 97-byte crashing input → crashes. |

## The bug

`pdfparse` reads a 4-byte `%PDF` magic, then a u32 little-endian length, then
copies that many bytes into a 64-byte stack buffer. A blob longer than 64 bytes
smashes the stack (CWE-787 / CWE-119).

## Reproduce

> Run in an isolated VM/container — this is a real memory-corruption crash.

```sh
./build.sh
./pdfparse seed.pdf         # -> exit 65   (clean: returns 'A')
./pdfparse crash_input.pdf  # -> exit 139 (SIGSEGV) or 134 (SIGABRT)
```

The exact fatal signal varies run to run (a SIGSEGV, or a glibc SIGABRT such as
`invalid stdio handle`) because the overflow smashes whatever adjacent stack
state it happens to reach — both are the same underlying bug.

## Why structure-aware finds it and byte-level doesn't

`crash_input.pdf` keeps the `%PDF` magic intact (so the parser doesn't reject
it) **and** carries a blob grown past the 64-byte buffer. Byte-level havoc
corrupts the magic (input rejected) and can't coordinate the length field with
the data it sizes, so it never reaches the vulnerable `memcpy`.

```
hexdump -C crash_input.pdf | head -1
00000000  25 50 44 46 00 00 c1 41  45 50 41 41 41 40 41 41   %PDF...AEPAAA@AA
           \_ %PDF __/  \_ u32 __/  \_ blob (grown > 64 bytes) ...
```

Measured on this target — same `seed.pdf`, same 400-exec budget:

| Mutator | Setting | Crashes |
|---------|---------|--------:|
| byte-level | (default) | **0** |
| structure-aware | `format_name=lv32`, `magic=%PDF` | **137** (1 unique) |

## Run it through the platform (as the GUI does)

Upload `pdfparse` as a target, attach `seed.pdf` via **+ seeds**, then in the
Fuzz control pick the **length-prefixed** format model and set the magic
override to `%PDF`. Equivalent API call:

```jsonc
POST /runs
{
  "case_id": "<case>", "target_id": "<target>", "stage": "fuzz",
  "params": {
    "input_mode": "file", "max_execs": 400, "seeds": ["<base64 of seed.pdf>"],
    "format_name": "lv32", "magic": "%PDF"    // structure-aware mutation
  }
}
```

The campaign confirms a **CWE-119 (critical)** finding whose minimized
reproducer is `crash_input.pdf`.
