# Tier-0 benchmark corpus

36 small C programs with planted bugs (29 positive cases with 30 bugs, plus 7 negatives). Each bug
has a known site and a hand-written reference PoC. This corpus is the ground truth for the lykos
north-star metric (see `docs/internal/52-ground-up-rethink-2026-10-29.md` §3):

> **validated PoCs at the correct bug site ÷ known bugs**, with **false confirmations = 0**

Run it on every change to the hypothesis loop (proposer → directed solve → validate → weaponize).
A bug counts as found only when the tool's own input fires the bug's oracle at the declared
`file:line`. Any "confirmed" finding on a negative case, or at a line that no bug declares, is a
false confirmation.

The programs are shaped like code a pentester meets: TLV/record parsers, line protocols, CLI tools
and job runners. None of them uses `gets()`, has a "win" function, or leaks addresses. Input
reaches each bug through realistic framing: magic bytes, type and length fields, checksums, state
machines, auth gates, or function-pointer dispatch.

## Layout

```
bench/tier0/
  build.sh          build every case -> <outdir>/<id>/{prog,prog_asan}
  selfcheck.py      prove the ground truth (python3 stdlib only)
  <id>/
    prog.c          the target (30-90 lines, self-contained)
    case.json       manifest (schema below)
    ref_poc.bin     reference PoC (ref_poc_b1.bin, ref_poc_b2.bin... when a case has >1 bug)
    seed.bin        optional valid, non-crashing sample input (4 cases have none on purpose)
    hostile_N.bin   negatives only: adversarial inputs that must stay clean
```

**Show the tool under test only `prog` or `prog.c`, plus `seed.bin` when one exists.** Copy them
into a clean directory first. `case.json`, `ref_poc*.bin`, `hostile_*.bin` and this README are
the answer key.

## Manifest schema (`case.json`)

```json
{
  "id": "s01_tlv_memcpy",
  "summary": "one line",
  "class": "stack",
  "difficulty": "easy|medium|hard",
  "invocation": {"argv": ["@@"], "input_mode": "file"},
  "cflags": ["-O0", "-g", "-fno-stack-protector", "-no-pie"],
  "bugs": [
    {"id": "b1", "cwe": "CWE-121", "kind": "stack-write", "file": "prog.c", "line": 20,
     "function": "handle_name", "oracle": "asan", "asan_kind": "stack-buffer-overflow",
     "note": "..."}
  ],
  "intended_exec": []
}
```

- `invocation.input_mode` is one of:
  - `file`: `argv` contains `@@`, which is replaced by the path of the input file.
  - `stdin`: `argv` has no `@@`, and the input is fed to stdin.
  - `arg`: the input bytes become the argv element at `@@`. They contain no NUL.
- `bugs[].line` is the line of the faulting statement. That is the first in-program (`prog.c`)
  frame of the sanitizer report from the `prog_asan` build. For an interceptor report
  (memcpy/strcpy/sprintf/read/fread/free/printf), it is the call site.
- `bugs[].kind` is one of: stack-write, heap-write, global-write, stack-read, heap-read,
  format-string, int-overflow-alloc, cmd-injection, use-after-free, double-free.
- `bugs[].oracle` is one of:
  - `asan`: an ASan or UBSan report whose first `prog.c` frame is `line`.
  - `fmt`: a format-string crash, usually ASan SEGV inside the printf-family interceptor, whose
    first `prog.c` frame (the printf caller) is `line`.
  - `exec`: command injection. Run under `strace -f -e trace=execve`. The oracle fires on a
    *successful* execve whose basename is not `sh`/`bash`/`dash`, not in `intended_exec`, and not
    the program itself.
- `bugs[].asan_kind` is what the reference `prog_asan` build reports. For ASan it is the text after
  `ERROR: AddressSanitizer:`, e.g. `stack-buffer-overflow`, `negative-size-param`,
  `attempting double-free`, or `SEGV`. For UBSan it is `ubsan:index-out-of-bounds`: a constant-size
  array indexed out of range trips `-fsanitize=bounds` before ASan sees the access. A scorer should
  match on **line** (and optionally function). Treat the kind as informational, because a different
  validator build can report the same bug under another kind.
- `intended_exec` lists the basenames that a command-running program legitimately executes.
- `class` (stack, heap, oob-index, format-string, int-overflow, cmd-injection, uaf, reach-*,
  negative) and an optional `seed_exit` (the expected seed exit code, default 0) are informational.
- Negative cases have `"bugs": []`.

## Build and self-check

```sh
bench/tier0/build.sh /tmp/t0            # all cases; or: build.sh /tmp/t0 s01_tlv_memcpy ...
python3 bench/tier0/selfcheck.py        # builds into a temp dir, then checks
python3 bench/tier0/selfcheck.py --keep /tmp/t0 s01_tlv_memcpy   # keep the binaries
```

`build.sh` produces two binaries per case (`CC` defaults to `gcc`; binaries are not committed):
- `prog` is built with the case's `cflags`. This is the binary the analyzer is pointed at.
- `prog_asan` is built with
  `-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined`.
  This is the validator; a case can override it with an `asan_cflags` list.

`selfcheck.py` runs with
`ASAN_OPTIONS=detect_leaks=0:abort_on_error=0` and `UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1`.
For every case it checks:
- every bug's `ref_poc*.bin` fires the oracle at the declared line, function and kind;
- `seed.bin` exits with `seed_exit`, with no sanitizer report, no signal and no unintended exec;
- for negatives, the seed and every `hostile_*.bin` stay clean.

It prints one PASS/FAIL line per check and exits non-zero on any failure. A scorer should use the
same environment.

The PoCs crash `prog_asan` deterministically. On the plain `prog` build, most of them also crash
(SIGSEGV, or a glibc heap abort). OOB reads, UAF reads and `o02` (whose stray stores do not reach
the canary at this frame layout) can run silently. The sanitizer build is the oracle; the plain build is only
the analysis target.

## Cases

| id | class | channel | difficulty | prog cflags | seed | bugs (id, CWE, kind, `function`:line) |
|---|---|---|---|---|---|---|
| `s01_tlv_memcpy` | stack | file | easy | O0 no-pie, no SSP | yes | b1 CWE-121 stack-write `handle_name`:20 |
| `s02_argv_strcpy` | stack | arg | easy | O0 no-pie, no SSP | yes | b1 CWE-121 stack-write `parse_target`:25 |
| `s03_stdin_read` | stack | stdin | medium | O2, no fortify | yes | b1 CWE-121 stack-write `handle_echo`:28 |
| `s04_sprintf_field` | stack | file | easy | O0 default (PIE+SSP) | yes | b1 CWE-121 stack-write `print_greeting`:46 |
| `s05_delim_loop` | stack | stdin | medium | O0 no-pie, SSP-strong | yes | b1 CWE-121 stack-write `parse_request_line`:20 |
| `s06_fread_count` | stack | file | medium | O0 no-pie, no SSP | **no** | b1 CWE-121 stack-write `process_rows`:32 |
| `h01_heap_memcpy` | heap | file | easy | O0 no-pie, no SSP | yes | b1 CWE-122 heap-write `msg_new`:25 |
| `h02_offbyone_nul` | heap | file | medium | O2, no fortify | yes | b1 CWE-193 heap-write `copy_comment`:29 |
| `h03_trusted_header_len` | heap | file | medium | O0 default (PIE+SSP) | yes | b1 CWE-122 heap-write `reassemble`:31 |
| `o01_signed_index` | oob-index | file | easy | O0 no-pie, no SSP | yes | b1 CWE-129 stack-write `set_reg`:12 |
| `o02_count_loop` | oob-index | stdin | medium | O0 no-pie, SSP-strong | yes | b1 CWE-787 stack-write `read_batch`:28 |
| `o03_global_table` | oob-index | file | easy | O2, no fortify | yes | b1 CWE-787 global-write `set_color`:19 |
| `o04_heap_read` | oob-index | file | medium | O0 no-pie, no SSP | yes | b1 CWE-125 heap-read `measure`:18 |
| `o05_stack_read` | oob-index | stdin | medium | O0 default (PIE+SSP) | **no** | b1 CWE-125 stack-read `decode`:26 |
| `f01_printf_line` | format-string | stdin | easy | O0 no-pie, no SSP | yes | b1 CWE-134 format-string `relay`:17 |
| `f02_log_record_type` | format-string | file | medium | O2, no fortify | yes | b1 CWE-134 format-string `log_line`:18 |
| `f03_snprintf_puts` | format-string | arg | easy | O0 default (PIE+SSP) | yes | b1 CWE-134 format-string `print_banner`:18 |
| `i01_mul_wrap` | int-overflow | file | medium | O0 no-pie, no SSP | yes | b1 CWE-190 int-overflow-alloc `load_table`:27 |
| `i02_u16_total` | int-overflow | file | medium | O0 no-pie, no SSP | yes | b1 CWE-190 int-overflow-alloc `seal_frame`:27 |
| `i03_signed_len` | int-overflow | stdin | medium | O2, no fortify | **no** | b1 CWE-195 stack-write `handle_record`:14 |
| `c01_system_job` | cmd-injection | file | medium | O0 no-pie, no SSP | yes | b1 CWE-78 cmd-injection `run_check`:20 |
| `c02_popen_argv` | cmd-injection | arg | easy | O0 default (PIE+SSP) | yes | b1 CWE-78 cmd-injection `lookup`:11 |
| `u01_uaf_error_path` | uaf | file | medium | O0 no-pie, no SSP | yes | b1 CWE-416 use-after-free `cmd_show`:46; b2 CWE-415 double-free `main`:75 |
| `u02_double_free` | uaf | file | medium | O0 default (PIE+SSP) | yes | b1 CWE-415 double-free `store_free`:50 |
| `u03_uaf_cache` | uaf | stdin | medium | O2, no fortify | yes | b1 CWE-416 use-after-free `lookup`:21 |
| `r01_checksum_gate` | reach-checksum | file | hard | O0 no-pie, no SSP | **no** | b1 CWE-121 stack-write `apply_update`:23 |
| `r02_state_machine` | reach-state | file | hard | O0 no-pie, no SSP | yes | b1 CWE-121 stack-write `on_data`:31 |
| `r03_admin_cmd` | reach-magic | stdin | medium | O0 no-pie, no SSP | yes | b1 CWE-787 global-write `admin`:19 |
| `r04_fnptr_dispatch` | reach-dispatch | file | hard | O0 no-pie, no SSP | yes | b1 CWE-122 heap-write `h_store`:37 |
| `n01_memcpy_clamped` | negative | file | easy | O0 no-pie, no SSP | yes | — |
| `n02_literal_fmt` | negative | stdin | easy | O2, no fortify | yes | — |
| `n03_index_checked` | negative | file | medium | O0 no-pie, no SSP | yes | — |
| `n04_mul_checked` | negative | file | medium | O2, no fortify | yes | — |
| `n05_system_const` | negative | file | easy | O0 default (PIE+SSP) | yes | — |
| `n06_heap_lifetime_safe` | negative | file | medium | O0 no-pie, no SSP | yes | — |
| `n07_read_bounded` | negative | stdin | easy | O0 no-pie, SSP-strong | yes | — |

`O2, no fortify` = `-O2 -g -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0`. Ubuntu's gcc turns fortify on
by default at `-O1` and above. `O0 default` = `-O0 -g` with the distro defaults (PIE, SSP-strong).

### Reachability notes (what a solver has to get right)

- **Framing.** Most file and stdin cases need a magic (`TLV1`, `MQ`, `CHNK`, `REGS`, `PAL`, `BFNT`,
  `EVT1`, `TBL0`, `SPL1`, `FWUP`, `\x7fMSG`, `RP\x01`, `SB`) plus a type byte, and a length field
  that is consistent with the bytes actually present.
- **`r01_checksum_gate`.** The payload byte-sum plus the trailing checksum byte must be 0 mod 256,
  and the version must be 2. Then `name_len` > 32.
- **`r02_state_machine`.** Needs a `K` record carrying `c0 de f0 0d`, then `M` = 2 (raw mode is
  rejected unless unlocked), then a `D` record longer than 48 bytes. The seed asks for raw mode
  *without* the key, so the clamp still applies.
- **`r03_admin_cmd`.** Needs `AUTH 7731`, then `ADMIN SETMOTD <more than 63 chars>`.
- **`r04_fnptr_dispatch`.** The vulnerable handler is reached only through `handlers[3]`, and the
  type byte is range-checked correctly.
- **`f02_log_record_type`.** `log_line()` is called with literal strings everywhere except for
  type-7 records.
- **`u01_uaf_error_path`.** One dangling pointer, two observable sites: `SHOW` (UAF read, b1) or
  end-of-script cleanup (double free, b2).
- **`i02_u16_total`.** The PoC is about 64 KiB, because `len` must be at least 65520 for
  `len + 16` to wrap in `uint16_t`.
- **`i03_signed_len`.** `rec_len` must be 1–3 (0 ends the loop), so `len` is −3..−1.

### Ground-truth audit

Beyond `selfcheck.py`, the corpus was audited with a mutation pass of 1,500 mutants per case
(about 54k runs on `prog_asan`), seeded from each case's seed, PoCs and hostile inputs:
- every sanitizer report landed on a declared bug line;
- no negative case ever produced a sanitizer report, a signal, or an unintended exec.

If you edit a `prog.c`, re-run `selfcheck.py`. Line numbers in `case.json` are not derived
automatically.
