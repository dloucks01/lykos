# Recall benchmark: known published bugs in real projects

Each directory is one target: a real project at one exact version, whose published crash-class
or code-execution defects (CVEs, plus upstream/oss-fuzz bugs without a CVE where noted) are
listed as ground truth. lykos is pointed at the tree **blind**: it gets no CVE list, no hints,
and no seeds. Its score is how many of these it finds, and how many it proves.

## `<id>/meta.json`

```json
{
  "id": "unzip-6.0",
  "project": "Info-ZIP UnZip",
  "version": "6.0",
  "tree": "examples/vuln-targets/src/unzip60",       // relative to the repo root
  "surface": "source",
  "entry": {"binary": "unzip", "argv": ["-t", "@@"]}, // the default way to drive the target
  "binary_path": "examples/vuln-targets/bin/unzip_x86-64",       // optional: the shipped binary
  "debug_binary": "examples/vuln-targets/bin/unzip_x86-64.dbg",  // optional: its -g debug twin
  "stripped_path": "...",                              // optional, default <binary_path>.stripped
  "note": "...",                                       // optional, target-level caveats
  "cves": [{
    "id": "CVE-2014-8140",            // or md4c-issue-NNN / oss-fuzz-NNNNN when no CVE exists
    "class": "heap-overflow-write",   // heap-overflow-read|heap-overflow-write|stack-overflow|uaf|
                                      // double-free|null-deref|div-by-zero|assertion|int-overflow|
                                      // infinite-loop|cmd-injection|other
    "file": "extract.c",              // relative to "tree"
    "function": "test_compr_eb",
    "line": 2224,                     // the defective statement, in the local tree
    "binary": "gif2rgb",              // optional: overrides entry.binary (multi-tool projects)
    "argv": ["-t", "@@"],             // what reaches it; @@ = the input
    "input": "file",                  // file | filename | stdin | argv
    "trigger": "one line",
    "fixed_in": "6.10b / debian patch name / commit",
    "ref": "https://...",
    "confidence": "high",             // high|medium|low: is this version affected, is the pin right
    "in_build": false,                // optional: the defective code is #ifdef'd out of the
                                      // tree's documented build (e.g. unzip's UNICODE_SUPPORT)
    "note": "..."                     // optional: why confidence is not high, build-flag caveats
  }],
  "excluded": [{"id": "...", "reason": "..."}]  // optional: considered and ruled out, and why
}
```

`argv` never includes the program name. `input` says what the attacker controls. Most bugs need a crafted **file** (`@@` is its path).
`filename` means the payload is the file's *name* (for example jhead's command injection), and
`argv` means `@@` stands for a crafted argument string rather than a path (ncompress's
CVE-2001-1413 pathname overflow). A target or bug whose `tree` is not on disk says so in a
`note`; its lines come from the upstream tag.

## Scoring

A lykos-demonstrated defect counts as a hit on a CVE when the **crashing frame's (file,
function)** matches the CVE's `(file, function)`. A matching `class` strengthens the match but
is not required, because sanitizers and lykos's root-causer can name the same bug differently
(an int-overflow often surfaces as a heap-overflow-read, for instance). `line` is for humans and
for tie-breaking when one function holds several CVEs. Match against the first few project
frames of the stack, not only the top one: some faults surface in a callee (unzip's CVE-2014-8139
reads out of bounds inside `crc32()`, several bugs fault in `memcpy`), and the entry's `note` names
the callee when that happens. Several ids can be one defect filed more than once (giflib's DumpScreen2RGB group, unzip's
memextract memcpy): report recall over distinct `(file, function, line)` as well as over ids.
Two numbers are reported per target:

- **found**: a finding at the CVE's (file, function), on any rung of the ladder;
- **proven**: a validated PoC (a demonstrated crash or exploit) whose crashing frame matches.

Use `confidence` to weight or filter. `low` means we could not confirm the version is
affected or could not pin the code, and a miss on such an entry should not be read as a recall
failure, and neither should a miss on an `in_build: false` entry when lykos used the
tree's documented build. Bugs that need `filename` or `argv` input are listed so they are not forgotten, but a
file-fuzzing run cannot be expected to reach them.

## Binary ground truth: surfaces, debug twins, address matching

Three surfaces are scored (`--surface source|binary|binary-stripped`, `both` = source+binary,
`all` = all three; `--rescore DIR` re-scores every `<id>--<surface>` run present in DIR):

- **source**: the `tree`;
- **binary**: the shipped `binary_path`, as built by `examples/vuln-targets/fetch_build.sh` (some
  have a symbol table, `unzip_x86-64` and `jhead-3.06.0.1_x86-64` ship stripped);
- **binary-stripped**: a `strip -s` copy of it, `examples/vuln-targets/bin/<bin>.stripped` (or
  `stripped_path`). No symbols at all: the honest "binary off the shelf" case.

A binary built without debug info gives a demonstrated dossier only a site address
(`location.site`, a link-time VA in hex) and, at best, the containing symbol. That symbol is often
`main` (skipped as a catch-all) or wrong for inlined/static code, so it cannot name the CVE's
function, and a stripped binary has no symbol at all. `debug_binary` fixes this. It names the
target's **debug twin**: the identical build with `-g` added and nothing else changed (the
build commands are in fetch_build.sh). A twin counts only when its `.text` is **byte-identical**
to the shipped binary's (`objcopy -O binary --only-section=.text`, compared). fetch_build.sh checks
this and deletes a twin that differs. A twin that maps addresses to the wrong code is worse than
none. `.text` is the same for `binary` and `binary-stripped`, so one twin serves both.

**Address matcher.** A dossier is first matched on its own frames, exactly as above. Only if
nothing matches, on a binary surface whose twin is on disk, its site VA is mapped with
`addr2line -a -f -i -e <twin> <va>` to `(function, file, line)` frames, inlined chain included
(innermost first). Those frames go through the same matcher. On this debug map `main` is NOT skipped:
addr2line names the true function, so `main` means the code really is in `main` (several entries
are). Runtime/libc frames are still skipped. Unmapped VAs (outside the twin, no line info) give no
frames, never a guess. Results are deterministic and cached per twin (path, size, mtime), with one
addr2line call per twin for all new VAs. Each `found` entry records `how` it matched:
`frame`, `addr` (its `site` beside it) or `class`. A dossier that already matched on its own frames
is scored exactly as before.

Targets without `debug_binary` (today unzip-6.0 and jhead-3.04): the shipped binaries were built with
a toolchain that cannot be reproduced exactly here (Debian gcc 16.2.0-1, and for the static jhead
its glibc `libc.a`). A twin built with a later toolchain does not have identical `.text`, so none is
recorded. Re-running fetch_build.sh rebuilds each binary together with its twin, so they are identical by
construction. Add `debug_binary` then, and re-run the binary surfaces, because old runs' VAs refer to the
old binary.
