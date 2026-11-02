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
