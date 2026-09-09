# RE test corpus — many architectures, formats, languages, difficulty

A diverse set of binaries for exercising the reverse-engineering pipeline (triage →
Ghidra decompile → functions/CFG/signatures/stack-frame → detection). The actual
binaries are **not committed** (large, and reproducible); regenerate them:

```sh
./build_corpus.sh   # locally compiled: x86-64 C (O0/O3/static/stripped), UPX, PE (mingw), C++
./fetch_real.sh     # downloaded real-world: busybox across 13 arches + ripgrep (Rust)
```

See `bin/manifest.tsv` (committed) for the full list. Coverage:

- **Architectures:** x86-64, i386/i686, aarch64, arm (v4/v5/v6), mips (BE), mipsel (LE),
  powerpc (BE), ppc64le, riscv64, s390x (BE), sparc — big & little endian, 32 & 64-bit,
  RISC & CISC.
- **Formats:** ELF, PE (Windows, via MinGW).
- **Languages:** C, C++ (mangled names, vtables, exceptions), Rust (ripgrep).
- **Difficulty:** stripped, statically linked, `-O3`, UPX-packed, and large real-world
  binaries (busybox is static+stripped; ripgrep is a stripped PIE Rust binary).

`build_corpus.sh` skips any toolchain that isn't installed (cross-GCC, Go, Rust may be
absent); `fetch_real.sh` needs network. Provenance: busybox.net prebuilt binaries and
Debian `busybox-static` / `rust-ripgrep` packages.
