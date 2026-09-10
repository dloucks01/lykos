#!/usr/bin/env bash
# Build a diverse RE test corpus: many architectures, formats (ELF/PE), languages
# (C/C++/Go/Rust), and difficulty knobs (stripped, static, -O3, UPX-packed).
# Skips any toolchain that isn't installed. Output: ./bin/  + manifest.tsv
set -u
cd "$(dirname "$0")"
SRC=src; OUT=bin; mkdir -p "$OUT"
MAN="$OUT/manifest.tsv"; : > "$MAN"
echo -e "file\tarch\tformat\tlang\tnotes" >> "$MAN"

have(){ command -v "$1" >/dev/null 2>&1; }
emit(){ # file arch format lang notes
  [ -f "$OUT/$1" ] && echo -e "$1\t$2\t$3\t$4\t$5" >> "$MAN" && echo "  + $1 ($2 $3 $4 $5)"
}

# arch matrix: label  compiler-prefix
CC_MATRIX="
x86-64:
i386:-m32
aarch64:aarch64-linux-gnu-
armhf:arm-linux-gnueabihf-
armel:arm-linux-gnueabi-
mips:mips-linux-gnu-
mipsel:mipsel-linux-gnu-
ppc:powerpc-linux-gnu-
ppc64:powerpc64-linux-gnu-
ppc64le:powerpc64le-linux-gnu-
riscv64:riscv64-linux-gnu-
s390x:s390x-linux-gnu-
sparc64:sparc64-linux-gnu-
"

echo "== C matrix (vuln.c, parser.c) across architectures =="
for entry in $CC_MATRIX; do
  arch="${entry%%:*}"; rest="${entry#*:}"
  if [ "$arch" = "i386" ]; then CC="gcc"; FLAGS="-m32"; else
    pfx="$rest"; CC="${pfx}gcc"; FLAGS=""; fi
  have "$CC" || { echo "  (skip $arch: $CC absent)"; continue; }
  # default -O0
  $CC $FLAGS -O0 -fno-stack-protector -w "$SRC/vuln.c"   -o "$OUT/vuln_${arch}"       2>/dev/null && emit "vuln_${arch}"       "$arch" ELF C "O0"
  $CC $FLAGS -O0 -fno-stack-protector -w "$SRC/parser.c" -o "$OUT/parser_${arch}"     2>/dev/null && emit "parser_${arch}"     "$arch" ELF C "O0 file-parser"
  # stripped
  if [ -f "$OUT/vuln_${arch}" ]; then cp "$OUT/vuln_${arch}" "$OUT/vuln_${arch}_stripped"; strip "$OUT/vuln_${arch}_stripped" 2>/dev/null && emit "vuln_${arch}_stripped" "$arch" ELF C "O0 stripped"; fi
  # optimized -O3 (harder decompile)
  $CC $FLAGS -O3 -fno-stack-protector -w "$SRC/vuln.c"   -o "$OUT/vuln_${arch}_O3"     2>/dev/null && emit "vuln_${arch}_O3"    "$arch" ELF C "O3"
  # static (self-contained, big symbol soup)
  $CC $FLAGS -O2 -static -w "$SRC/vuln.c"                -o "$OUT/vuln_${arch}_static" 2>/dev/null && strip "$OUT/vuln_${arch}_static" 2>/dev/null && emit "vuln_${arch}_static" "$arch" ELF C "O2 static stripped"
done

# == musl cross toolchains (static-pie, self-contained -> ideal for qemu-user) ==
# The distro cross-GCC family is often absent; musl.cc ships static prebuilt toolchains that
# produce self-contained static-pie binaries qemu-user runs with no target libs. Point
# MUSL_CROSS_ROOT at a dir holding extracted <triple>-cross/ trees (e.g. arm-linux-musleabihf-cross)
# to (re)build the cross vuln_<arch> matrix. `-static` (musl links it static-pie) + keep symbols.
#   arch label  : musl triple
MUSL_MATRIX="
arm:arm-linux-musleabihf
aarch64:aarch64-linux-musl
mipsel:mipsel-linux-musl
mips_be:mips-linux-musl
ppc:powerpc-linux-musl
riscv64:riscv64-linux-musl
"
if [ -n "${MUSL_CROSS_ROOT:-}" ] && [ -d "$MUSL_CROSS_ROOT" ]; then
  echo "== musl cross matrix (MUSL_CROSS_ROOT=$MUSL_CROSS_ROOT) =="
  for entry in $MUSL_MATRIX; do
    arch="${entry%%:*}"; triple="${entry#*:}"
    MCC="$MUSL_CROSS_ROOT/${triple}-cross/bin/${triple}-gcc"
    MSTRIP="$MUSL_CROSS_ROOT/${triple}-cross/bin/${triple}-strip"
    [ -x "$MCC" ] || { echo "  (skip $arch: ${triple}-gcc absent)"; continue; }
    if "$MCC" -O0 -fno-stack-protector -static -w "$SRC/vuln.c" -o "$OUT/vuln_${arch}" 2>/dev/null; then
      emit "vuln_${arch}" "$arch" ELF C "O0 static-pie stack-overflow (musl cross)"
      cp "$OUT/vuln_${arch}" "$OUT/vuln_${arch}_stripped"
      "$MSTRIP" "$OUT/vuln_${arch}_stripped" 2>/dev/null && emit "vuln_${arch}_stripped" "$arch" ELF C "O0 static-pie stripped"
    fi
  done
else
  echo "== musl cross matrix skipped (set MUSL_CROSS_ROOT to a dir of <triple>-cross toolchains; get them from musl.cc) =="
fi

echo "== Windows PE via MinGW =="
have x86_64-w64-mingw32-gcc && x86_64-w64-mingw32-gcc -O2 -w "$SRC/vuln.c" -o "$OUT/vuln_win64.exe" 2>/dev/null && emit "vuln_win64.exe" "x86-64" PE C "mingw"
have i686-w64-mingw32-gcc   && i686-w64-mingw32-gcc   -O2 -w "$SRC/vuln.c" -o "$OUT/vuln_win32.exe" 2>/dev/null && emit "vuln_win32.exe" "i386"   PE C "mingw"
if [ -f "$OUT/vuln_win64.exe" ]; then cp "$OUT/vuln_win64.exe" "$OUT/vuln_win64_stripped.exe"; strip "$OUT/vuln_win64_stripped.exe" 2>/dev/null && emit "vuln_win64_stripped.exe" "x86-64" PE C "mingw stripped"; fi

echo "== C++ (name mangling / vtables / exceptions) =="
have g++ && g++ -O2 -w "$SRC/shapes.cpp" -o "$OUT/shapes_x86-64_cpp" 2>/dev/null && emit "shapes_x86-64_cpp" "x86-64" ELF C++ "vtables+exceptions"
have aarch64-linux-gnu-g++ && aarch64-linux-gnu-g++ -O2 -w "$SRC/shapes.cpp" -o "$OUT/shapes_aarch64_cpp" 2>/dev/null && emit "shapes_aarch64_cpp" "aarch64" ELF C++ "vtables+exceptions"

echo "== Go (static, own runtime -- very hard) =="
if have go; then
  cat > "$OUT/.hello.go" <<'GO'
package main
import ("fmt";"os")
func secret(p string) bool { return len(p)==4 && p=="4242" }
func main(){ a:="anon"; if len(os.Args)>1 { a=os.Args[1] }; if secret(a){fmt.Println("unlocked")}; fmt.Println("hi",a) }
GO
  (cd "$OUT" && CGO_ENABLED=0 go build -o hello_go .hello.go 2>/dev/null) && emit "hello_go" "x86-64" ELF Go "static runtime"
  (cd "$OUT" && CGO_ENABLED=0 GOARCH=arm64 go build -o hello_go_arm64 .hello.go 2>/dev/null) && emit "hello_go_arm64" "aarch64" ELF Go "static runtime"
  (cd "$OUT" && CGO_ENABLED=0 GOOS=windows go build -o hello_go.exe .hello.go 2>/dev/null) && emit "hello_go.exe" "x86-64" PE Go "static runtime"
  rm -f "$OUT/.hello.go"
fi

echo "== Rust (static-ish, monomorphized -- hard) =="
if have rustc; then
  cat > "$OUT/.hello.rs" <<'RS'
use std::env;
fn secret(p:&str)->bool{ p.len()==4 && p=="4242" }
fn main(){ let a:Vec<String>=env::args().collect(); let s=if a.len()>1{&a[1]}else{"anon"};
  if secret(s){println!("unlocked");} println!("hi {}",s); }
RS
  rustc -O "$OUT/.hello.rs" -o "$OUT/hello_rust" 2>/dev/null && emit "hello_rust" "x86-64" ELF Rust "monomorphized"
  rm -f "$OUT/.hello.rs"
fi

echo "== UPX-packed (obfuscation/unpacking test) =="
if have upx && [ -f "$OUT/vuln_x86-64_static" ]; then
  cp "$OUT/vuln_x86-64_static" "$OUT/vuln_x86-64_upx"
  upx -q "$OUT/vuln_x86-64_upx" >/dev/null 2>&1 && emit "vuln_x86-64_upx" "x86-64" ELF C "UPX packed"
fi

echo "== Download real multi-arch busybox (stripped, static, real-world) =="
# Official prebuilt busybox binaries (busybox.net) -- real, stripped, statically linked.
BB=https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl
for pair in \
  "busybox-x86_64:x86-64:${BB/x86_64/x86_64}/busybox" ; do :; done
declare -A BBURL=(
  [busybox_x86-64]="https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"
  [busybox_armv7]="https://busybox.net/downloads/binaries/1.35.0-armv7l-linux-musleabihf/busybox"
  [busybox_armv5]="https://busybox.net/downloads/binaries/1.35.0-armv5l-linux-musleabi/busybox"
  [busybox_mips]="https://busybox.net/downloads/binaries/1.35.0-mips-linux-musl/busybox"
  [busybox_mipsel]="https://busybox.net/downloads/binaries/1.35.0-mipsel-linux-musl/busybox"
  [busybox_powerpc]="https://busybox.net/downloads/binaries/1.35.0-powerpc-linux-musl/busybox"
  [busybox_i686]="https://busybox.net/downloads/binaries/1.35.0-i686-linux-musl/busybox"
)
for name in "${!BBURL[@]}"; do
  arch="${name#busybox_}"
  if timeout 40 curl -fsSL "${BBURL[$name]}" -o "$OUT/$name" 2>/dev/null && [ -s "$OUT/$name" ]; then
    chmod -x "$OUT/$name" 2>/dev/null
    emit "$name" "$arch" ELF C "busybox real-world stripped static"
  else
    echo "  (skip $name: download failed/offline)"; rm -f "$OUT/$name"
  fi
done

echo
echo "== manifest ($(($(wc -l < "$MAN")-1)) binaries) =="
column -t -s $'\t' "$MAN" 2>/dev/null || cat "$MAN"
