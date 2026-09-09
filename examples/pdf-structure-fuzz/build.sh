#!/usr/bin/env bash
# Build the mock PDF parser used by the structure-aware fuzzing demo.
set -eu
cd "$(dirname "$0")"
gcc -O0 -fno-stack-protector -no-pie pdfparse.c -o pdfparse
echo "built ./pdfparse"
