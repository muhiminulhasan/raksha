#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
x86_64-w64-mingw32-gcc -O2 -o hello.exe hello.c \
    -Wl,--enable-reloc-section -Wl,-emain
echo "built fixtures/hello.exe"
