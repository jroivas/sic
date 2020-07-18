#!/bin/bash

set -eu

if [ ! -f "$1" ]; then
    echo "Usage: $0 file"
    exit 1
fi

MYDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
export LD_LIBRARY_PATH="${MYDIR}/build:"

"${MYDIR}/build/sic" --dump-tree "$1" -o "$1.ir"
llvm-as "$1.ir"
llc -O0 -relocation-model=pic -filetype=obj "$1.ir.bc" -o "$1.ir.o"
${CC:-cc} "$1.ir.o" -o "$1.ir.bin" -lm

echo "Running:"
"$1.ir.bin"
echo
echo "Done"
