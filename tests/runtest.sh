#!/bin/bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 build_folder [llvm]"
    exit 1
fi

MYDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
outfolder=$1
llvm=0
if [ $# -ge 2 ]; then
    if [ "$2" == "llvm" ]; then
       llvm=1
    fi
fi

tests=0
success=0
while read test; do
    base=$(basename $test .sic)
    echo "*** $base"
    tests=$((tests+1))
    ${CC} $test -o "$outfolder/$base.ir"
    if [ "$llvm" -eq 1 ]; then
        if ! llvm-as "$outfolder/$base.ir"; then
            echo "--- FAILED: llvm-as"
            continue
        fi
        if ! llc -O0 -relocation-model=pic -filetype=obj "$outfolder/$base.ir.bc" -o "$outfolder/$base.ir.o"; then
            echo "--- FAILED: llc"
            continue
        fi
        if ! gcc "$outfolder/$base.ir.o" -o "$outfolder/$base.ir.bin" -lm; then
            echo "--- FAILED: link"
            continue
        fi
        "$outfolder/$base.ir.bin"
        echo "+++ Success, return $?"
    fi
    success=$((success+1))
done <<<$(ls $MYDIR/*.sic)

failed=$((tests-success))
echo "*** Passed ${success}/${tests} (failed ${failed})"
