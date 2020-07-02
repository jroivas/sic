#!/usr/bin/env bash

set -eu

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

dotest()
{
    base=$(basename $test .sic)
    echo "*** $base"
    tests=$((tests+1))
    if ! ${CC} $test -o "$outfolder/$base.ir" ; then
        echo "FAILED: ${CC} compile"
        return 1
    fi
    if [ "$llvm" -eq 1 ]; then
        if ! llvm-as "$outfolder/$base.ir"; then
            echo "FAILED: llvm-as"
            return 1
        fi
        if ! llc -O0 -relocation-model=pic -filetype=obj "$outfolder/$base.ir.bc" -o "$outfolder/$base.ir.o"; then
            echo "FAILED: llc"
            return 1
        fi
        if ! ${HOSTCC} "$outfolder/$base.ir.o" -o "$outfolder/$base.ir.bin" -lm; then
            echo "FAILED: link"
            return 1
        fi
        expected_res=0
        if [ -f "$test.res" ]; then
            expected_res=$(cat "$test.res")
        fi
        "$outfolder/$base.ir.bin"
        res=$?
        if [ "${res}" -eq "${expected_res}" ]; then
            echo "+++ Success, return $res"
        else
            echo "FAILED, return $res"
            return 1
        fi
    fi
    return 0
}

tests=0
success=0
VERS=${BASH_VERSINFO[0]}
if [ $VERS -ge 4 ]; then
    while read test; do
        if ! dotest; then
            continue
        fi
        success=$((success+1))
    done <<<$(ls $MYDIR/*.sic)
else
    for test in $(ls $MYDIR/*.sic); do
        if ! dotest; then
            continue
        fi
        success=$((success+1))
    done
fi

failed=$((tests-success))
echo "*** Passed ${success}/${tests} (failed ${failed})"
