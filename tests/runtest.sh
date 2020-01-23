#!/bin/bash

MYDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
outfolder=$1

#echo $tests
ls $MYDIR/*.sic | while read test; do
    base=$(basename $test .sic)
    echo "*** $base"
    ${CC} $test -o "$outfolder/$base.out"
done
