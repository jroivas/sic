#!/bin/bash
# Differential test of x86 intrinsics, sic against GCC.
#   tests/intrin/mk.sh NAME "GCCFLAGS" HEADER...
# generates NAME.c calling every intrinsic of the headers (dropping the calls
# GCC itself rejects, e.g. out-of-range immediates), builds it with GCC and
# sic (-O0 and -O2), and reports the intrinsics whose results differ.
# Example: tests/intrin/mk.sh sse "-msse2" mmintrin.h xmmintrin.h emmintrin.h
D=$(cd "$(dirname "$0")" && pwd)
SIC=${SIC:-$D/../../siccomp/target/release/sic}
N=$1; F=$2; shift 2
rm -f $N.drop
for i in 1 2 3 4 5 6; do
  python3 $D/gen.py $N.c "$@" --drop $N.drop 2>/dev/null
  if gcc -O0 $F -w $N.c -o ${N}_gcc 2> $N.err; then ok=1; break; fi
  grep -o "^$N.c:[0-9]*" $N.err | cut -d: -f2 | sort -u | while read l; do grep "^$l " $N.c.map | cut -d' ' -f2; done >> $N.drop
  sort -u -o $N.drop $N.drop
done
[ -n "$ok" ] || { echo "gcc still rejects $N.c"; head $N.err; exit 1; }
./${N}_gcc > $N.gcc.out
for o in -O0 -O2; do
  $SIC $o -w $N.c -o ${N}_sic || exit 1
  stdbuf -oL ./${N}_sic > $N.sic.out
  echo "sic $o: rc=$? $(wc -l < $N.sic.out)/$(wc -l < $N.gcc.out) lines"
  diff $N.gcc.out $N.sic.out | grep '^>' | cut -d'#' -f1 | sort | uniq -c | sort -rn | head -40
done
