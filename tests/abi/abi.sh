#!/bin/bash
# Differential calling-convention tests, sic against GCC. Each pair
# <name>_caller.c / <name>_callee.c is built by GCC and by sic, linked in every
# pairing, and each program must print what the all-GCC one does, per back end
# and optimization level:
#   ms  — `ms_abi` (the Microsoft x64 convention)
#   va  — System V structs and unions: through `...`, and past the registers
#   tests/abi/abi.sh            # uses siccomp/target/release/sic
#   SIC=/path/to/sic tests/abi/abi.sh
D=$(cd "$(dirname "$0")" && pwd)
SIC=${SIC:-$D/../../siccomp/target/release/sic}
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
cd "$W" || exit 1
fail=0
for t in ms va; do
  gcc -O1 -c "$D/${t}_caller.c" -o caller_gcc.o || exit 1
  gcc -O1 -c "$D/${t}_callee.c" -o callee_gcc.o || exit 1
  gcc caller_gcc.o callee_gcc.o -o ref && ./ref > ref.out || exit 1
  for be in $("$SIC" -print-backends); do
    for o in -O0 -O2; do
      "$SIC" -fbackend=$be $o -c "$D/${t}_caller.c" -o caller_sic.o || { echo "FAIL $t $be $o: sic caller"; fail=1; continue; }
      "$SIC" -fbackend=$be $o -c "$D/${t}_callee.c" -o callee_sic.o || { echo "FAIL $t $be $o: sic callee"; fail=1; continue; }
      for pair in "sic gcc" "gcc sic" "sic sic"; do
        set -- $pair
        gcc caller_$1.o callee_$2.o -o prog || { fail=1; continue; }
        if ./prog > out 2>&1 && cmp -s ref.out out; then
          echo "ok   $t $be $o caller=$1 callee=$2"
        else
          echo "FAIL $t $be $o caller=$1 callee=$2"; diff ref.out out | head -20; fail=1
        fi
      done
    done
  done
done
exit $fail
