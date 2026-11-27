#!/bin/bash
# Tests of the re module (lib/re): the API (api.sic against
# api.expected) and a differential test against Python's re (run.sic over
# cases.txt against expected.txt, both made by gen.py). Python is not needed
# to run them.
#   tests/re/re.sh                 # uses siccomp/target/release/sic
#   SIC=/path/to/sic tests/re/re.sh
D=$(cd "$(dirname "$0")" && pwd)
SIC=${SIC:-$D/../../siccomp/target/release/sic}
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
mkdir "$W/re"
cp "$D/../../lib/re/re.sic" "$W/re/"
"$SIC" -O2 --emit-module "$W/re" > "$W/err" 2>&1 || { echo "FAIL re: module build"; cat "$W/err"; exit 1; }
fail=0
for o in -O0 -O2; do
    if ! "$SIC" $o "$D/api.sic" -I"$W/re" "$W/re/libre.a" -o "$W/api" 2> "$W/err"; then
        echo "FAIL re api $o: compile"; cat "$W/err"; fail=1
    elif "$W/api" > "$W/api.out" && cmp -s "$W/api.out" "$D/api.expected"; then
        echo "ok   re api $o"
    else
        echo "FAIL re api $o"; diff "$D/api.expected" "$W/api.out" | head -20; fail=1
    fi
    if ! "$SIC" $o "$D/run.sic" -I"$W/re" "$W/re/libre.a" -o "$W/run" 2> "$W/err"; then
        echo "FAIL re python $o: compile"; cat "$W/err"; fail=1
    elif "$W/run" "$D/cases.txt" > "$W/run.out" && cmp -s "$W/run.out" "$D/expected.txt"; then
        echo "ok   re python $o ($(wc -l < "$D/cases.txt") cases)"
    else
        echo "FAIL re python $o"; diff "$D/expected.txt" "$W/run.out" | head -20; fail=1
    fi
done
exit $fail
