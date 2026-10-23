#!/bin/bash
# sic-fmt's tests:
#   - each tests/NAME.sic formats to tests/NAME.out, and NAME.out to itself;
#   - each tests/NAME.err-input is refused (exit 1, the file left as it is) with
#     the message in NAME.err;
#   - the command line: --check, -l, writing in place, sic-fmt.toml, --config;
#   - every SIC source of the repository formats without error, and formatting
#     the result again changes nothing.
# Usage: ./test.sh [path/to/sic-fmt]   (default: ./sic-fmt — `make` first)
cd "$(dirname "$0")"
FMT="$(realpath "${1:-./sic-fmt}")"
[ -x "$FMT" ] || { echo "no sic-fmt at $FMT — run make"; exit 2; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
pass=0; fail=0; failed=""
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); failed="$failed $1"; echo "FAIL $1${2:+: $2}"; }

for t in tests/*.sic; do
    name=$(basename "$t" .sic)
    out="tests/$name.out"
    if ! "$FMT" < "$t" > "$TMP/got" 2> "$TMP/err"; then bad "$name" "$(cat "$TMP/err")"; continue; fi
    if ! cmp -s "$TMP/got" "$out"; then bad "$name" "differs from $out"; diff "$out" "$TMP/got" | head -20; continue; fi
    "$FMT" < "$out" > "$TMP/again" 2>/dev/null
    if ! cmp -s "$TMP/again" "$out"; then bad "$name" "formatting $out again changes it"; continue; fi
    ok
done

for t in tests/*.err-input; do
    name=$(basename "$t" .err-input)
    cp "$t" "$TMP/in.sic"
    if "$FMT" "$TMP/in.sic" 2> "$TMP/err"; then bad "$name" "accepted"; continue; fi
    if ! grep -qF "$(cat "tests/$name.err")" "$TMP/err"; then bad "$name" "message: $(cat "$TMP/err")"; continue; fi
    if ! cmp -s "$t" "$TMP/in.sic"; then bad "$name" "the file was changed"; continue; fi
    ok
done

# The command line.
mkdir -p "$TMP/p/sub/.hidden"
printf 'int  main(){return 0;}\n' > "$TMP/p/a.sic"
printf 'int f(int x) { return x * 2; }\n' > "$TMP/p/sub/b.sic"
cp "$TMP/p/a.sic" "$TMP/p/sub/.hidden/c.sic"
"$FMT" --check "$TMP/p" > "$TMP/diff"; rc=$?
if [ $rc -eq 1 ] && grep -q '^-int  main' "$TMP/diff" && grep -q '^+int main() { return 0; }' "$TMP/diff"; then ok; else bad check "exit $rc"; fi
"$FMT" -l "$TMP/p" > "$TMP/list"
if [ "$(cat "$TMP/list")" = "$TMP/p/a.sic" ] && grep -q '^int main() { return 0; }$' "$TMP/p/a.sic" \
    && cmp -s "$TMP/p/sub/.hidden/c.sic" <(printf 'int  main(){return 0;}\n'); then ok; else bad in-place; fi
if "$FMT" --check "$TMP/p" > /dev/null; then ok; else bad check-clean; fi
printf 'tab_spaces = 2\n' > "$TMP/p/sic-fmt.toml"
printf 'void g() {\nx();\n}\n' > "$TMP/p/sub/d.sic"
if [ "$("$FMT" --emit stdout "$TMP/p/sub/d.sic" | sed -n 3p)" = "  x();" ]; then ok; else bad config-file; fi
if [ "$("$FMT" --config tab_spaces=8 --emit stdout "$TMP/p/sub/d.sic" | sed -n 3p)" = "        x();" ]; then ok; else bad config-flag; fi
if ! "$FMT" --config nope=1 "$TMP/p/a.sic" 2>/dev/null; then ok; else bad config-unknown; fi

# The repository's sources: no errors (but the expected refusals), stable.
REPO="$(realpath ..)"
refused="tests/preprocess_0071.sic"     # its parentheses balance only across #if branches
n=0
while IFS= read -r f; do
    rel="${f#$REPO/}"
    case " $refused " in *" $rel "*) continue ;; esac
    n=$((n + 1))
    if ! "$FMT" < "$f" > "$TMP/once" 2> "$TMP/err"; then bad "$rel" "$(cat "$TMP/err")"; continue; fi
    "$FMT" < "$TMP/once" > "$TMP/twice" 2>/dev/null
    cmp -s "$TMP/once" "$TMP/twice" || bad "$rel" "not stable"
done < <(find "$REPO/tests" "$REPO/siccomp/lib" "$REPO/sic-cpp/src" "$REPO/sic-fmt/src" "$REPO/module_test" \
             -name '*.sic' -not -path '*/target/*' | sort)
[ $fail -eq 0 ] && echo "repository: $n files formatted, all stable"

echo "Passed $pass/$((pass + fail)) (and the repository check)"
[ $fail -eq 0 ] || { echo "Failed:$failed"; exit 1; }
