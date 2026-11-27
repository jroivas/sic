#!/usr/bin/env bash
# Compare two lexers: each corpus file through `-dump-tokens` with compiler A and
# with compiler B, and diff the dumps (and the exit codes).
#
#   sic/tests/diff-lexer.sh                 franken: SIC_PARTS=none against =lexer
#   A=cmd B=cmd sic/tests/diff-lexer.sh     any two commands (words are split)
#
# Corpus: tests/*.c and *.sic (with their .flags), c-testsuite, lib/, sic-cpp,
# sic-fmt, tests/re and the SQLite amalgamation ($SQLITE_DIR, default
# ~/install/sqlite; skipped when it is not there). JOBS=N runs N at once
# (default: the CPUs). KEEP=1 keeps the work directory. Exits 1 on a difference.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FRANKEN="${FRANKEN:-$ROOT/sic/franken/target/release/sic}"
if [ -z "${A:-}" ] || [ -z "${B:-}" ]; then
    [ -x "$FRANKEN" ] || { echo "no franken compiler at $FRANKEN (sic/build.sh), or set A and B"; exit 2; }
fi
A="${A:-env SIC_PARTS=none $FRANKEN}"
B="${B:-env SIC_PARTS=lexer $FRANKEN}"
JOBS="${JOBS:-$(nproc)}"
SQLITE_DIR="${SQLITE_DIR:-$HOME/install/sqlite}"

W="$(mktemp -d)"
[ -n "${KEEP:-}" ] && echo "work directory: $W" || trap 'rm -rf "$W"' EXIT

# One corpus entry per line: the file, a tab, its flags.
{
    for f in "$ROOT"/tests/test_*.c "$ROOT"/tests/test_*.sic; do
        [ -e "$f" ] || continue
        flags=""; [ -f "$f.flags" ] && flags="$(cat "$f.flags")"
        printf '%s\t%s\n' "$f" "$flags"
    done
    find "$ROOT/c-testsuite/tests/single-exec" -name '*.c' 2>/dev/null | sort | sed 's/$/\t/'
    find "$ROOT/lib" "$ROOT/sic-cpp/src" "$ROOT/sic-cpp/lib" "$ROOT/sic-fmt/src" "$ROOT/tests/re" \
        -name '*.sic' 2>/dev/null | sort | sed 's/$/\t/'
    for f in sqlite3.c shell.c; do
        [ -f "$SQLITE_DIR/$f" ] && printf '%s\t-I%s\n' "$SQLITE_DIR/$f" "$SQLITE_DIR"
    done
} > "$W/corpus"

# compare N FILE FLAGS: one entry, a line `same|DIFF|DIFF-RC N FILE`.
compare() {
    local n="$1" f="$2" flags="$3"
    $A -dump-tokens $flags "$f" -o "$W/$n.a" > /dev/null 2> "$W/$n.a.err"; local ra=$?
    $B -dump-tokens $flags "$f" -o "$W/$n.b" > /dev/null 2> "$W/$n.b.err"; local rb=$?
    if [ "$ra" != "$rb" ]; then echo "DIFF-RC $n $f ($ra vs $rb)"
    elif [ "$ra" != 0 ]; then
        if cmp -s "$W/$n.a.err" "$W/$n.b.err"; then echo "same $n $f"; else echo "DIFF $n $f (errors)"; fi
    elif cmp -s "$W/$n.a" "$W/$n.b"; then echo "same $n $f"
    else echo "DIFF $n $f"; return 0
    fi
    # Only a difference is kept for looking at.
    rm -f "$W/$n.a" "$W/$n.b" "$W/$n.a.err" "$W/$n.b.err"
}
export -f compare
export A B W

n=0
while IFS=$'\t' read -r f flags; do
    n=$((n + 1))
    printf '%s\0%s\0%s\0' "$n" "$f" "$flags"
done < "$W/corpus" | xargs -0 -n 3 -P "$JOBS" bash -c 'compare "$@"' _ > "$W/results"

total=$(wc -l < "$W/results")
diffs=$(grep -c '^DIFF' "$W/results")
echo "A: $A"
echo "B: $B"
echo "files: $total, differing: $diffs"
if [ "$diffs" -gt 0 ]; then
    sort -k2 -n "$W/results" | grep '^DIFF' | head -n 20
    first=$(sort -k2 -n "$W/results" | grep -m1 '^DIFF ' | awk '{print $2}')
    if [ -n "$first" ] && [ -f "$W/$first.a" ]; then
        echo "--- first difference (A < > B):"
        diff "$W/$first.a" "$W/$first.b" | head -n 20
    fi
    [ -z "${KEEP:-}" ] && echo "(KEEP=1 keeps the dumps)"
    exit 1
fi
