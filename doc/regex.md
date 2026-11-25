# Regular expressions — the `re` module

`import re;` gives regular expressions designed after Rust's `regex` crate and
Python's `re`. A pattern is compiled once and then searched as often as needed:

```sic
import re;

auto r = re::Compile("(?P<year>\\d{4})-(\\d{2})") else return 1;

r.is_match("on 2026-11");                    // true
match (r.find("on 2026-11")) {
    Some(m): printf("%zu..%zu %s\n", m.start, m.end, m.text.ptr);   // 3..10 2026-11
    None: {}
}
```

`re::Compile` returns `Result<re::Regex, string>`; the error message says what is
wrong and where (in code points): `re: missing ), unterminated subpattern at
position 0`. A `Regex` does not change once compiled, so one may be shared between
threads.

## Matching

Matching takes time linear in the length of the text, whatever the pattern: all
the ways the pattern can match are followed at once (a Pike VM), so there is no
exponential backtracking (`(a*)*b` on a long run of `a`s is as fast as any other
search). Of the matches that start first, the one the pattern prefers wins
(leftmost-first, as in Rust and Python): `a|ab` on `"ab"` matches `"a"`, and a
greedy `a+` takes as many as it can, a lazy `a+?` as few.

The text is UTF-8. `.`, `[^x]` and a class match one code point; the offsets of a
match are **bytes**, so `s[m.start:m.end]` is the match and they agree with
`s.size` and `s.find()`. An invalid byte matches as U+FFFD. `\d`, `\w`, `\s`, `\b`
and `(?i)` are ASCII-only (as Rust's `(?-u)` and Python's `re.ASCII`).

## The `Regex` methods

| method | result |
|--------|--------|
| `r.is_match(s)` | whether the pattern matches anywhere in `s` |
| `r.find(s)` | the leftmost match: `Option<re::Match>` |
| `r.find_at(s, start)` | the leftmost match at or after byte `start` (what comes before still counts for `^` and `\b`) |
| `r.fullmatch(s)` | a match of all of `s` |
| `r.captures(s)`, `r.captures_at(s, start)` | the groups of the leftmost match: `Option<re::Captures>` |
| `r.find_iter(s)` | each successive non-overlapping match, for a range-`for` |
| `r.captures_iter(s)` | the groups of each successive match |
| `r.find_all(s)` | all the matches: `list<re::Match>` |
| `r.replace(s, rep)`, `r.replace_all(s, rep)`, `r.replacen(s, n, rep)` | `s` with the first, every, or the first `n` matches replaced |
| `r.split(s)`, `r.splitn(s, n)` | the pieces of `s` between the matches: `list<string>` (at most `n`; the last is the rest) |
| `r.captures_len()` | the number of groups, the whole match included |
| `r.as_str()` | the pattern |

`re::Escape(s)` escapes every character that has a meaning in a pattern, so that
`re::Compile(re::Escape(s))` matches `s` itself.

A `re::Match` has `start`, `end` and `text` (a view of the searched string, not a
copy). A `re::Captures` holds every group of one match:

```sic
match (r.captures("on 2026-11")) {
    Some(c): {
        c.group(1);          // "2026": a group's text, "" when it took no part
        c.get(2);            // Option<re::Match>: None when it took no part
        c.name("year");      // Option<re::Match> by name
        c.len();             // 3: groups, the whole match (group 0) included
    }
    None: {}
}

for (auto m : r.find_iter(text)) { … m.text … }
for (auto c : r.captures_iter(text)) { … c.group(1) … }
```

An empty match may directly follow a non-empty one, but not another empty one at
the same place (as in Python): `x*` on `"axxb"` matches at 0..0, 1..3, 3..3 and
4..4.

### Replacements

In the replacement text `$1` is group 1, `$name` and `${name}` a named group
(`${1}` when a letter follows the number), and `$$` a `$`. A group that took no
part, or that does not exist, is empty. This is Rust's syntax (a pattern's `\1`
stays free for backreferences).

```sic
auto mail = re::Compile("(\\w+)@(?P<host>\\w+)") else return 1;
mail.replace_all("x@y and foo@bar", "${host}/$1");   // "y/x and bar/foo"
```

## Pattern syntax

| syntax | matches |
|--------|---------|
| `x` | the character `x`; `\.` `\*` … a meta character itself |
| `\n \t \r \f \v \a \0` | newline, tab, CR, form feed, vertical tab, bell, NUL |
| `\xHH`, `\x{H…}`, `\uHHHH`, `\u{H…}`, `\UHHHHHHHH` | a code point by number |
| `.` | any character but `\n` (any with `(?s)`) |
| `[abc]`, `[a-z]`, `[^…]` | a character in (not in) the set; `\d \w \s` and their complements may be inside; `]` first and `-` at either end are literal |
| `\d \w \s` | `[0-9]`, `[0-9A-Za-z_]`, `[\t\n\v\f\r ]`; `\D \W \S` the rest |
| `^ $` | the start, the end of the text (of a line with `(?m)`) |
| `\A`, `\z` (`\Z`) | the start, the end of the text |
| `\b`, `\B` | a word boundary, not one |
| `xy`, `x\|y` | `x` then `y`, `x` or `y` |
| `x* x+ x?` | 0 or more, 1 or more, 0 or 1 |
| `x{n} x{n,} x{n,m} x{,m}` | exactly `n`, at least `n`, `n` to `m`, at most `m` (up to 1000) |
| `x*? x+? x?? x{n,m}?` | the same, as few as possible |
| `(x)` | a group, numbered from 1 by its `(` |
| `(?P<name>x)`, `(?<name>x)` | a named group |
| `(?:x)` | a group that captures nothing |
| `(?flags)`, `(?flags:x)` | flags to the end of the group, or for `x` only |
| `(?#…)` | a comment |

A `{` that does not start a repetition is itself (Python's rule). The flags are
`i` (ASCII case-insensitive), `m` (`^`/`$` at lines), `s` (`.` matches `\n`) and `x`
(whitespace and `#` comments in the pattern are ignored, outside classes; `\ ` is
a space); `-` turns those after it off: `(?i)a(?-i)b`. As in Rust, `(?i)` holds to
the end of its group, also in the alternatives after it.

A loop whose body can match the empty string behaves as in Rust: its first pass
may match nothing, but a later pass that matches nothing is not taken. Python
takes one more empty pass, so a group in such a loop can capture differently
(`(a|)+` on `"a"`: Rust and SIC give group 1 = `"a"`, Python `""`).

### Not supported

Backreferences (`\1`, `\k<name>`, `(?P=name)`) and lookaround (`(?=…)`, `(?!…)`,
`(?<=…)`, `(?<!…)`) are compile errors: they need a backtracking engine, whose
time can grow exponentially. Unicode classes (`\p{L}`) and Unicode case folding
are not there yet, nor possessive repetition (`a*+`). A pattern may not compile
to more than 100 000 instructions (`(?:a{1000}){1000}` is too large) nor nest
groups deeper than 250.

Next: [writing idiomatic SIC](sic-for-llms.md).
