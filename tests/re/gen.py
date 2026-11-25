#!/usr/bin/env python3
"""Make the differential test cases of sic's `re` module, with Python's `re` as
the reference: cases.txt (pattern and text per line, in hex) and expected.txt
(what Python finds, in the report format of run.sic).

    python3 -I tests/re/gen.py      # rewrites tests/re/cases.txt and expected.txt

The cases are hand-written ones and random patterns over a small alphabet (a
fixed seed: the same files each time). Python runs with re.ASCII, as sic's
classes and case folding are ASCII; offsets are converted to bytes. A pattern's
`$` (without (?m)) is `\\Z` for Python, whose `$` also matches before a final
newline.
"""
import os
import random
import re

HERE = os.path.dirname(os.path.abspath(__file__))

# (sic pattern, Python pattern or None for the same, texts)
HAND = [
    (r"a|ab", None, ["ab", "b", "xab"]),
    (r"(a+)(b*)", None, ["xaaabbc", "bbb", ""]),
    (r"(?P<y>\d{4})-(\d\d)", None, ["on 2026-11 ok", "1-2", "2026-1x 1999-12"]),
    (r"[^a-c]+", None, ["abcdef", "", "zzz"]),
    (r"(?i)hello", None, ["say HeLLo", "HELLO hello", "help"]),
    (r"(?i)[a-c]+", None, ["xABcaB", "D"]),
    (r"(?i)[^a]", None, ["aAb", "A"]),
    (r"^b", None, ["ab", "b", "\nb"]),
    (r"(?m)^b", None, ["a\nb", "b\nb", "ab"]),
    (r"(?m)a$", None, ["a\na", "ba\n", "ab"]),
    (r"a$", r"a\Z", ["a\na", "ba", "ba\n"]),
    (r"\bfoo\b", None, ["afoo foo", "foo", "foo_bar foo."]),
    (r"\Bo\B", None, ["foo", "o", "boom"]),
    (r"a{2,3}?", None, ["aaaa", "a"]),
    (r"a{2,}", None, ["a aa aaaaa", ""]),
    (r"a{,2}", None, ["aaa", "b"]),
    (r"a{3}", None, ["aaaaaaa"]),
    (r"x{a", None, ["x{a", "xa"]),
    (r"x*", None, ["abc", "xx", ""]),
    (r"\w*", None, ["ab cd", " ", ""]),
    (r"é.", None, ["café!", "éé", "e"]),
    (r".", None, ["日本", "a\nb"]),
    (r"(?s).", None, ["a\nb"]),
    (r"[α-ω]+", None, ["abγδεz", "Ω"]),
    (r"(a)|(b)", None, ["b", "ab"]),
    (r"(a|b)*c", None, ["abac", "c", "ababx"]),
    (r"(?:ab)+", None, ["ababab", "aba"]),
    (r"(a*?)(a*)", None, ["aaa"]),
    (r"(a+?)b", None, ["aaab"]),
    (r"\d+\.\d*", None, ["pi is 3.14, e 2.", "1."]),
    (r"\s+", None, ["a \t\n b", "x"]),
    (r"\S+", None, ["ab  cd"]),
    (r"[\d_]+", None, ["a_1_2b"]),
    (r"[\w.-]+@[\w.-]+", None, ["mail me at a.b-c@ex.org now"]),
    (r"[-a]", None, ["-", "a", "b"]),
    (r"[a-]", None, ["-", "b"]),
    (r"[]a]", None, ["]", "a"]),
    (r"[^]a]", None, ["]ab"]),
    (r"\x41é\n", None, ["Aé\n"]),
    (r"\.\*\+\?\(\)\[\]\{\}\|\^\$\\", None, [".*+?()[]{}|^$\\"]),
    (r"(?i:a)b", None, ["Ab", "AB", "ab"]),
    (r"a(?i)b|c", r"a(?i:b)|(?i:c)", ["aB", "C", "c"]),
    (r"(?:^)*a", None, ["a"]),
    (r"(?:\b|x)+y", None, ["xy", "y"]),
    (r"(?x) a b # comment", None, ["ab", "a b"]),
    (r"(?x) a\ b", None, ["a b"]),
    (r"(?#comment)ab", None, ["ab"]),
    (r"(?P<first>\w+) (?P<last>\w+)", None, ["Ada Lovelace"]),
    (r"", None, ["", "ab"]),
    (r"|a", None, ["a"]),
    (r"a|", None, ["a", "b"]),
    (r"()", None, ["a"]),
    (r"((a)|b)+", None, ["ab", "ba"]),
    (r"(a|ab)(c|bcd)(d*)", None, ["abcd"]),
    (r"(?:a|b)*?b", None, ["aab"]),
    (r"\A\w+\Z", None, ["word", "two words"]),
    (r"[a-cx-z]", None, ["w", "y", "b"]),
    (r"[^\s]+", None, ["  ab c"]),
    (r"[\D]", None, ["1a"]),
    (r"[^\W]+", None, ["!ab_1!"]),
    (r"\t|\v|\f|\r", None, ["\v\f"]),
    # errors in both
    (r"(", None, [""]),
    (r"a)", None, [""]),
    (r"*a", None, [""]),
    (r"a**", None, [""]),
    (r"[a", None, [""]),
    (r"[b-a]", None, [""]),
    (r"a{3,2}", None, [""]),
    (r"(?P<n>a)(?P<n>b)", None, [""]),
    (r"\q", None, [""]),
    (r"(?z)", None, [""]),
    (r"[\d-z]", None, [""]),
    (r"[\d-]+", None, ["1-2a"]),
]

ALPHA = "ab1 \n"


def rand_atom(rng, depth, flags):
    """A random atom as (sic, python, whether it can match the empty string)."""
    k = rng.randrange(14 if depth < 3 else 10)
    if k <= 2:
        c = rng.choice("ab1 ")
        return c, c, False
    if k == 3:
        return ".", ".", False
    if k == 4:
        c = rng.choice(["[ab]", "[^a]", "[a-b1]", "[^ \\n]", "[\\d ]", "[^\\w]"])
        return c, c, False
    if k == 5:
        c = rng.choice(["\\d", "\\w", "\\s", "\\D", "\\W", "\\S"])
        return c, c, False
    if k == 6:
        c = rng.choice(["\\b", "\\B", "^"])
        return c, c, True
    if k == 7:
        if "m" in flags:
            return "$", "$", True
        return "$", "\\Z", True
    if k <= 9:
        c = rng.choice("ab")
        return c, c, False
    s, p, e = rand_alt(rng, depth + 1, flags)
    kind = rng.randrange(3)
    if kind == 0:
        return "(" + s + ")", "(" + p + ")", e
    if kind == 1:
        return "(?:" + s + ")", "(?:" + p + ")", e
    return "(?P<g%d>" % depth + s + ")", "(?P<g%d>" % depth + p + ")", e


def rand_quant(rng):
    k = rng.randrange(12)
    q = ["", "", "", "", "*", "+", "?", "{2}", "{1,2}", "{0,3}", "{2,}", "{,2}"][k]
    if q and rng.randrange(3) == 0:
        q += "?"
    return q


# A loop whose body can match the empty string is where Python and Rust differ:
# Python takes one more, empty, pass after a non-empty one; sic does as Rust.
# Such an atom is only made optional.
def rand_cat(rng, depth, flags):
    s, p, empty = "", "", True
    for _ in range(rng.randrange(1, 4)):
        a, b, e = rand_atom(rng, depth, flags)
        q = rand_quant(rng)
        if q and (a in ("\\b", "\\B", "^", "$")):
            q = ""
        if e and q not in ("", "?", "??"):
            q = ""
        if q in ("*", "?", "{0,3}", "{,2}") or q[:-1] in ("*", "?", "{0,3}", "{,2}"):
            e = True
        s += a + q
        p += b + q
        empty = empty and e
    return s, p, empty


def rand_alt(rng, depth, flags):
    s, p, e = rand_cat(rng, depth, flags)
    while rng.randrange(4) == 0:
        a, b, f = rand_cat(rng, depth, flags)
        s += "|" + a
        p += "|" + b
        e = e or f
    return s, p, e


def rand_case(rng):
    flags = rng.choice(["", "", "", "i", "m", "s", "ms"])
    s, p, _ = rand_alt(rng, 0, flags)
    if flags:
        s = "(?" + flags + ")" + s
        p = "(?" + flags + ")" + p
    texts = ["".join(rng.choice(ALPHA + "AB") for _ in range(rng.randrange(0, 9))) for _ in range(3)]
    return s, p, texts


def boff(s, i):
    return len(s[:i].encode())


def report(pat, text):
    """What run.sic prints for this case, by Python's re."""
    try:
        r = re.compile(pat, re.ASCII)
    except re.error:
        return "error"
    ms = []
    for m in r.finditer(text):
        gs = []
        for g in range(r.groups + 1):
            a, b = m.span(g)
            gs.append("-" if a < 0 else "%d:%d" % (boff(text, a), boff(text, b)))
        ms.append(",".join(gs))
    f = r.fullmatch(text)
    full = "none" if f is None else "%d:%d" % (boff(text, f.start()), boff(text, f.end()))
    rep = "<\\g<1>>" if r.groups >= 1 else "<\\g<0>>"
    sub = r.sub(rep, text).encode().hex()
    return "M %s F %s R %s" % (" ".join(ms) or "none", full, sub or "-")


def main():
    rng = random.Random(20261125)
    cases = []
    for s, p, texts in HAND:
        for t in texts:
            cases.append((s, p or s, t))
    for _ in range(3000):
        s, p, texts = rand_case(rng)
        for t in texts:
            cases.append((s, p, t))
    with open(os.path.join(HERE, "cases.txt"), "w") as fc, open(os.path.join(HERE, "expected.txt"), "w") as fe:
        for s, p, t in cases:
            fc.write("%s %s\n" % (s.encode().hex() or "-", t.encode().hex() or "-"))
            fe.write(report(p, t) + "\n")


main()
