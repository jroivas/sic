# Strings

SIC has a native `string` type — a length-carrying, reference-counted UTF-8
string — alongside ordinary NUL-terminated C strings. A `string` is a small
descriptor `{ data, size, refcount }` over a byte buffer; slicing and passing it
around copies only the descriptor, never the bytes (see
[memory & ownership](memory-and-ownership.md)).

## Literals

```sic
string s = "Hello world!";
auto   t = "inferred";        // t is a `string`
```

A double-quoted literal **is a `string` by default** — a non-owning view over the
static bytes (so `auto`, `match`/ternary arms, and returns naturally yield a
`string`). It **decays to a `char*`** only where a pointer is wanted, decided from
the target type at compile time:

```sic
char *p = "raw";              // pointer target → stays a char*
strlen("abc");                // char* parameter → char*
printf("%s\n", name);         // C variadic → the string decays to a char*
char *q = "abcdef" + 2;       // `literal + int` is pointer arithmetic
```

So you get the native `string` everywhere it's reasonable, and plain `char*` for C
interop — no explicit conversions. SIC also has Python-style **triple-quoted**
literals:

```sic
// Non-raw: source newlines/indentation collapse to single spaces, escapes decode.
string a = """This is line one.
    And line two.""";                 // "This is line one. And line two."

// Raw (r prefix): bytes preserved verbatim, no escape processing.
string b = r"""line1
line2""";                             // "line1\nline2"
```

Inside a non-raw `"""…"""`, one or two `"` are literal; three end the string
(escape them as `\"""` if you need three).

## Concatenation

`+` joins strings, producing a fresh owned string:

```sic
string s = "Hello world!";
string more = s + " And more.";       // "Hello world! And more."
string cat  = "foo" + "bar";          // literal + literal → "foobar"
```

(`"abc" + 1` with an integer is still pointer arithmetic, as in C — concatenation
requires a string operand or two string literals.)

## Slicing

`s[lo:hi]` is a **half-open** substring — a no-copy view sharing the parent's
bytes. Indices may be negative (from the end) and either bound may be omitted:

```sic
string s = "Hello world!";
s[6:11];   // "world"
s[-1:];    // "!"      (negative index counts from the end)
s[:5];     // "Hello"
s[:];      // whole string
```

Out-of-range or reversed ranges are clamped (safe), yielding a shorter or empty
string rather than reading out of bounds.

## Offset & indexing

`s + n` drops the first `n` bytes — a cheap view, `s + n` ≡ `s[n:]`:

```sic
"hello" + 1;   // "ello"  (a string view)
"hello" + 5;   // ""      (n == length is allowed)
```

`s[i]` is the **byte** at index `i` (a `char`):

```sic
"hello"[1];    // 'e'
```

Both are bounds-checked: a **literal** with a **constant** offset/index is checked
at *compile time* (`"hello" + 6` and `"hi"[9]` are compile errors), and a runtime
index traps on out-of-range. Assigning `s + n` to a `char*` gives plain pointer
arithmetic into the bytes (`char *p = "abcdef" + 2;` → `p` at `'c'`).

## Comparison

Compare bytes directly with `==` / `!=` — no `strcmp`, no NUL requirement:

```sic
string h = s[6:10];
if (h != "world") return 1;
```

## Search & split

`contains` tests for a substring; a single-character argument is the
character-search case, so there's no separate `strchr`:

```sic
string path = "path/to/file.txt";
path.contains("/");           // true
path.contains("file");        // true
path.contains("zzz");         // false
```

`split(sep)` / `rsplit(sep)` divide the string at the **first** / **last**
occurrence of `sep`, returning a `tuple(before, after)`:

```sic
tuple head_tail = path.split("/");    // ("path", "to/file.txt")   — first "/"
tuple name_ext  = path.rsplit(".");   // ("path/to/file", "txt")   — last "."
string dir  = head_tail[0];
string rest = head_tail[1];
```

When the separator is **absent**, the result is a **one-element** tuple holding
the whole string, so a tuple's `.length` (see
[arrays & tuples](arrays-and-tuples.md#tuples)) distinguishes a real split — it is
`2` when the separator was found, `1` when not. That makes a peel loop natural:

```sic
tuple res;
string tail = path;
do {
    res  = tail.split("/");
    tail = res[0];
} while (res.length > 1);      // stop when no "/" remains → tail == "path"
```

The two parts are **views** into the original string (plain byte offsets, no
copy), valid while it is — the same non-owning slice semantics as `s[lo:hi]`.

## Accessors

| accessor | meaning |
|----------|---------|
| `.length` | number of UTF-8 code points |
| `.size`   | number of bytes |
| `.ptr` / `.str` | a NUL-terminated `char*` (copies only if the view isn't already NUL-terminated) |
| `.dup`    | an owned heap copy (see below) |
| `.utf8`   | the bytes decoded into a `u8char[]` of code points (see [types](types.md#u8char--a-unicode-code-point)) |

```sic
s.length;                    // 12
s.size;                      // 12
printf("%s\n", s.ptr);       // interop with C APIs
```

Interop is explicit — a `string` does not implicitly decay to `char*`; use
`.ptr`.

## `.dup` — force an owned copy

`string s = <char*>` (or a slice) is a **view**, not a copy — cheap, but it
borrows someone else's bytes. `.dup` makes an independent owned copy that outlives
the source:

```sic
string owned = s.dup;        // independent heap copy
```

You rarely need `.dup` explicitly: returning a `string` that views a *local*
buffer copies it automatically (see
[copy-on-escape](memory-and-ownership.md#copy-on-escape)). Reach for `.dup` when
you want to keep a copy past the source's lifetime in some other situation.

## Ownership in one line

Owned strings (from `+`, `.dup`, or an owned literal chain) are reference-counted
and released at scope exit; copies share and retain, slices keep their parent
alive, and returning a string moves it out. You don't call `free`. The details
are in [memory & ownership](memory-and-ownership.md).

Next: [memory & ownership](memory-and-ownership.md).
