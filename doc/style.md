# SIC style

The default layout of SIC code — what [`sic-fmt`](../sic-fmt/README.md) produces
(`sic-fmt file.sic`, or `sic-fmt --check dir/` to only report). It is K&R style: a
function's or namespace's body opens on its own line, every other block on the
same line.

## Indentation and lines

- 4 spaces per level, never tabs. LF line endings, no trailing whitespace, one
  newline at the end of the file.
- Prefer lines of at most **100** characters. It is a preference, not a limit: a
  longer line stays when breaking it would read worse (a long string, a table-like
  row, a URL in a comment) — see [Wrapping long lines](#wrapping-long-lines).
- Blank lines are the author's: kept where they are, at most one in a row, never
  right after a `{` or before a `}`.

## Braces

A **function** (also a method, constructor or destructor) and a **namespace** —
the blocks that enclose larger stretches of code — open their body on the next
line; **everything else** opens on the same line: structs, unions, enums,
`if`/`for`/`while`/`do`/`switch`, `match`, `unsafe`/`defer` blocks and lambdas:

```sic
namespace file
{
    struct File {
        int fd;
        string name;

        ~File() { close(fd); }

        i64 size(File *self)
        {
            struct stat sb;
            if (fstat(self->fd, &sb) != 0)
                return -1;
            return sb.st_size;
        }
    };

    Status Open(string name, OpenMode mode)
    {
        match (mode) {
            Read: flags = O_RDONLY;
            Write: flags = O_WRONLY | O_CREAT | O_TRUNC;
        }
        do {
            fd = open(name.ptr, flags);
        } while (fd < 0 && errno == EINTR);
        if (fd < 0) {
            return Status::Error(errno);
        } else {
            return Status::Opened(fd);
        }
    }
}
```

- `} else {`, `} else if (…) {` and `} while (…);` follow the closing brace on its
  line.
- **One-line bodies** stay on one line when they fit: `~File() { close(fd); }`,
  `int sq(int x) { return x * x; }`, `if (n == 0) { return 1; }`. A body that does
  not fit opens up into the block form. (A block written over several lines is
  not joined into one.)
- **Braces may be omitted** around a single-statement `if`/`else`/`for`/`while`
  body, on the same line (`if (x < 0) return -1;`) or the next, indented. The
  exception is the dangling `else`: an `if` without braces whose body is itself an
  `if` with an `else` needs braces (SIC rejects the ambiguous form anyway).

```sic
if (a)
    if (b) f();
    else g();          // ✗ a dangling else — a compile error

if (a) {
    if (b) f();
    else g();          // ✓
}
```

## Spacing

- A space after the keywords `if`, `for`, `while`, `switch`, `match`, `return`,
  `defer` and `del`; none between a function name and its `(` (`f(x)`,
  `sizeof(T)`).
- Spaces around binary and assignment operators (`a + b`, `x <<= 2`, `x <> y`,
  `v <<< 13`), around `?`/`:` of a conditional, and around `=>` of a lambda; none
  after unary operators (`-x`, `!ok`, `*p`, `&v`) or around `::`, `.`, `->`.
- The `*` of a pointer binds to the name, everywhere: `char *p`, `Buffer *self`,
  `char *a, b;`, `(u8 *)p`, and a return type: `char *name(i32 n)`.
- A space after each comma and after the `;` of a `for` header; none just inside
  parentheses or brackets: `f(a, b)`, `xs[i]`, `for (int i = 0; i < n; i++)`.
- Generic arguments without inner spaces at the brackets: `list<i32>`,
  `dict<string, i64>`, `m::HashMap<i64, string>::new()`, `fixed<10, 2>`.
- A cast is tight: `(char *)p`, `(i32)(u8)c`. Slices are tight at the `:`, the
  bounds spaced as any expression: `s[0:5]`, `s[i:i + 1]`, `s[1:]`.
- Brace initializers and one-line blocks have a space inside the braces:
  `{ 1, 2, 3 }`, `{ return x; }`; empty ones none: `{}`.
- Named arguments are spaced like assignments: `std::Println("{}", x, target = 2)`.
- `o?.field` and `a ?: b` keep the `?` with its partner; a lambda's return type
  is spaced: `[](i32 x) -> i32 { … }`.

## `match` and `switch`

One arm per line, `Pattern: statement;`, indented one level inside the braces. A
longer arm body is a block (`Pattern: { … }`). Arms are not column-aligned — an
added arm then changes only its own line:

```sic
i32 area(Shape s)
{
    return match (s) {
        Circle(r): 3 * r * r;
        Square(w): w * w;
        _: 0;
    };
}
```

`case` labels of a `switch` are indented one level; their statements one more.
A short case may stay on its label's line: `case 1: x = 2; break;`.

## Continuation lines

Where a statement goes on to another line, the line breaks are the author's; the
later lines are indented **one level per bracket left open from an earlier line**,
or one level when no bracket is open (a continued expression). A line that starts
by closing brackets goes back to their level. Break a long expression before its
operator:

```sic
i32 total = compute(first,
    second);
bool ok = header.valid
    && header.size <= limit;
```

A braceless body is one level in from its `if`/`for`/`while`/`else`; an `else`
lines up with its `if`.

## Wrapping long lines

A line over the width is broken where that makes it fit, as rustfmt does; a line
that cannot be made to fit that way stays as written:

- **A one-line body** opens into the block form first.
- **Calls, parameter lists and initializers** that end the line go one element
  per line, indented one level, the closing bracket back on its own line.
- A list that is an operand in the middle of an expression (`a || f(x, y)`) is not
  broken; break such a line yourself, before an operator.

```sic
std::Println(
    "{} items of {} at {} each",
    count,
    name,
    price
);
bool ok = header.valid
    && header.size <= limit
    && checksum(body) == header.sum;
```

## Comments

- `//` followed by one space. Doc comments go on the line(s) above what they
  describe.
- Trailing comments on consecutive lines that are aligned stay aligned (to the
  longest line), as in the docs; a trailing comment on its own keeps its gap:

```sic
x <> y;            // swap
u32 r = v <<< 13;  // rotate left
```

## Left as written

The formatter changes only whitespace and line breaks; it never adds or removes a
token, so it never changes what code means. In particular it leaves alone:

- string literals, including `"""…"""` and raw strings;
- preprocessor lines (`#include`, `#define`, …) and the order of includes and
  imports;
- braces themselves (it does not add braces to a braceless `if`, or remove any);
- `macro_rules` definitions, apart from their indentation;
- everything between a `// sic-fmt: off` comment and a `// sic-fmt: on` one.

Code whose brackets do not balance, or that does not lex, is reported and left
untouched.
