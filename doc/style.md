# SIC style

The default layout of SIC code — what `sic-fmt` produces, and what the standard
library, the docs and the tests follow. It is K&R style: a function's body opens on
its own line, every other block on the same line.

## Indentation and lines

- 4 spaces per level, never tabs. LF line endings, no trailing whitespace, one
  newline at the end of the file.
- Prefer lines of at most **100** characters. It is a preference, not a limit: a
  longer line stays when breaking it would read worse (a long string, a table-like
  row, a URL in a comment).
- At most one blank line in a row; one blank line between top-level items.

## Braces

A **function** (also a method, constructor or destructor) opens its body on the
next line; **everything else** opens on the same line — namespaces, structs,
unions, enums, `if`/`for`/`while`/`do`/`switch`, `match`, `unsafe`/`defer` blocks
and lambdas:

```sic
namespace file {
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
  `int sq(int x) { return x * x; }`, `if (n == 0) { return 1; }`.
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
- The `*` of a pointer binds to the name: `char *p`, `Buffer *self`, `u8 *buf`.
- A space after each comma and after the `;` of a `for` header; none just inside
  parentheses or brackets: `f(a, b)`, `xs[i]`, `for (int i = 0; i < n; i++)`.
- Generic arguments without inner spaces at the brackets: `list<i32>`,
  `dict<string, i64>`, `m::HashMap<i64, string>::new()`.

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

## Wrapping long lines

When a line is broken, break at the outermost level first:

- **Calls and parameter lists:** one argument per line, indented one level, the
  closing `)` back on its own line.
- **Binary expressions:** before the operator, the continuation indented one level.
- **Guards** (`x = f() else …`): a guard that does not fit becomes the block form,
  `else {` … `}`.

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
- Trailing comments on consecutive lines are aligned to one column, as in the
  docs:

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
- the bodies of `macro_rules` macros, apart from their indentation.

Code that does not parse is left untouched.
