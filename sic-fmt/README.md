# sic-fmt — the SIC code formatter

`sic-fmt` lays SIC source out in the [default style](../doc/style.md), the way
`rustfmt` does for Rust. It is written in SIC (`src/main.sic`) and built by the
top-level `build.sh`, or here with `make` (`make test` runs its tests).

```sh
sic-fmt src/main.sic          # format a file in place
sic-fmt src/                  # every .sic file below a directory
sic-fmt < in.sic > out.sic    # standard input to standard output (also `-`)
sic-fmt --check src/          # write nothing: print the changes, exit 1 if any
```

| Option | |
|---|---|
| `--check` | write nothing; print what would change (`Diff in FILE at line N:` then `-`/`+` lines) and exit 1 if anything would |
| `--emit stdout` | print the formatted files instead of writing them |
| `-l`, `--files-with-diff` | print the name of each file that changes |
| `--config KEY=VAL[,…]` | set options, over the config file |
| `--config-path FILE` | read options from FILE instead of the nearest `sic-fmt.toml` |
| `--print-config` | print the options in effect |
| `-v` / `-q` | name each file / print nothing but errors |

Directories are searched for `.sic` files, skipping hidden directories and `target`.

## Options

`sic-fmt` reads the nearest `sic-fmt.toml` (or `.sic-fmt.toml`) in the file's
directory or above it — `key = value` lines, `#` comments:

```toml
max_width = 100     # the preferred line width
tab_spaces = 4      # columns per indentation level
hard_tabs = false   # indent with tabs
```

`max_width` is a preference, not a limit. A longer line is broken only where
that makes it fit: a one-line body expands, then the argument list or initializer
that ends the line goes one element per line. A line that cannot be made to fit
that way — a long condition, a long string — is left as written.

## What it changes, and what it does not

It changes only whitespace and line breaks: it never adds, removes or reorders a
token, so the code means exactly what it did. Before writing a file it lexes the
result and compares it with the source token by token; if they differ (a bug), it
reports an internal error and leaves the file alone. It also leaves alone, as
written:

- string literals, including `"""…"""` and `r"""…"""`;
- preprocessor lines, and the order of `#include`s and `import`s;
- braces — a braceless `if` stays braceless;
- `macro_rules` definitions (re-indented as a whole);
- anything between `// sic-fmt: off` and `// sic-fmt: on` (to the end of the
  file without an `on`).

The line breaks inside a statement are the author's: `sic-fmt` re-indents a
statement's continuation lines but does not join them (only a line over
`max_width` is broken further).

Code whose brackets do not balance (for example, when they balance only across
`#if` branches) or that does not lex is reported and left untouched.

## How it works

`sic-fmt` works on tokens, not a syntax tree, so it formats code that is still
being written and needs no knowledge of what a name refers to. Each token's role
comes from its neighbours: whether a `{` opens a function (its own line) or any
other block, whether `<` opens generic arguments or compares, whether `*` is a
declarator, a dereference or a product. Where the neighbours cannot tell — `T *p`
against `a * b` — the source's own spacing decides, so a second run never
changes the result.

## Tests

`./test.sh` (or `make test`) checks that each `tests/NAME.sic` formats to
`tests/NAME.out` and that output to itself; that each `tests/NAME.err-input` is
refused with the message in `tests/NAME.err`; the command line; and that every
SIC source in this repository formats without error and stably.
