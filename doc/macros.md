# Macros

SIC has Rust-style declarative macros, `macro_rules`, invoked **without `!`**.
They work on tokens after the C preprocessor and only in `.sic` files (`#define`
keeps working as in C).

```sic
macro_rules square { ($x:expr) => ( $x * $x ); }

macro_rules sum {
    [] => ( 0 );
    [$($x:expr),+ $(,)?] => ( 0 $(+ $x)+ );
}

int nine = square(1 + 2);      // ((1 + 2) * (1 + 2)): no C-macro precedence trap
int six  = sum[1, 2, 3,];      // trailing comma accepted by `$(,)?`
```

## The bracket picks the rules

Each rule's matcher is written with `(…)`, `[…]` or `{…}`. `name<bracket>…` is
an invocation only if the macro has a rule written with that bracket, so the
same name can also be an ordinary function:

```sic
int pick(int a, int b) { return a - b; }
macro_rules pick { [$($x:expr),*] => ( 100 ); }

pick(5, 3);    // 2: `pick` has no `(…)` rules, so this calls the function
pick[5, 3];    // 100: the macro
```

When the bracket fits but **no rule matches**, a function of that name (declared
earlier) is called instead; with no such function it is an error listing the
rules. A macro takes precedence over a function when a rule does match.

A variable or parameter cannot have a macro's name — `name[i]` must never be
ambiguous with indexing.

## Matchers

| Fragment | Matches |
|---|---|
| `$x:expr` | an expression (no top-level comma) |
| `$x:ident` | one identifier |
| `$x:ty` | a type, e.g. `unsigned char`, `list<int>` |
| `$x:literal` | a number, string, character or `true`/`false` (optionally `-n`) |
| `$x:block` | a `{ … }` block |
| `$x:stmt` | one statement |
| `$x:path` | `a::b::c` |
| `$x:tt` | any single token or bracketed group |

Repetition: `$( … ) sep? op` with `*` (zero or more), `+` (one or more) or `?`
(optional); `sep` is an optional separator token such as `,`. Any other token
must match literally. Rules are tried in order; the first that matches the whole
invocation wins.

## Transcribers

`$x` inserts what `$x` matched (an `expr` is inserted parenthesized), `$( … )*`
repeats once per match of the variables inside, and three built-ins exist:

- `$str(…)` — the tokens as a string literal (the source text as written);
- `$file`, `$line` — the invocation's file and line.

## Where a macro can be used

- **Expression**: the expansion becomes one parenthesized expression.
- **Statement**: an invocation followed by `;` (or written with `{…}`) expands to
  statements. As the body of an `if`/`while` it is braced, so every statement
  belongs to it.
- **File scope**: the expansion is a list of declarations (functions, structs,
  globals).

```sic
macro_rules point { [$name:ident { $($f:ident),* }] => ( struct $name { $(int $f;)* }; ); }
point[P { x, y, z }]                      // struct P { int x; int y; int z; };
```

Macros may expand to other macros, including themselves (`count[a b c] =>
1 + count[b c]`); nesting is limited to 128 levels. A macro is visible from its
definition to the end of the file, and may also be defined inside a function.

## Hygiene

A local that a template declares itself is renamed for each expansion, so it can
neither capture nor shadow the caller's variables:

```sic
macro_rules swap_vals { {$a:ident, $b:ident} => { int tmp = $a; $a = $b; $b = tmp; } }

int tmp = 5, a = 1, b = 2;
swap_vals{a, b}          // the template's `tmp` is separate: the caller's stays 5
```

Names that come from the invocation (`$a`, `$b`) are never renamed.

## `assert`

Every SIC file has a built-in `assert` macro:

```sic
assert(x > 0);
assert(x > 0, "x must be positive");   // the message may be any `string`
```

On failure it prints `file:line: assertion failed: x > 0: x must be positive`
to stderr and aborts. Like Rust's `assert!` it is always checked (`NDEBUG` does
not disable it). A function, variable or macro of your own named `assert`
replaces it, and C's `<assert.h>` `assert(…)` still applies where included (the
preprocessor expands it first).

## `unreachable`

`unreachable` marks a point control never reaches — like Rust's `unreachable!()`.
Three forms, all statements:

```sic
i32 sign(i32 x)
{
    if (x > 0) return 1;
    else if (x < 0) return -1;
    else return 0;
    unreachable;                        // also `unreachable();`
}

if (state > LAST) unreachable("bad state");
```

If it is reached after all, it prints `file:line: unreachable code reached: bad
state` to stderr and aborts. In a SIC file, `__builtin_unreachable()` (and C23's
`unreachable()` from `<stddef.h>`) means the same: checked, not undefined.

Control ends at an `unreachable`, as at `exit(…)` and `abort()`: a guard's `else`
may end with one (`int v = find(k) else { exit(1); };`), and the code after it is
unreachable. The [unreachable-code warning](getting-started.md) reports such code;
an `unreachable` itself is never reported.

## Errors

An error inside an expansion is reported at the invocation, with a note:

```
x.sic:3:10: error: expected an expression after `+`, found `)`
  note: in expansion of macro `m`: `m[1]` expands to `( 1 + )`
```

Not yet supported: exporting macros from a module, `$x:pat`, and paths such as
`ns::m[…]` to name a macro.

Next: [atomics](atomics.md).
