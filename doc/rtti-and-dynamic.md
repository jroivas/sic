# RTTI & dynamic values

SIC carries runtime type information and offers a boxed dynamic value (`any`) and
Python-style varargs (`va_array`). Together they let you write type-directed code
— like a formatter — without hand-written type tags.

## `type(x)` / `typeid(x)`

`type(x)` (alias `typeid(x)`) yields a **type value** describing the static (or,
for an `any`, runtime) type of `x`. The operand isn't evaluated — only its type
is used, like `sizeof`. A bare type name in value position is also a type value:

```sic
type(x)          // the type of expression x
typeid(char*)    // the type value for a type
i32              // a bare type name is its own type value
```

Accessors on a type value:

| accessor | meaning |
|----------|---------|
| `.str` / `.name` | canonical spelling, e.g. `"i32"`, `"string"`, `"fixed<10,4>"` |
| `.size` | size in bytes |
| `.kind` | coarse classification (see below) |
| `.id`   | stable 64-bit hash of the canonical name (equal across compilation units) |

```sic
int x = 5;
type(x).str;    // "i32"
type(x).size;   // 4
type(x).kind;   // 2  (signed int)
```

### Comparing types

`type(a) == type(b)` (or `type(x) == SomeType`) compares by `.id`, so it is an
**exact** type test — `type(v) == i32` is false for an `i64`:

```sic
if (type(x) == i32) …          // exactly i32
if (type(s) == string) …
```

### Kinds

`.kind` is a coarse category shared by related types (all signed-int widths share
one kind, etc.). The categories, in order, are:

`void, bool, int, uint, f32, f64, f80, ptr, cstr, string, fixed, array, struct,
union, enum, tuple, bigint, type`.

You rarely compare `.kind` by number — use [`match (type(x))`](#match-typex--dispatch-by-kind).

## `any` — a boxed dynamic value

`any` is a 16-byte box `{ type, value }` holding a value of any type together with
its runtime type. Box implicitly or with a cast; read the dynamic type with
`type()`; recover the value by casting back:

```sic
any a = 42;                    // implicit box
any b = (any)3.5;              // explicit box
string s = "hi"; any c = s;

type(a);                       // dynamic: i32
(int)a;                        // 42     (downcast)
(double)b;                     // 3.5
(string)c;                     // borrows the boxed string
```

`type(x)` on an `any` is **dynamic** — it reads the boxed type, not `any` itself.

## `va_array` — variadic arguments

A trailing `va_array` parameter collects the remaining call arguments (each boxed
as an `any`), Python-style. Iterate it like an array:

```sic
int sum_ints(va_array args) {
    int acc = 0;
    for (int i = 0; i < args.length; i++) {
        any e = args[i];
        if (type(e) == i32) acc += (int)e;
    }
    return acc;
}

sum_ints(10, "skip", 20, 3.5, 30);   // 60  (non-ints ignored)
```

`.length` is the argument count and `args[i]` is the i-th `any`. A function may
take fixed parameters before the `va_array`:

```sic
string Fmt(string fmt, va_array args) { … }
```

### Forwarding

Passing a `va_array` value as the sole trailing argument **forwards** it (it is
not re-boxed as one element) — like `f(*args)` in Python — so one varargs
function can delegate to another:

```sic
int Println(string fmt, va_array args) {
    return Print(fmt, args);   // `args` passes straight through to Print
}
```

## `match (type(x))` — dispatch by kind

Match a value's runtime type by category. An arm pattern is a type name or a kind
category; it matches when `type(x).kind` falls in that category — so `int`
catches every signed-int width and `float` every float. No hand-written kind
table is involved; the compiler owns the vocabulary.

```sic
static string describe(any x) {
    match (type(x)) {
        string: return "text";
        int:    return "signed";     // i8..i64, char
        uint:   return "unsigned";   // u8..u64
        float:  return "real";       // f32 | f64 | f80
        bool:   return "flag";
        bigint: return "bignum";
        fixed:  return "decimal";
        ptr:    return "pointer";
        cstr:   return "c-string";
        _:      return "other";
    }
}
```

Category patterns: `void, bool, int, uint, f32/f64/f80, float (any float), ptr,
cstr, string, fixed, array, struct, union, enum, tuple, bigint, type`. When you
need an *exact* type (distinguish `i32` from `i64`), use `type(x) == i64`
instead.

This is exactly how the standard library formats a value of any type — see
[the standard library](standard-library.md).

Next: [arrays & tuples](arrays-and-tuples.md).
