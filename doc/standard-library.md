# The standard library

`import std;` brings in the SIC standard library. It is an ordinary
[module](modules.md) — plain SIC source shipped with the compiler and installed
in the sysroot, so no flags are needed — and it demonstrates the language's own
features (RTTI, `any`, `va_array`, ownership) rather than being compiler magic.

Today `std` provides formatted output: `Fmt`, `Print`, `Println`.

## Formatting

All three use `{}` placeholders, each substituted by the next argument formatted
according to its runtime type. `{{` and `}}` are literal braces.

```sic
import std;

int main() {
    string who   = "World";
    fixed  price = 19.99;

    std.Println("Hello, {}!", who);                 // Hello, World!
    std.Println("{} items at {} each", 3, price);   // 3 items at 19.99… each
    string s = std.Fmt("{{}} then {}", 42);         // "{} then 42"
    return 0;
}
```

| function | signature | effect |
|----------|-----------|--------|
| `Fmt`     | `Fmt(string fmt, …) -> string`  | build a formatted string |
| `Print`   | `Print(string fmt, …)`          | format and write to stdout |
| `Println` | `Println(string fmt, …)`        | `Print` plus a trailing newline |

The trailing arguments are collected as a [`va_array`](rtti-and-dynamic.md), so
you pass as many as the format needs. To print a single value with no formatting,
use `"{}"`:

```sic
std.Println("{}", value);
```

## What it can format

Any type carries enough runtime type information for `std` to render it:

- `string`, `char*` — the text
- `int` / `uint` of any width, `bool` (`true`/`false`)
- `f32`/`f64`/`f80`
- `bigint` — full decimal
- `fixed` — exact decimal
- pointers — address

This works because `std` dispatches on each argument's type with
[`match (type(x))`](rtti-and-dynamic.md#match-typex--dispatch-by-kind) — the same
mechanism available to your own code.

## How it's written

The whole library is about 130 lines of SIC (`siccomp/lib/std/std.sic`). Its core
is a `match (type(x))` that turns one boxed argument into a `string`, borrowing
string/`char*` arguments (no copy) and formatting the rest into a local buffer
(copied out on return automatically — see
[copy-on-escape](memory-and-ownership.md#copy-on-escape)):

```sic
static string arg_str(any x) {
    match (type(x)) {
        string: return (string)x;                    // borrow — no content copy
        cstr:   { string s = (char *)x; return s; }
        bigint: return ((bigint)x).str;
        fixed:  return ((fixed)x).str;
        bool:   { if ((bool)x) return "true"; return "false"; }
        int:  { char b[32]; snprintf(b, 32, "%lld", (long long)(i64)x); return b; }
        // … uint, float, ptr …
        _:      return "<?>";
    }
}
```

`Print`/`Println` are one-liners that forward their `va_array` to `Fmt`. Reading
`std.sic` is a good way to see the language used idiomatically.

---

That's the tour. Back to the [index](README.md).
