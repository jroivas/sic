# Types

## Fixed-width integers

SIC adds Rust-style, explicitly-sized integer aliases (reserved names in `.sic`
units):

| signed | unsigned | width |
|--------|----------|-------|
| `i8`   | `u8`     | 8     |
| `i16`  | `u16`    | 16    |
| `i32`  | `u32`    | 32    |
| `i64`  | `u64`    | 64    |
| `i128` | `u128`   | 128   |
| `isize`| `usize`  | machine word (32/64) |

```sic
i32 a = 12345;
i64 b = 567890;
u128 big = 0;  big = big - 1;   // all-ones, wraps (no UB)
```

`isize`/`usize` are the pointer-width integers — use them for sizes and offsets,
not for portable values. The C spellings (`int`, `short`, `long`, `unsigned …`)
also work with their usual platform widths; `char` is a plain 8-bit signed C
`char`.

> Overflow on any of these **wraps** by default and is fully defined — see
> [defined behavior](language-basics.md#integer-overflow--wraps-by-default).

## `bigint` — arbitrary precision

`bigint` is a built-in arbitrary-precision integer backed by a self-contained
runtime (no external library). It grows as needed and is used like any integer:

```sic
bigint c = 123456789123456789001234567890;   // larger than u64
i64 b = 567890;
bigint d = 12345 + b;    // promotes from ints
d += c;

// Explicit conversions:
char *s = d.str;         // decimal string (freed at scope exit)
i64   n = d.int;         // low 64 bits as a fixed integer
```

Supports `+ - *`, division/remainder, all comparisons, and bit operations.
Factorials, cryptographic-size values, etc. stay exact:

```sic
bigint f = 1;
for (int i = 1; i <= 25; i++) f = f * i;
// f.str == "15511210043330985984000000"
```

`.str` yields a fresh decimal `char*` that is freed automatically at scope exit —
don't `free` it yourself. (Assigning it into a `string` copies it out safely; see
[memory & ownership](memory-and-ownership.md).)

## `fixed` — exact decimal / rational

`fixed<I,F>` is an exact fixed-point number: an arbitrary-precision mantissa
scaled by a power of ten, so arithmetic is **exact and never routed through a
float**. `I` is the number of integral digits, `F` the fractional digits:

```sic
fixed<10,2> price = 19.99;
fixed<10,2> total = price * 3;   // exactly 59.97
// total.str == "59.97"
```

- Operations harmonize scales automatically; the result type takes the larger
  integral and fractional precision:

  ```sic
  fixed<4,2> p = 12.50;
  fixed<4,3> q = 2.125;
  // (p * q).str == "26.56250"   (fraction scale 2 + 3 = 5)
  // (p - q).str == "10.375"
  ```

- Plain `fixed` (unspecified precision) is an exact rational that reduces — so
  `1/3` stays exact and `(1/3) * 3 == 1` exactly:

  ```sic
  fixed third = 1;
  third = third / 3;
  (third * 3).int;    // == 1
  ```

- Exactness holds past `f64` precision:

  ```sic
  fixed<10,9> big = 1234567890.123456789;
  fixed<10,9> eps = 0.000000001;
  // (big + eps).str == "1234567890.123456790"
  ```

Accessors: `.str` (decimal string, rounded to the display precision `F`), `.int`
(truncated toward zero to a 64-bit integer). Always specify the precision
(`fixed<I,F>`) when you can — a bare `fixed` may fall back to the slower rational
path. Fixed overflow raises an exception (catchable with `overflow`), unlike
integer wrap.

## Floating point

| type | width | alias |
|------|-------|-------|
| `f32`  | 32  | `float`  |
| `f64`  | 64  | `double` |
| `f80`  | 80  | — (x86 extended) |
| `f128` | 128 | — |

```sic
f64 x = 3.5;
f80 hp = 1.5;
```

Use `fixed` when you need exact decimal results (money, accounting); use floats
for approximate scientific math.

## `bool`

`bool` is a distinct boolean type; `true` and `false` are `bool`-typed literals
(not integers):

```sic
bool t = true;
bool f = false;
if (t && !f) { … }
```

A `bool` converts to `int` only where an integer is actually needed (`(int)t` is
`1`), and an integer converts to `bool` implicitly in a boolean context (`if (n)`
tests `n != 0`). Because `true`/`false` keep the `bool` type, they carry their
type through [RTTI](rtti-and-dynamic.md) — e.g. `std.Print("{}", true)` prints
`true`, not `1`.

## `u8char` — a Unicode code point

`char` stays a plain C byte (see above). For Unicode text, `u8char` is a single
Unicode scalar value, stored in 32 bits. It behaves like its code point in
comparisons and arithmetic:

```sic
u8char a = 65;        // 'A'
(int)a;               // 65
if (a == 65) { … }
```

`sizeof(u8char)` is `4` (its storage), a compile-time constant like any
`sizeof`. But `.size` gives the value's **UTF-8 encoded length**, `1`–`4`
depending on the character (a runtime property):

```sic
u8char a = 0x41;    a.size;   // 1  ('A')
u8char e = 0x00E9;  e.size;   // 2  ('é')
u8char u = 0x20AC;  u.size;   // 3  ('€')
u8char m = 0x1F600; m.size;   // 4  ('😀')
```

### `string.utf8` — decode to code points

A `string` is stored as UTF-8 bytes (`.size` bytes, `.length` code points). Its
`.utf8` accessor decodes those bytes into a `u8char[]` you can index and iterate:

```sic
string s = "A€😀";
auto cps = s.utf8;          // a u8char[]
cps.length;                 // 3   (code points, == s.length)
cps.size;                   // 8   (total UTF-8 bytes, == s.size)
(int)cps[0];                // 0x41
cps[2].size;                // 4   (the emoji is 4 bytes)

usize bytes = 0;
for (usize i = 0; i < cps.length; i++)
    bytes = bytes + cps[i].size;   // == cps.size
```

`cps.length` is the code-point count and `cps.size` the byte total; `cps[i]` is a
`u8char`. The decoded buffer is freed automatically at scope exit. Use `auto` to
bind the result (its type is a compiler-internal slice).

Next: [strings](strings.md).
