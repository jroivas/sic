# Language basics & defined behavior

SIC keeps C's syntax and semantics but removes undefined behavior and tightens a
few error-prone constructs. Everything on this page is C-compatible source that
behaves *predictably* where C would not.

## Zero-initialization

Every variable with no explicit initializer starts as zero:

```sic
int main() {
    int a;          // 0
    double b;       // 0.0
    char *p;        // NULL
    int arr[4];     // all 0
    // structs are zeroed like memset(&s, 0, sizeof s)
    if (a == 0 && b == 0.0 && p == 0) return 0;
    return 1;
}
```

There are no uninitialized reads.

## Integer overflow — wraps by default

Signed and unsigned overflow **wrap around**; they are not undefined:

```sic
u8 x = 255; x = x + 1;   // x == 0
i8 y = 127; y = y + 1;   // y == -128
```

### `unsafe` — trap instead of wrapping

Inside an `unsafe` block, an overflowing (or divide-by-zero) operation raises a
runtime exception that terminates the program instead of wrapping:

```sic
unsafe {
    int a = INT_MAX;
    a++;              // traps — program aborts
}
```

### `overflow { ... }` — catch it

The `overflow` guard evaluates a block and yields `0` on success or `1` if an
overflow was detected. On overflow the offending operation and everything after
it in the block are **not committed**:

```sic
int a = INT_MAX;
int b = 0;
int c = overflow {
    b = 1;      // runs
    a += 10;    // overflows → stops here
    b = 2;      // not executed
};
// a is still INT_MAX, b == 1, c == 1
```

`overflow` works with or without `unsafe`; using it *without* `unsafe` is the
idiomatic way to detect overflow while keeping the default wrap semantics
elsewhere. `divide_by_zero { ... }` and `exception { ... }` are the analogous
guards for those traps.

## Divide by zero → 0

Outside `unsafe`, integer division or remainder by zero yields `0`:

```sic
int a = 10, b = 0;
// a / b == 0 and a % b == 0
```

Inside `unsafe` it traps (catchable with `divide_by_zero { ... }`).

## Shifts and rotates

Shift results are fully specified:

- `<<` fills with zero.
- `>>` fills with zero for unsigned operands, with the sign bit for signed.
- A shift count `>=` the width yields `0` (or all sign bits for a signed `>>`).
- A zero or negative count leaves the value unchanged.

```sic
unsigned int a = 0x12345678u;
a << 100;   // 0
a << -1;    // 0x12345678 (unchanged)
int b = -88888888;
b >> 32;    // 0xffffffff  (sign-filled)
```

SIC also adds **rotate** operators `<<<` and `>>>` — bits shifted out one end
re-enter the other:

```sic
unsigned int x = 0x12345678u;
x <<< 8;   // 0x34567812
x >>> 8;   // 0x78123456
x <<< 32;  // 0x12345678  (full-width rotate is the identity)
```

## Swap — `<>`

`a <> b` exchanges two same-typed lvalues (scalars, pointers, array elements,
whole structs):

```sic
int a = 3, b = 7;
a <> b;              // a == 7, b == 3

int arr[3] = { 10, 20, 30 };
arr[0] <> arr[2];    // { 30, 20, 10 }
```

The operands must have the same type; `i64 <> i32` is a compile error. Cast
explicitly if you mean it: `(i32)a <> b`.

## Assignment inside a condition

A bare assignment used directly as a truth value is a common typo (`if (x = y)`
instead of `==`). SIC rejects it; wrap it in an extra pair of parentheses to say
you mean it:

```sic
if (x = y)  { … }     // error: ambiguous with `==`
if ((x = y)) { … }    // ok — assign, then test the result
while ((c = getc(in)) != EOF) { … }   // the common, correct form
```

## Dangling `else`

An `else` attached to a nested `if` without braces is ambiguous and rejected —
add braces to make the association explicit:

```sic
if (a)
    if (b) return 1;
    else return 2;      // error: ambiguous dangling `else`

if (a) {
    if (b) return 1;
} else return 2;        // ok
```

## `switch` — no accidental fallthrough

Every non-empty `case` must end with an explicit `break` or `fallthrough`;
falling off the end of a case body is a compile error. This makes the common
missing-`break` bug impossible:

```sic
switch (x) {
    case 1:
        r = 111;
        break;
    case 6: fallthrough;   // deliberate fallthrough
    case 7: fallthrough;
    case 8:
        r = 678;
        break;
    default:
        r = 0;
        break;
}
```

No code may appear between a `break`/`fallthrough` and the next `case`.

## Other tightenings

- `char test[];` (empty-bracket array) is not valid.
- **Struct field reordering:** the compiler may reorder struct fields
  largest-first to shrink padding (offsets by name are unaffected). Opt out with
  `__attribute__((__packed__))` or `__attribute__((__order__))`. C layout is
  never changed for C units.

Next: [types](types.md).
