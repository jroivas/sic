# Enums & pattern matching

## Tagged enums

SIC enums are Rust-style tagged unions: each variant has a name and may carry a
typed payload (written after the name in parentheses):

```sic
enum Shape { Circle(int), Square(int) };

int area(Shape s) {
    match (s) {
        Circle(r): return r * r * 3;
        Square(w): return w * w;
    }
}

Shape c = Shape::Circle(2);   // construct with Enum::Variant(payload)
```

A `match` over an enum handles each variant; a payload arm binds the inner value
(`Circle(r)` binds `r`). An arm body is a single statement or a `{ … }` block:

```sic
match (result) {
    Ok(v):  return v;
    Err(m): {
        printf("error: %s\n", m.ptr);
        return -1;
    }
}
```

## Generics

Enums can be generic over their payload types and are monomorphized per
instantiation:

```sic
enum Option<T> { Some(T), None };
enum Result<T, E> { Ok(T), Err(E) };

Option<int>          a = Option::Some(42);
Option<int>          b = None;                 // None infers its type from the target
Result<int, string>  r = Result::Ok(7);
Result<int, string>  e = Result::Err("boom");

match (a) { Some(x): use(x); None: … }
match (e) { Ok(v): … ; Err(m): printf("%s\n", m.ptr); }
```

`Option` and `Result` are **built in** — you can use them without declaring them.
`Some`/`None`/`Ok`/`Err` resolve to the right instantiation from the target type,
so `Option<int> b = None;` and `Result::Ok(7)` just work.

## Old-C-style enums

Plain C enums still work, and a variant may carry a payload while keeping an
integer discriminant. Unwrap a payload with `Enum::Variant(value)` — best used in
an `if`-binding so a mismatch is handled instead of trapping:

```sic
enum E { NONE, TAG(int) };

E c = E::TAG(42);
if (int cv = E::TAG(c)) {     // binds cv only if c is a TAG
    printf("%d\n", cv);       // 42
}
```

## Ergonomics — no `.unwrap()`

SIC deliberately has no bare `.unwrap()`. Instead:

### `?:` — value or default

The Elvis operator yields the present payload, or the right-hand default when the
value is absent/none/error:

```sic
Option<int> o = None;
int v = o ?: 8;               // 8   (o was None)

Option<int> p = Option::Some(5);
int w = p ?: 99;              // 5   (payload)
```

### `else` guard — bind or diverge

`auto x = expr else <stmt>;` binds the present payload (of an `Option`/`Result`,
or a non-null pointer) into the current scope; if the value is absent, the `else`
branch runs and **must diverge** (`return`/`break`/…):

```sic
int get(Option<int> o) {
    auto v = o else return -1;   // bind v, or return -1 on None
    return v;
}
```

There's also a boolean form — `cond else <stmt>;` is `if (!cond) <stmt>` (the
`else` may fall through here):

```sic
x > 0 else return EINVAL;
```

### `?.` — null-safe field access

`base?.field` yields the field when `base` is a non-null pointer (or a present
`Option`/`Result`), otherwise a zero value of the field type — so it chains and
pairs with `?:`:

```sic
struct Node { int value; struct Node *next; };
int v = node?.next?.value ?: -1;   // 0-propagates through nulls, then -1
```

## `switch`

Traditional `switch`/`case` is available for integer dispatch, with SIC's
mandatory `break`/`fallthrough` — see
[language basics](language-basics.md#switch--no-accidental-fallthrough). For
matching a value's *runtime type*, see
[`match (type(x))`](rtti-and-dynamic.md#match-typex--dispatch-by-kind).

Next: [RTTI & dynamic values](rtti-and-dynamic.md).
