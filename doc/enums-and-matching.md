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

### Exhaustiveness

A `match` **must be exhaustive** — cover every variant, or add a `_` catch-all.
A missing variant is a *compile error* (not a runtime surprise):

```sic
match (s) { Circle(r): …; }
// error: non-exhaustive match on `Shape`: missing Square — cover it or add a `_` arm
```

This is the point of `match` over a C `switch`: the compiler proves you handled
every case. Use `_` for "everything else":

```sic
match (m) { A: …; _: …; }        // A explicitly, all other variants via `_`
```

### `match` as an expression

A `match` can also *produce a value* — each arm's value is its trailing expression
(a bare `expr;`, or the last expression of a `{ …; expr }` block). All arms share a
common type, which `auto` infers:

```sic
int area = match (s) {
    Circle(r): r * r * 3;
    Square(w): w * w;
    Tri(t):    t;
};

auto label = match (m) {
    A: "a";
    _: "other";
};
```

An arm may still diverge with `return`/`break` instead of yielding a value.

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

### Strict typing — no accidental `int`/enum mixing

Unlike C, SIC treats a payload-less enum as its own type. A plain `int`, or a
*different* enum, cannot flow into an `enum` slot without an explicit `(enum E)`
cast — this catches the classic C bug of passing the wrong constant:

```sic
enum Color { RED, GREEN, BLUE };
enum Fruit { APPLE, PEAR };
void paint(enum Color c);

paint(1);            // ERROR: `int` passed as `enum Color`
paint(APPLE);        // ERROR: `enum Fruit` passed as `enum Color`
paint((enum Color)1);// ok — explicit cast
paint(BLUE);         // ok

enum Color c = 0;    // ERROR: use `RED`, or `(enum Color)0`
c = 2;               // ERROR (assignment)
```

An enum has **no arithmetic** — its value is an identity, not a number. Cast to
`int` when you mean the number:

```sic
int n = c + 1;       // ERROR: enum has no arithmetic
int n = (int)c + 1;  // ok
c += 1;              // ERROR — write c = (enum Color)((int)c + 1)
```

Going the other way is free: an enum **widens to `int`** implicitly, and you may
compare it to an integer. So indexing, `printf`, and loops read naturally:

```sic
int i = BLUE;              // ok (enum → int)
if (c == 2) { … }          // ok (compare by value)
arr[c];                    // ok
for (enum Color e = RED; (int)e <= (int)BLUE; e = (enum Color)((int)e + 1)) { … }
```

Typedef enums (`typedef enum { LO, HI } Level;`, named or anonymous) are checked
exactly the same way. Tagged enums are already distinct types, so this all falls
out for them too.

### `.str` — the variant name

Any enum value — payload-less **or** tagged — renders as a native `string` naming
its variant, `"EnumName::Variant"`, handy for logging and debugging:

```sic
enum Color { RED, GREEN, BLUE };
enum Status { Ok, Bad(int), Gone };

enum Color c = BLUE;
c.str;                        // "Color::BLUE"   (from the runtime value)
RED.str;                      // "Color::RED"    (a bare constant)
std::Println("{}", c.str);    // Color::BLUE

Status s = Status::Bad(7);
s.str;                        // "Status::Bad"   (tagged enum → just the name)

if (c.str == "Color::BLUE") … // it's an ordinary string
```

An out-of-range value (e.g. `(enum Color)99`) yields `"Color::?"`. This applies to
variables, parameters, function results, and bare constants alike.

### Equality

`==` / `!=` on tagged enums compare the **variant** (the discriminant tag), so
testing a value against a variant works — the two are not compared by address:

```sic
Status s = Status::Ok;
if (s == Status::Ok) …        // true
if (s != Status::Gone) …      // true
```

Payload equality is not implied — use `match` when you need to inspect a payload.

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
