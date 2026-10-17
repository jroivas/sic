# Writing idiomatic SIC — a guide for LLMs converting C or Rust

SIC is C with the sharp edges fixed. **Valid C compiles as-is in a `.sic` file**, so
a literal transliteration "works" — but it is not idiomatic. When converting, use the
SIC forms below. Each pair shows the C-style way (✗) and the SIC way (✓).

Ground rules:

- Locals, arrays and structs are **zero-initialized**. Don't write `= 0` / `memset`
  just to clear them.
- Integer overflow wraps, `x / 0 == 0`, and shifts by any count are defined. Don't add
  guards against C undefined behavior. `unsafe { … }` makes overflow and ÷0 trap.
- `if (x = y)` and a dangling `else` are compile errors: write `if ((x = y))` and use
  braces.
- Enums are strict types. `int` → enum needs a cast; enum → `int` is implicit.
- A `string` does not decay to `char*`. Pass `s.ptr` to C APIs (`printf("%s", s.ptr)`).
- Keep `#include <stdio.h>` / `printf` for plain output, or `import std;` and
  `std::Println("{} {}", a, b)`.

## Types

```c
unsigned int h; long long n; size_t len; unsigned char b; int ok = 1;   /* ✗ */
```
```sic
u32 h; i64 n; usize len; u8 b; bool ok = true;                          // ✓
```

## Heap arrays: `malloc`/`free` → `new T[n]` + `defer del`

```c
int *a = malloc(n * sizeof(int));                                       /* ✗ */
if (!a) return -1;
...
free(a);            /* and again on every early return */
```
```sic
i32 *a = new i32[n] else return -1;   // ✓ zeroed, bounds-checked, NULL → else
defer del a;                          // freed on every exit from the scope
```

Single objects: `Node *p = new Node;` … `del p;` (`del NULL` is a no-op).

## Cleanup that belongs to a type: destructor, not a release function

```c
void tree_free(Node *n) { if (!n) return; tree_free(n->l); tree_free(n->r); free(n); }  /* ✗ */
```
```sic
struct Node {                     // ✓ `del root` frees the whole tree
    Node *l;
    Node *r;
    ~Node() { del l; del r; }
};
```

Constructors work the same way: `Buf() { data = new u8[64]; }` runs at declaration.

## Methods instead of `module_verb(obj, …)` functions

```c
typedef struct { u32 state; } Rng;                                       /* ✗ */
u32 rng_next(Rng *r) { r->state = r->state * 1664525u + 1013904223u; return r->state; }
...  u32 x = rng_next(&g);
```
```sic
struct Rng {                                   // ✓ explicit self pointer, dot call
    u32 state;
    u32 next(Rng *self) { self->state = self->state * 1664525 + 1013904223; return self->state; }
};
... u32 x = g.next();
```

## Strings: `char[]` + `str*` → `string`

```c
char buf[64];                                                            /* ✗ */
strcpy(buf, "hello, "); strcat(buf, name);
if (strcmp(buf, "hello, bob") == 0) ...
size_t n = strlen(buf);
```
```sic
string s = "hello, " + name;                   // ✓ owned, refcounted, freed for you
if (s == "hello, bob") { … }
usize bytes = s.size;                          // .length = code points
string head = s[0:5];                          // slice view, no copy
tuple parts = s.split(", ");                   // ("hello", "bob"); .length 1 if absent
printf("%s\n", s.ptr);                         // C interop through .ptr
string msg = std::Fmt("{} = {}", "x", 42);     // formatting (import std;)
```

## Errors: sentinel values and out-params → `Option` / `Result`

```c
int find(const int *a, int n, int key, int *out_index);  /* ✗ returns -1 */
```
```sic
Option<i32> find(i32 *a, i32 n, i32 key) {                  // ✓
    for (i32 i = 0; i < n; i++) if (a[i] == key) return Option::Some(i);
    return None;
}

i32 idx = find(a, n, 7) else return 1;       // unwrap or bail out (like Rust `?`)

match (parse(text)) {                        // or handle both cases
    Ok(v):  use(v);
    Err(e): printf("bad input: %s\n", e.ptr);
}
```

`Option<T>` and `Result<T, E>` are built in. No declaration needed.

## Tagged data: enum + union + `switch` → tagged enum + `match`

```c
enum Kind { CIRCLE, RECT };                                              /* ✗ */
struct Shape { enum Kind k; union { int r; int w; }; };
switch (s.k) { case CIRCLE: return 3 * s.r * s.r; case RECT: return s.w * s.w; }
```
```sic
enum Shape { Circle(i32), Square(i32) };                           // ✓
i32 area(Shape s) {
    return match (s) {                                             // exhaustive:
        Circle(r): 3 * r * r;                                      // a missing case
        Square(w): w * w;                                          // is a compile error
    };
}
Shape c = Shape::Circle(2);
```

Plain C enums still work. Write `Color c = BLUE;`; an enum value `.str` gives
`"Color::BLUE"`.

## Containers: hand-rolled growth and hashing → `list` / `dict` / `set`

```c
int *v = NULL; size_t len = 0, cap = 0;                                  /* ✗ */
if (len == cap) { cap = cap ? cap * 2 : 8; v = realloc(v, cap * sizeof *v); }
v[len++] = x;
```
```sic
list<i32> v;                     // ✓ growable, owned, freed at scope exit
v.add(x);
i32 first = v[0];
for (i32 x : v.values) { … }

dict<string, i32> count;         // insertion-ordered hash map
count["apple"] += 1;             // missing key reads as 0
for (tuple kv : count) { string k = kv[0]; i32 n = kv[1]; }

set<string> seen;
if (!seen.contains(word)) seen.add(word);
```

Use `new T[n]` rather than `list` for large numeric buffers: `list` elements are boxed.

## Loops and arrays

```c
for (int i = 0; i < (int)(sizeof a / sizeof a[0]); i++) total += a[i];  /* ✗ */
int t = x; x = y; y = t;
#define ROTL(v, k) (((v) << (k)) | ((v) >> (32 - (k))))
```
```sic
for (auto x : a) total += x;     // ✓ range-for (arrays, strings, list.values, enums)
i32 n = a.length;                // element count (.size = bytes)
x <> y;                          // swap
u32 r = v <<< 13;                // rotate left (>>> right)
```

## Several results: out-params → `tuple`

```c
void divmod(int a, int b, int *q, int *r) { *q = a / b; *r = a % b; }   /* ✗ */
```
```sic
tuple divmod(i32 a, i32 b) { return tuple(a / b, a % b); }    // ✓
i32 q, r;
tuple(q, r) = divmod(17, 5);
```

## Callbacks: function pointer + `void *ctx` → lambda / closure

```c
int add_base(int x, void *ctx) { return x + *(int *)ctx; }               /* ✗ */
apply(add_base, &base);
```
```sic
i32 apply(Fn<i32(i32)> f, i32 x) { return f(x); }             // ✓
i32 base = 40;
apply([base](i32 x) => x + base, 2);                          // 42; captures by value
qsort(a, n, sizeof(i32), [](const void *p, const void *q) {   // captureless lambda =
    return *(const i32 *)p - *(const i32 *)q;                 // plain function pointer
});
```

## Cleanup without a type: `goto out` → `defer`

```c
FILE *f = fopen(path, "r"); if (!f) return -1;                           /* ✗ */
if (read_header(f) < 0) { fclose(f); return -1; }
...
fclose(f);
```
```sic
FILE *f = fopen(path.ptr, "r");                               // ✓
f != NULL else return -1;                                     // boolean guard
defer fclose(f);                                              // runs on every exit
if (read_header(f) < 0) return -1;
```

## From Rust

| Rust | SIC |
|---|---|
| `i32 u64 usize f64 bool` | same names |
| `Vec<T>` (growable) | `list<T>`; large numeric buffer: `new T[n]` + `defer del` |
| `HashMap<K,V>` / `HashSet<T>` | `dict<K,V>` / `set<T>` |
| `String` / `&str` | `string` (slices `s[a:b]` are views) |
| `Box<T>` | `new T` + `del`, or a struct destructor owning it |
| `Option<T>` / `Result<T,E>` | same, built in; construct `Option::Some(x)`, `None`, `Result::Ok(v)` |
| `match x { A(v) => …, _ => … }` | `match (x) { A(v): …; _: …; }` |
| `let v = f()?;` | `auto v = f() else return …;` |
| `if let Some(v) = o { … }` | `auto v = o else { … }` or `match` |
| `impl S { fn m(&mut self) }` | method in the struct: `void m(S *self) { … }`, call `s.m()` |
| `Drop` | destructor `~S() { … }` |
| closures `\|x\| x + n` | `[n](i32 x) => x + n`; type `Fn<i32(i32)>` |
| `(a, b)` return | `tuple(a, b)` |
| `x.rotate_left(k)`, `std::mem::swap` | `x <<< k`, `a <> b` |
| `wrapping_add` | plain `+` (SIC wraps); checked: `unsafe { … }` / `overflow { … }` |
| `println!("{} {}", a, b)` | `std::Println("{} {}", a, b)` (`import std;`) |
| a crates.io dependency | a binding crate built with `sic --emit-module`, then `import` it ([Rust crates](rust-crates.md)) |

## Checks: `assert`

```c
#include <assert.h>                                                      /* ✗ */
assert(n > 0);       /* disabled by NDEBUG */
```
```sic
assert(n > 0);                        // ✓ built in, always checked
assert(n > 0, "n must be positive");  // optional message (any string)
```

Repetitive boilerplate can be a `macro_rules` macro (Rust syntax, no `!`):
`macro_rules sq { ($x:expr) => ( $x * $x ); }` then `sq(a + 1)`.

## Checklist before you finish

1. No `malloc`/`free`, `strcpy`/`strcat`/`strlen`/`sprintf`, `realloc`-grown arrays,
   or `goto cleanup` left over.
2. Every early-exit resource has a `defer` or a destructor.
3. Fallible functions return `Option`/`Result`, and callers use `match` or `else`.
4. `switch` over a tag became an exhaustive `match`.
5. Fixed-width types (`i32`, `u64`, `usize`, `bool`) everywhere.
6. Strings go to C only through `.ptr`.
