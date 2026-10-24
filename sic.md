# SIC - Slightly Improved C specification

Slightly Improved C is a programming language that borrows a lot from C,
but is not afraid to introduce breaking changes in order to improve it.

**STATUS** Most of the features described here are implemented in the current
compiler (Rust front end, Cranelift back end). They are active for SIC-mode
sources (`.sic` files); the same compiler also builds ordinary C (it compiles real
C codebases such as SQLite and QEMU). A few items remain partial or planned, noted
inline where relevant: compile-time enforced error handling (§"Errors and exceptions"), and a cross-module generic
template whose body calls other module functions; calling a method through `?.`,
and swapping through a cast.

## Limit undefined behavior

One of C's optimization strategies is "undefined behavior": cases where the
compiler may do whatever it wants.

We remove that freedom and specify what happens in each case.

The reason is to avoid hard-to-debug undefined behavior. Our thesis is that the
compiler can produce good enough code even with these rules, while saving the
human time such bugs cost.

### Initialized variables

All variables are initialized to 0 (or logically similar).
This avoids problems with uninitialized variables.

- Integral values to 0
- Floating and fixed point to 0.0
- Pointers to NULL
- Strings to empty string
- Structures to memset(struct, 0, sizeof(struct))

Example:

    int main()
    {
        int a;
        double b;
        char *p;

        assert(a == 0);
        assert(b == 0.0);
        assert(p == NULL);
    }

## Integer sizes

Traditionally in C the size of `int` may differ depending on the system it is compiled for.
We specify the size of every type explicitly:

- 8-32 bits: one Unicode character as UTF-8 (u8char)
- 8 bits: char and unsigned char
- 16 bits: short and unsigned short
- 32 bits: int and unsigned int
- 64 bits: long and unsigned long
- 64 bits: long long and unsigned long long


On top of that we have specific bit size ints:

- 8 bits: i8, u8
- 16 bits: i16, u16
- 32 bits: i32, u32
- 64 bits: i64, u64
- 128 bits: i128, u128

Extending to bigger types is trivial if hardware support becomes available.
The compiler also has a built-in `bigint` for arbitrarily large integers.
A bigint has no fixed bit or byte size; it grows as needed.
This of course has a cost in performance and storage.
Otherwise bigints can be used like any other integer type:

    i32 a = 12345;
    i64 b = 567890;
    bigint c = 123456789123456789001234567890;

    bigint d = a + b;
    d += c;

When specifically needed, there are two types of the machine word size:

- isize: signed machine word size (32/64 bits)
- usize: unsigned machine word size (32/64 bits)

These can produce optimal code for the target architecture, but their size differs between targets, so they should not be used in portable code.

## Integer overflow

Integer overflow is not undefined behavior.
Instead these rules apply:

- By default signed and unsigned overflow causes wrap around
- For example: unsigned 8 bit integer `255` plus one becomes `0`
- For example: signed 8 bit integer `127` plus one becomes `-128`
- Divide by zero results in `0`

Operations can instead be checked strictly by wrapping them in an `unsafe` block
(`INT_MAX` and `INT_MIN` come from `<limits.h>`):

    unsafe {
        int a = INT_MAX;
        a++;
    }

That raises an exception instead of becoming `INT_MIN`.
The only way to catch the exception inside an `unsafe` block is to
enclose the operation in an `overflow` block.
The use of `overflow` is not limited to `unsafe` blocks:
it can be used anywhere to detect overflow.

Example:

    int main()
    {
        int a = INT_MAX - 5;

        unsafe {
            while (a > INT_MAX - 10 || a < 5) {
                if (overflow { a++; }) {
                    a = 0;
                }
            }
        }

        return 0;
    }

Without the `overflow` block the program would end with an exception. With it,
the loop counts from INT_MAX - 5 to INT_MAX, then assigns a = 0, and continues
counting until 5.

By default the wrap-around rules apply, and this example is perfectly valid:

    int main()
    {
        int a = INT_MAX - 5;

        while (a > INT_MAX - 10 || a < 5) {
            a++;
        }

        return 0;
    }

There `a` wraps from INT_MAX to INT_MIN and then counts on until it reaches 5,
which does not behave the same as the first example.
So the most natural way to use `overflow` is without `unsafe`:

    int main()
    {
        int a = INT_MAX - 5;

        while (a > INT_MAX - 10 || a < 5) {
            if (overflow { a++; }) {
                a = 0;
            }
        }

        return 0;
    }


When an overflow is detected, the overflowing operation does not change its
target, and the rest of the `overflow` block is skipped. Consider this example:

    int main()
    {
        int a = INT_MAX;
        int b = 0;
        int c;

        unsafe {
            overflow { a++; };
            // Value of a is unchanged, so it's still INT_MAX
            c = overflow {
                b = 1;   // This is always performed
                a += 10; // This will overflow and
                         // break out from overflow block
                // None of following are done:
                b = 2;
                a += 20;
                b = 3;
                a += 30;
                b = 4;
            };
        }

        assert(a == INT_MAX);
        assert(b == 1);

        return c;
    }

That program exits with code 1 (the value of `c`), but does not fail at any point.
Without the `overflow` blocks, execution would end at the first `a++`.
Here, for the first time, the value of an `overflow` block is assigned to an
integer; the earlier `if` examples use the same value: `overflow` yields `0` on
success and `1` when an overflow was detected.

## Built-in fixed point, and extended floats

Floating point is great, but sometimes a more exact representation is needed,
for example in financial calculations.

For float:

- 32 bits: f32, float
- 64 bits: f64, double
- 80 bits: f80
- 128 bits: f128

Note: `f80` is C's `long double`: stored in the x87 80-bit format (16 bytes,
ABI-compatible with C), but computed with `f64` precision. `f128` currently maps to
the same type (not IEEE binary128). C's `long double` is deprecated for that reason
(opt-in warning `-Wlong-double`).

`fixed` holds an **exact** rational number (a reduced numerator/denominator pair of
arbitrary precision), so its arithmetic never rounds: `(1 / 3) * 3 == 1`, and ten
`0.1`s add up to exactly `1`, which floats cannot do.

The syntax for fixed number types is `fixed<a,b>`, where `a` is the number of
meaningful digits of the integral part and `b` of the fraction part. The value
itself stays exact; it is rounded (half away from zero) to `b` decimals only when
it is shown or converted (`.str`, `.int`, a cast). Plain `fixed` shows 18
decimals.

- fixed<2,4>: 2 digits for integral, 4 digits for fraction, e.g. -99.9999 to 99.9999
- fixed<2,2>: 2 digits for integral, 2 digits for fraction, e.g. -99.99 to 99.99
- fixed<10,1>: 10 digits for integral, 1 digit for fraction, e.g. -9999999999.9 to 9999999999.9

Operations may mix fixed numbers of different precisions. The result type takes
the bigger integral and the bigger fraction part:

    fixed<10,2> a = 123456789.55;
    fixed<1,9> b = 1.123456789;

    // Prints fixed<10,9>
    printf("%s\n", type(a + b).str);

Because the value is exact, storing it in a `fixed` of another precision loses
nothing; only the number of decimals shown differs:

    fixed<10,9>  c = a + b;   // shown as 123456790.673456789
    fixed<5,4>   f = a + b;   // the same value, shown as 123456790.6735

Exactness has a price: the numbers are arbitrary precision (built on `bigint`), so
`fixed` math is slower than integer or floating-point math.


## Built-in string

SIC has a built-in `string` type. Traditional null-terminated strings (`char *`)
are of course still supported as well.

Built-in strings support UTF-8 natively.

Converting to a traditional null-terminated string is easy (`s.ptr`), with one
caveat: a string is not necessarily null-terminated, so the conversion may copy it.

This lets the indexes and ranges of a string be plain offsets into the original
data.

Strings support concatenate and substring:

    int main()
    {
        string test = "Hello world!";
        string another = test + " And all others!";

        printf("%s\n", test);
        printf("%s\n", another);
        // Substring, prints "world": from index 6 up to (not including) 11
        printf("%s\n", another[6:11]);
    }

Strings compare easily, without strcmp:

    string test = "Hello world!";
    string h = test[6:11];

    if (h != "world")
        return 1;
    return 0;

Basic search and split operations are built in. `contains` tests for a substring
(a single-character argument is the character-search case, so there is no separate
`strchr`); `split`/`rsplit` divide the string at the first/last occurrence of a
separator into a `tuple(before, after)`:

    string path = "path/to/file.txt";
    if (path.contains("/")) { /* … */ }

    tuple head_tail = path.split("/");        // ("path", "to/file.txt")
    tuple name_ext  = path.rsplit(".");       // ("path/to/file", "txt")
    string dir  = head_tail[0];
    string rest = head_tail[1];

When the separator is absent the result is a **one-element** tuple holding the whole
string, so `res.length` distinguishes a real split (its `.length` is `2` when the
separator was found, `1` when not). A `tuple t;` on its own is the empty tuple —
`t.length` is `0` and it has no valid element. This makes a peel-loop natural:

    tuple res;
    string tail = path;
    do {
        res = tail.split("/");
        tail = res[0];
    } while (res.length > 1);

The two parts are views into the original string (plain offsets, no copy), valid
while it is.

## Empty brackets pointer

This is not valid, since an array needs a size or an initializer:

    char test[];

## Struct reordering

Unlike C, the SIC compiler is allowed to reorder the struct to get optimal
alignment. This means that struct like

    struct test {
        u32 val;
        u64 val2;
        u8  val3;
        u32 val4;
    }

is internally reorganized by type size:

    struct test {
        u64 val2;
        u32 val;
        u32 val4;
        u8  val3;
    }

The reordering follows a fixed, standardized rule set:

1. **Primary key: storage size**, largest first. Each field is placed by its
   `sizeof`, so wider fields lead and padding is minimized.
2. **Secondary key: declaration order.** Fields of *equal* size keep the order
   they were written in — the sort is stable — so `u32 a; u32 b;` always keeps
   `a` before `b`, no matter how many fields sit between them.
3. **A union member sorts by its storage size**, which is the size of its largest
   element (rule 1 applied to the union).
4. **The order is overridable.** A struct can pin its declared order (see below),
   and because the physical order can differ from the source, the chosen
   permutation is recorded in the module manifest so consumers see the same
   layout.
5. **Only the size is compared** — never signedness, kind, or any other property.
   `i32` and `u32` are interchangeable for ordering purposes.

The size-based layout above is the **sic** ordering mode. There are four modes,
selectable per struct with an attribute, or globally with a flag:

| Mode | Per-struct attribute | Meaning |
|------|----------------------|---------|
| sic | `__attribute__((order_sic))` | size-based reorder (the rules above) |
| C | `__attribute__((order_c))` — or bare `__order__`, or `packed` | keep the declaration order (the C layout) |
| custom | `__attribute__((order(a, b, c)))` | an explicit permutation of the field *names* |
| random | `__attribute__((order_random))` / `order_random(seed)` | randomize the layout (hardening) |

A per-struct attribute always wins. With no attribute, a struct follows the global
default set by the compiler flag:

    -fstruct-order=sic       # size-based reorder for every struct (the .sic default)
    -fstruct-order=c         # keep declaration order everywhere (the C default)
    -fstruct-order=random    # randomize every struct

**Custom order** names every field exactly once; a missing, unknown, or duplicated
field name is a compile error (so a typo can't silently drop a field).

**Random order** is a `randstruct`-style hardening measure: the layout is shuffled
so code cannot depend on field offsets. It is deterministic in a *build seed* that
is drawn once per compiler invocation and shared by every translation unit in that
build — so all units agree on offsets (a differing layout across units would be a
broken ABI) — while a later build, with a fresh seed, produces a different layout.
Pin the seed for reproducible or split compile+link builds:

    -fstruct-order=random -fstruct-order-seed=12345   # or per struct: order_random(12345)

`-d` (debug output) prints the chosen build seed. Because the resulting permutation (for any mode)
is written into the module manifest, a consumer that `import`s the module always
sees the exact same layout the producer chose.

Whatever the requested mode, reordering is skipped entirely (the C layout is kept
exactly as written) for a `packed` struct, any struct containing a bit-field, and
any struct using an `aligned(n)` override on a member or on the type itself — those
forms pin the C layout. Reordering also applies to *named* structs; an anonymous
inline struct keeps its declaration order.

# Named parameters

A call may pass arguments **by name**, `name = value`, in addition to positionally.
Named arguments are matched to the callee's parameters of that name, so they can be
given in any order:

    int sum(int a, int b) { return a + b; }

    sum(2, 4);         // positional
    sum(b = 4, a = 2); // all named, reordered
    sum(2, b = 4);     // positional, then named

The rules are:

- **Named arguments may only follow positional ones** — `sum(a = 1, 2)` is an error.
  (Once you start naming, keep naming; the named ones may be in any order.)
- **Every mandatory parameter must be filled**, and no parameter may be given twice
  (whether positionally and by name, or by two names).
- Only parameter names are accepted; an unknown name is an error.

Named parameters are a purely caller-side convenience — the callee is unchanged.

For a **variadic** callee, named arguments are collected into a **`va_dict`** — a
`dict<string, any>` the function declares as a trailing parameter — while positional
trailing arguments still go to a `va_array`:

    int show(va_dict kw) { return (int)kw["a"] + (int)kw["b"]; }
    show(a = 1, b = 2);        // → kw = { "a": 1, "b": 2 }

`std::Print`/`Println`/`Fmt` use this for **named placeholders** `{name}` alongside
the positional `{}`:

    std::Print("{name} is {age}\n", name = "Sam", age = 42);   // Sam is 42
    std::Println("{} then {key}", 1, key = "two");             // 1 then two

An argument name may be any identifier, including a language keyword (`else = 42`),
which is handy for a `va_dict` sink. (To pass an actual assignment expression as an
argument, parenthesize it: `f((a = b))`.)

# Dict

`dict` is a built-in dynamically-sized hash map. It is used like an array but allows
any key and any value:

    dict data;                 // shorthand for dict<any, any>
    data["key"] = 42;
    data[5] = 9;               // keys of different types are fine

Keys and values may be constrained to specific types:

    dict<string, int> d;
    d["hello"] = 4;
    d["test"]  = 42;
    int n = d["hello"];        // 4

The map grows automatically as entries are added. Reading a key that is not present
yields a zero value. Deleting an entry — freeing its resources — is `del`:

    del data["key"];           // remove "key"; data["key"] now reads back as 0

A dict may be heap-allocated with `new`. Because a dict handle is itself already a
pointer, a pointer-to-dict is the same thing as a dict — `dict d` and `dict *p` are
interchangeable, and both are subscripted, iterated, and freed directly:

    dict<int, string> d;
    dict<int, string> *p = new dict<int, string>;   // same handle type as `d`
    d[5] = "five";
    p[5] = "five";                                    // no deref needed

A `new`-allocated container is owned by its binding and freed automatically at scope
exit, the same as a locally-declared one.

The implementation is a CPython-style insertion-ordered hash table (a compact
entries array plus a sparse index), so iteration order is stable and deletions
keep the surviving order intact. The key kind is tracked so key-type-specialized fast
paths can be added later.

A dict can hold values of **any** type via `dict<K, any>`, which stores each value
with its runtime type:

    dict<int, any> m;
    m[1] = 42;  m[2] = "hi";  m[3] = 3.14;   // mixed value types

Values may be of any concrete type too — `dict<int, string>`, `dict<int, struct
Point>`, etc. — read back as the declared type.

> As implemented today: keys may be integers or strings, and both string keys and
> string values are copied and owned by the dict (so they survive their source) and
> reclaimed on delete, overwrite, and scope exit. A scalar value is one machine word;
> a `dict<K, any>` also stores the value's runtime type. A typed struct value is
> deep-copied and owned by the dict too (shallow for its inner pointers, like a C
> struct copy). Reading a missing key yields a zero value (an empty string for a
> `string` value).

# List

`list<T>` is a built-in growable array (a dynamic vector). Use `list<any>` for a
heterogeneous list.

    list<int> xs;
    xs.add(10);              // also .push / .append
    xs.add(20);
    int a = xs[1];           // 20
    xs[1] = 99;              // update in place
    usize n = xs.size;       // element count (also .length)
    for (int i = 0; i < xs.size; i++) { /* xs[i] */ }

Elements are owned by the list — string and struct elements are copied and freed
with the list (and reclaimed when overwritten via `l[i] = …`). `l[i].field` and
`l[i][j]` work for aggregate elements.

> A plain `list` is `list<any>` (likewise `set` = `set<any>` and `dict` =
> `dict<any, any>`). As a type name it is contextual: code that uses `list`/`set`
> as a variable name is unaffected.

# Set

`set<T>` is a built-in hash set — unique elements of `T`, built on the same table as
`dict` (a `set<T>` is a `dict<T, bool>` under the hood). Plain `set` is `set<any>`.

    set<string> tags;
    tags.add("red");
    tags.add("red");                 // already present — no effect
    bool has = tags.contains("red"); // (also `.has`)
    tags.remove("red");
    usize n = tags.size;

Elements are owned by the set (string elements are copied), reclaimed on `remove`
and at scope exit — the same ownership rules as `dict` keys. The subscript form works
too, since a set is a dict: `s[x] = true` adds, `s[x]` tests membership, `del s[x]`
removes.

# Iterators

The containers are iterable with range-`for` (as are arrays, strings, enums, and any
struct with a `next()` method). Each container has a natural iteration shape:

    dict<string, int> ages;
    for (tuple kv : ages) { string k = kv[0]; int v = kv[1]; }  // key/value pair

    set<int> seen;
    for (int x : seen) { /* each element */ }

    list<string> words;
    for (tuple iv : words) { usize i = iv[0]; string w = iv[1]; }  // index/value pair

So iterating a `dict` yields a `tuple(key, value)`, a `set` yields each element, and a
`list` yields a `tuple(index, value)`.

To iterate just the keys or just the values, use `.keys` / `.values`. Each returns a
`list` — of the keys, or of the values — which iterates as plain elements:

    for (string name : ages.keys)   { /* … */ }
    for (int    age  : ages.values) { /* … */ }
    for (string w    : words.values){ /* each element, no index */ }

A `list`'s `.keys` are its indices `0 .. length-1`; its `.values` are the elements.
The projected list is a real, indexable `list` you can also bind and keep:

    list<string> names = ages.keys;   // owns a snapshot of the keys

Values in a projection are borrowed from the source container; string keys are copied
into the returned list, so the projection is safe to keep after the source changes.

# Async

A function marked `async` is asynchronous: it returns a `Task<T>` (where `T` is its
written return type) instead of running to completion at the call site. `await` drives
a task to completion and yields its `T`:

    async int fetch(int id) { return id * 2; }

    Task<int> t = fetch(21);   // start it; get a handle
    int a = await t;           // 42
    int b = await fetch(50);   // 100 — await a call directly

Inside an `async` function, `return v` completes the task with `v`. `await` accepts
any `Task<T>` and produces the `T`.

> This is language-level support. The compiler emits only the surface; the executor
> lives in a **module**. A built-in synchronous stub keeps `async`/`await` working
> standalone (an async call runs eagerly and `await` returns the stored result).

## The `art` runtime module

`art` is sic's async runtime — a small **cooperative, single-threaded coroutine
executor** built on stackful `ucontext` coroutines. It lives entirely in a module
(`import art;`), so scheduling can grow — timers, an I/O reactor, `join`/`select` —
without touching the compiler.

    import art;

    void worker(void *arg) {
        for (int i = 0; i < 3; i++) { /* … */ art::yield_now(); }
    }

    int main() {
        art::spawn(worker, a);   // schedule a coroutine
        art::spawn(worker, b);
        art::run();              // drive them to completion (round-robin)
        return 0;
    }

Two spawned coroutines that `yield_now()` interleave cooperatively. This is the
foundation the richer async API (and a bridge from `async`/`await` to real
suspension) builds on.

# Generics

Functions may be generic over one or more type parameters, written in a `<…>` list
after the function name:

    T add<T>(T a, T b) { return a + b; }
    T first<T>(T *p)   { return p[0]; }
    U cast<T, U>(T x)  { return (U)x; }

Generics are resolved **entirely at compile time by monomorphization** (as in Rust):
each distinct set of concrete type arguments produces its own specialized, fully
type-checked copy of the function — there is no runtime dispatch. The copies get
distinct symbols (`add$i32`, `add$i64`, `add$f64`).

The type arguments are **inferred from the argument types**, and each type parameter
must resolve to a single type:

    add(3, 4);        // T = int
    add(1.5, 2.5);    // T = double  (a second instantiation)
    add(1, 2.0);      // error: conflicting types for `T` (int vs double)

Type arguments may also be given **explicitly** (turbofish), which is required when a
type parameter appears only in the return type and so cannot be inferred:

    add<int>(3, 4);          // explicit, equivalent to the inferred form
    make<double>(5);         // T is the return type only → must be explicit
    conv<double, int>(9.7);  // two type parameters

Generic functions may also be **exported across modules**. A module's public
templates are carried in its manifest as source, and a consumer re-instantiates the
monomorphs it needs locally — like a template in a C++ header, there is no single
symbol to import:

    // module gmath;   T gadd<T>(T a, T b) { return a + b; }
    import gmath;
    int s = gadd(3, 4);              // inferred, instantiated in the consumer
    double d = gadd<double>(1, 2);   // turbofish across the module boundary

An imported template's body may reference only primitives, its type parameters, and
its arguments; a body that calls other module functions is not yet supported.

# Memory safety

## Scopes and automatic release

SIC borrows the `new` keyword from C++ to create new "objects".
They are not C++ class objects, but structs, which can have a
constructor and a destructor:

    struct test {
        test() {
            val = new int(8);
        }
        ~test() {
            del val;
        }
        int *val;
    }


These look like C++ classes. A struct can also have methods, which take the
struct as an explicit first parameter (`int get(test *self)`, called as
`a.get()`). Like in C++, the constructor and destructor are called automatically
on creation and when the object goes out of scope:


    void test()
    {
        struct test a; // constructor of 'test' for 'a' is called here
        struct test *b = new struct test; // constructor of 'test' for 'b' is called here

        // destructor of 'test' for 'a' called here, and 'a' is released;
        // 'b' is not released here: it is released with `del b`
    }

Memory allocated with `new` is reference counted, and every access to it is
bounds-checked.

Use `new` and `del` instead of C-style malloc/free.
Let's look at this example more closely:

    int *val = new int(10);
    val[10] = 0;
    del val;

This causes either a compile error or a runtime exception.
`new int(10)` allocates memory for 10 ints, so it is the same as `sizeof(int) * 10`
bytes, and index 10 is out of bounds.
To allocate just one integer, `new int` is enough.

An array may also be allocated with the bracket form `new T[count]`, where `count`
is any expression:

    i32 *a = new i32[n * n];    // n*n elements
    defer del a;                // released on scope exit

`new T[count]` is always an element count — unlike `new S(n)` on a struct with a
constructor, which allocates one object and passes `n` to the constructor.

The returned pointer is a so-called fat pointer. It includes information about the allocation:

- start_of_allocation
- size_of_allocation
- reference_cnt
- data

Its reference_cnt starts at 1.
Every access to the data is bounds-checked, so `val[10] = 0` makes this check:

    (10 * sizeof(int)) < size_of_allocation

Since we allocated `10 * sizeof(int)` bytes but access the element starting at `10 * sizeof(int)`, this check fails.
A failed check causes a runtime (or build-time) exception.

Without the out-of-bounds access, `del val` would release the allocation: it
decrements reference_cnt, and frees the memory when the count reaches 0.
A reference to the allocation may also have been passed on, for example to a thread.
In that case reference_cnt is still not 0, and the memory is freed when that reference goes out of scope.

### Tail-call optimization

A self-recursive function whose recursive call is in tail position — `return f(...)` —
is compiled as a **loop** rather than as recursion: the arguments are evaluated, the
parameters are reassigned, and control jumps back to the function's entry, reusing the
one stack frame. This means accumulator-style recursion runs in O(1) stack and does
not overflow, however deep:

    long sum(long n, long acc) {
        if (n == 0) return acc;
        return sum(n - 1, acc + n);   // tail call → becomes a loop, no stack growth
    }

The rewrite is applied conservatively (only when it is provably transparent — no
address of a parameter or local is taken, no `new`/`del`/`defer`, and only scalar
locals), so it never changes a program's result. A recursive call that is *not* in
tail position (e.g. `return f(n-1) + f(n-2)`) is left as a real call.

## Defer keyword

`defer`, borrowed from Go, runs a statement automatically on every exit from the scope.

For example:

    void test()
    {
        int *tmp = new int(10);
        defer del tmp;
        int *tmp2 = new int(5);
        if (!tmp2)
            return; // the deferred statement runs after this return
        tmp[0] = 10;
    } // the deferred statement runs here when exiting the scope

## Field access

Prefer `.` for field access — it works on both a value and a pointer, so a
pointer is dereferenced automatically. The compiler knows statically whether the
base is a pointer and generates the right access, so `p.field` and `p->field` are
equivalent:

    struct Point { int x; int y; };
    Point *p = new Point;
    p.x = 5;            // same as p->x
    int y = p.y;        // reads through the pointer

The C `->` operator still works, but `.` is the idiom. The null-safe `?.` operator
(below) also auto-derefs a pointer, and works as an assignment target too — a write
through a null base is simply dropped:

    p?.x = 10;          // if p is null, no write happens
    int v = p?.x;       // if p is null, v is 0

## Safe access

Besides the ternary operator, SIC has the elvis operator `?:` and the safe-access
operator `?.`.

For example:

    // If parse_port(s) returns 0 (or NULL), port will be 8080
    int port = parse_port(s) ?: 8080;

    // If "user" is null, "username" becomes NULL without an exception;
    // otherwise it is the result of the "user.name()" call.
    char *username = user?.name();

(Not implemented yet: calling a method through `?.`; reading and writing a field
through `?.` works.)

On top of these, an `else` guard runs a custom action when a value is missing — an
`Option`/`Result` without a value, or a null pointer — or a condition is false:

    int port = find_port(s) else return 0;     // find_port returns Option<int>
    auto val = table.find(key) else return -1;

    x > 0 else return EINVAL;

## References

A reference is indicated by `@` at the beginning of the type declaration.
When taking a reference to a variable, its name is also prefixed with `@`:

    int calculate_length(@char* s) {
        mut int i = 0;

        while (s[i]) {
            i++;
        }
        return i;
    }

    char *name = new char(10);
    memcpy(name, "test", 5);

    int len = calculate_length(@name);

This example looks like what you would normally do in C.
The difference is that a reference to the variable `name` is taken, instead of passing `name` as a plain pointer.
A pointer would normally be passed as-is, but since we use `@`, we are handling a new kind of reference.
This reference has its own scope, and is released automatically when it goes out of scope.
Thus it is valid only inside the `calculate_length()` function.
Inside the function, the variable `s` itself can be used as if it were a normal immutable pointer passed there.

A few things happen:
The first one is reference counting.
If `name` were freed in another context, the memory would not be freed until the last reference is dropped.
It's safe to pass references around, since they can never point to freed memory.
Reference to NULL is not allowed, and a reference can only be taken to memory
allocated with `new` (or to another reference): the count lives in the
allocation's header, which a string literal, a stack array or `malloc` memory
does not have.
This means that one can't call `free` on a reference.
Dereferencing is not allowed. Thus references are **always** scoped.

Note that in the previous example the reference itself is mutable, but the value it refers to is not.
It would be totally fine to go even one step closer to "normal C":

    int calculate_length(@char* s) {
        mut int i = 0;

        while (*s) {
            s++;
            i++;
        }
        return i;
    }

This is still memory safe. All access to the reference causes boundary checks.
In case the boundaries are violated an exception is raised.

To pass a reference to a mutable variable, one needs to state that explicitly:

    int calculate_length(@mut char* s) {
        int v = *(++s);

        // We can mutate value referenced by "s"
        *s = 0;
        return v;
    }

In that example both the reference itself and the value it refers to are mutable.
One should rarely pass a reference to a mutable variable.
First of all, passing `@mut` gives the function an exclusive reference to the variable.
A referenced variable may have either multiple readers or only one writer.
While a write reference exists, no other reads (or writes) are possible:
the compiler does not allow taking another reference to a variable that has a mutable reference.

Second, if you end up using this kind of construction, it's highly recommended to reconsider whether you really need it.
There are still legitimate use cases for it, so the language does not restrict it.

Returning a reference to a local variable is not allowed. However, to keep a reference alive,
a function can return a reference it was given back to the caller:

    @char *tst(@char *s) {
        printf("Ref: %s\n", s);
        return s;
    }

    char *name = new char(5);
    memcpy(name, "test", 5);
    @char *ret = tst(@name);
    printf("Still: %s\n", ret);

After the return the reference is kept alive; only its scope changes.
This would cause a compile error:

    @int tst() {
        int x = 42;
        return @x;
    }

    @int ret = tst();

Variable `x` is local, and its lifetime is bound to the function scope.
Referencing to it is allowed, but returning the reference is not.

Passing reference to another function is valid:

    int strlen_ref(@char *s) {
        int l = 0;
        while (*s) {
            ++l;
            ++s;
        }
        return l;
    }

    int add5(@char *s) {
        return *s + 5;
    }

    int adds(@char *s) {
        int res = strlen_ref(s);
        res += add5(s);
        return res;
    }

When a reference is passed as a parameter, a new reference is formed, and the reference count of the original variable is increased.

## Strict mode

Strict mode makes variables immutable unless they say otherwise. It is off by
default, and can be turned on for a whole file or for single functions.

To enable it for every function in a file:

    using strict;

To use it for a single function:

    strict int fn() {
        return 42;
    }

In strict code every variable — a local, a parameter, a global of a strict file —
is immutable after its initialization. The `mut` keyword makes one changeable:

    int meaning = 42;
    mut int life = 123;

    life++;          // fine
    meaning = 0;     // compile error: `meaning` is immutable

This is the opposite of the default in C, where only `const` variables are fixed.

Immutability covers what the variable holds by value: the fields of a struct,
the elements of an array, the entries of a list or a dict. With `p`, `xs` and
`d` immutable, `p.x = 1`, `xs[0] = 1` and `d["k"] = v` are errors. What a
pointer points to is not part of the pointer: `int *p` cannot be pointed
elsewhere, but `*p = 1` and `p->x = 1` follow the pointee's `const`, as in C.

Methods may change their struct: `p.bump()` works on an immutable `p`. A method
that does not change it should take `const S *self`; the compiler then rejects
any write through `self` in its body.

A loop counter needs `mut`: `for (mut int i = 0; i < n; i++)`. The variable of a
range-`for` is a new immutable binding on each pass.

An immutable variable declared without a value may be assigned once — its late
initialization — as long as no path through the function assigns it twice:

    int r;
    if (n > 5)
        r = 1;
    else
        r = 2;      // fine: one assignment on each path

Until then it reads as zero, like any SIC variable. An assignment that a loop
would run again, one that follows another assignment on some path, and one in a
`defer` are errors. (A function that uses `goto` gets no late initialization.)

Outside strict mode `mut` is accepted and does nothing.

## Ownership and copies

A value of a primitive type (an integer, a float, a pointer) is copied, exactly
as in C. Every other value — a `string`, a `list`/`dict`/`set`, a tuple, a
closure, a `bigint`/`fixed`, a struct holding one of those — has an owner and is
released when its owner's scope ends (see §"Scopes and automatic release"):

- **Assignment shares.** `b = a` makes `b` a second owner of the same value: only
  a small descriptor or handle is copied, and a reference count goes up. A string
  is immutable, so sharing one is invisible; a shared list is the same list.
- **A result moves.** A function's result, `return x` and a new value
  (`a + b`, `new`) go to their receiver without a copy.
- **An argument is borrowed.** The callee uses the caller's value for the call.

```sic
list<int> a;
list<int> b = a;    // the same list, two owners
b.push(1);          // a.length is 1 as well
```

### Copying: `clone()`

`x.clone()` makes an independent copy of any value: changing the copy never
changes the original, and the two are released separately.

```sic
list<int> a;
list<int> b = a.clone();
b.push(1);          // a is still empty
```

What is copied depends on the type:

| Type | `clone()` |
|---|---|
| primitive, enum, bitfield | the value |
| `string` | its bytes (the same as `.dup`) |
| `list`, `dict`, `set` | a new container, each element cloned |
| tuple | a new tuple with each element cloned (a tuple of plain values, being immutable, is shared) |
| tagged enum | the active variant's payload cloned |
| `bigint`, `fixed` | the value |
| `any` | a wrapped `string` is copied; any other wrapped value is a value or a borrow and stays |
| closure | shared: its captures cannot change |
| `weak<T>` | another weak reference to the same container |
| `new` pointer | a new block of the same size, each element cloned |
| struct | field by field, or by its own `clone()` method |

A pointer that does not come from `new` has no size to copy: `p.clone()` on it is
a compile error. A pointer to a struct (`p.clone()`, `p->clone()`) clones the
struct, as `p.method()` calls a method on it.

A struct clones field by field: each field is cloned by its type, and a plain
pointer field keeps pointing where it did (the struct does not own it). A struct
can say how it is copied with a method `S clone(S *self)` that returns the copy;
it is then used wherever an `S` is cloned — directly, as a field of another
struct, or as a container element.

A struct with its own constructor or destructor manages something that copying
its fields would duplicate — a file descriptor, a lock, a handle from a C
library — so it is never cloned field by field: it must define `clone()`. Cloning
it without one, or cloning a container of it, is a compile error.

    struct File {
        int fd;
        string name;
        ~File() { close(fd); }
        File clone(File *self) {
            File f;
            f.fd = dup(self->fd);
            f.name = self->name;
            return f;
        }
    };

    File a = open_file("log.txt");
    File b = a.clone();         // a second descriptor; each is closed once

A clone of a struct that holds a list of itself (a tree) clones the whole tree.
Strong references that form a cycle would make a clone run forever; a `weak<T>`
reference is not followed (see §"Weak references").

### References instead of copies

Instead of a copy, a function can take a reference to a `new` allocation; see
§"References":

    void print_ref(@char *s) {
        printf("Passed: %s\n", s);
    }

    char *text = new char(6);
    memcpy(text, "Hello", 6);
    print_ref(@text);
    // "text" is still usable after the call returns

## Assignment and equals

We define clear rules for assignment and equals operators,
which is not always the case in C.

Example in C:

    while (c = getc(in) != EOF)
        putc(c, out);

This is actually:

    while (c = (getc(in) != EOF))
        putc(c, out);

Which is wrong in that case; the code should have been written as:

    while ((c = getc(in)) != EOF)
        putc(c, out);


Same problem applies to:

    if (x = y)
        foo();

Which is just a typo, and should be:

    if (x == y)
        foo();

One solution is to disallow assignment in truth evaluation expressions
like if, while, etc.

First case would then be:

    c = getc(in);
    while (c != EOF) {
        putc(c, out);
        c = getc(in);
    }

This solution would cause compiler error on assignment inside conditionals.

A third option is to keep what we have; for example, with a `for` statement:

    for (int c = getc(in); c != EOF; c = getc(in))
        putc(c, out);

But we still have our repeated calls to `getc`.

This leads to the conclusion that our solutions so far might not be the best ones.
Better is to require parentheses around an assignment used in a condition.
The assignment must be written like this:

    while ((c = getc(in)) != EOF)
        putc(c, out);

And this, if that is really what you want:

    while ((c = (getc(in) != EOF)))
        putc(c, out);

The other case looks a bit odd with double parentheses, but tells the compiler you really mean it:

    if ((x = y))
        foo();

An unparenthesized assignment in a condition is a compile error.

## Dangling else

Curly braces are required for a non-trivial if statement.

This is valid:

    if (test)
        do_something();
    else
        do_other();

This would not be:

    if (test)
        if (second_test)
            do_something();
    else
        do_other();

Proper way would be:

    if (test) {
        if (second_test)
            do_something();
    } else
        do_other();

Now it's clear which `if` the `else` branch belongs to.

## Imports

The current C preprocessor mechanism of includes, headers and main units works,
but has its drawbacks.

SIC adds real modules, which can be imported.

Example of module:

    module test;

    int meaning = 42;

    int double_int(int x)
    {
        return 2 * x;
    }

    int power(int x)
    {
        return x * x;
    }


Everything is exported by default, unless defined as `static`. A new keyword,
`private`, marks a struct as private to the module, so it is not exported.
For functions `static` should be used.
The difference from C headers is that the implementation is not exported,
only the definitions of the module's non-static symbols.

To use the module:

    import test;

    void main()
    {
        printf("%d\n", test::double_int(5));
        printf("%d\n", test::power(5));
        printf("%d\n", test::meaning);
    }

Note that exported symbols are accessible only through the module's namespace.
We can import specific symbols from a module, or give them a new local name:

    // Imports only "double_int" from test and specifies it as "double_int" here
    import test::double_int;
    // Imports "power" from test, but renames it to "my_power"
    import test::power as my_power;
    // Module "test" itself is NOT imported, only those two symbols from it

    void main()
    {
        printf("%d\n", double_int(5));
        printf("%d\n", my_power(5));
    }

If really needed, there is a special syntax to import all symbols into the global namespace:

    import test::*;

This is the same as importing all symbols from `test` separately.

A module may itself import other modules:

    module extra;
    import std;

    namespace Extra {
        string greet(string name) { return std::Fmt("Hello, {}!", name); }
    }

A module's dependencies are chain-loaded: importing `extra` transitively pulls in
`std`, so `extra`'s std-backed API works and `std::` is reachable, without the
consumer importing `std` itself. Each module's manifest records only what that
module defines (plus a `dep` on each module it imports) — it does not re-export its
dependencies' symbols. Symbols are module-qualified internally, so two modules that
export a struct or function of the same name never collide.

The idea of modules is to be separate compilation units, which can be tested and exported separately.
Modules could be described as libraries.
For C compatibility, normal header files are generated from the module.
In that case, module usage would be (in C):

    #include "module_test.h"

    void main()
    {
        printf("%d\n", test_double_int(5));
        printf("%d\n", test_power(5));
    }

A module can span multiple compilation units.
The files of a module must be located in one folder (subfolders are not allowed);
files in a different folder form a different module.
Headers and other files can still be included with the preprocessor's `#include`
from outside the module folder.

Example of a multi-file module. First `test.sic`:

    module test;

    int meaning = 42;


Then `support.sic`:

    module test;

    int double_power(int x)
    {
        return power(x) * power(x);
    }

And `power.sic`

    module test;

    int power(int x)
    {
        return x * x;
    }

Since these are all in the same folder, they form a module. The folder may
contain other files, but files not marked with the same `module` tag are not
counted in.

Compiling a module (`sic --emit-module <folder>`) produces these outputs in the
module folder (on a Linux system):

- lib[module\_name].a and lib[module\_name].so
- module\_[module\_name].h
- module\_[module\_name].def
- module\_[module\_name].smod (the manifest `import` reads)

### Rust crates as modules

A module folder holding a `Cargo.toml` is a Rust crate. `--emit-module` binds the
`pub fn`s, `pub struct`s and their inherent `impl`s at the root of its
`src/lib.rs`, mapping Rust types to SIC ones:
- `&str`/`String` → `string`;
- `Vec<T>`/`&[T]` → `list<T>`, with byte vectors and slices → `string`;
- `Option`/`Result` → the built-in enums, the error formatted with `Display`;
- a struct → a refcounted handle type with methods and a destructor.

It generates the `extern "C"` glue and a SIC interface module, builds the glue
with cargo (`panic = "abort"`), and links the Rust code into the module's
libraries. The crate's modules are SIC namespaces and every name is Rust's
(`semver::Version::parse`, `hashbrown::hash_map::HashMap`); `pub use` re-exports
are the same item at the other path; associated functions live in a namespace
named after the type, and an argument-less `new()` is also the constructor. The test crate `module_test/13-rust-crate/mod-rsdemo` is the
example; see `doc/rust-crates.md`.

`cargo sic add <crate>` (the `cargo-sic` tool) automates this for a crates.io
crate. It generates a binding crate in `sic-deps/<module>/` from the crate's
rustdoc JSON, whose own Cargo.toml records the crate and its version (or an
optional `sic.toml` lists it), and builds it. Generic
types are bound at the instances `sic.toml` names. `sic` finds `sic-deps/*`
without `-I`.

## Match

`Option<T>` and `Result<T, E>` (and `Iterator<T>`) are **native, built-in**
generic enums — part of the language itself, not of the `std` module: they need
no declaration and no `import`. A module may return them and its consumers can
`match` or guard-unwrap the values.

New alternative to traditional `switch` and `case`.
Match takes an instance of an `enum`. It largely follows Rust syntax.
Old C-style enums are improved a bit:

    enum Option {
        Some<int>,
        None
    };

    enum Result {
        Ok<int>,
        Err<string>
    };

Every entry of an enum may carry a value, and the values may have different types.
The type is given after the name, inside < and >.

With these two we can make something like:

    Option a = Option::Some(5);
    Option b = Option::None;

    void check_option(Option opt) {
        match (opt) {
            // We can use Option::None here, but not needed since type
            // can be resolved from `opt`
            Some(val): printf("Some value: %d\n", val);
            None: printf("None value");
        }
    }
    check_option(a);
    check_option(b);

    // Same here: the type is Result, so even if another enum also had
    // an Ok, Result::Ok is used.
    Result r = Ok(5);
    Result e = Err("Some error");

    void check_result(Result res) {
        match (res) {
            Ok(val): printf("Result: %d\n", val);
            Err(msg): {
                printf("Error: %s\n", msg);
                exit(1);
            }
        }
    }

    check_result(r);
    check_result(e);

Thus the enum itself may give the type of the value.
Every entry in the enum has a name, and optionally a type.
An instance of the enum can hold a value of the entry's type.
Each entry may have a different type.

Old C enums work as before, and the new format still follows them: every item has
its integer value, like enums in C. For example:

    enum Test {
        NONE,
        BLACK = 1,
        RED = 2,
        GREEN = 3,
        CUSTOM(int)
    }

When using traditional print:

    Test b = BLACK;
    Test c = CUSTOM(42);

    printf("Val b: %d\n", (int)b);
    printf("Val c: %d\n", (int)c);

This prints out:

    Val b: 1
    Val c: 4

This is because the enumeration value of c is 4 (after GREEN = 3). To get the
value inside `c`, one must use the wrapper:

    printf("Val of c: %d\n", Test::CUSTOM(c));

`Test::CUSTOM` unwraps the value from c. It causes an exception if c is not a
CUSTOM. Better is to use:

    if (int cv = Test::CUSTOM(c))
    {
        printf("Val of c: %d\n", cv);
    }

## Bitfields

Bit flags are common — permission masks, feature sets, hardware registers — and
in C they are usually an `enum` (or `#define`s) stuffed into a `uint32_t`, with
nothing stopping you from adding, shifting, or mixing them with plain integers.
SIC has a dedicated `bitfield` type for this:

    bitfield Data { One, Two, Three };

Each member is a distinct power of two by position: `One = 1 << 0`, `Two = 1 << 1`,
`Three = 1 << 2`. You combine them with `|` and refer to a member bare or as
`Data::Two`:

    Data a = Two | Three;              // 0b110
    Data b = Data::One | Data::Three;  // 0b101

The bare form (`Two`) is allowed only where the bitfield type is unambiguous from
context — an initializer/assignment/return of that bitfield type, a matching call
argument, or a comparison/`&|^`/`~` against a value of that type. Where the type
can't be determined the bare form is a compile error and the qualified `Data::Two`
is required (which works anywhere):

    Data a = Two;            // ok — target is `Data`
    if (a == Three) …        // ok — `a` fixes the type
    int x = Two;             // ERROR: ambiguous — write `Data::Two`
    int y = (int)Two;        // ERROR: cast target is `int`, not `Data`
    int z = (int)Data::Two;  // ok — qualified; z == 2

A `_` placeholder skips a bit position without naming a flag — the next member
keeps its higher power of two:

    bitfield Tst { a, b, _, d };       // a=1<<0, b=1<<1, (1<<2 undefined), d=1<<3

You may skip several:

    bitfield Tst { _, b, _, d, _, e }; // b=1<<1, d=1<<3, e=1<<5

Only the bit operators `& | ^ ~` (and `== !=`) are allowed. Arithmetic, shifts,
and ordering are rejected at compile time — a `bitfield` is a *set of flags*, not
a number:

    Data c = a + Two;   // error: bitfield `Data` supports only `& | ^ ~`

`~` is the set complement — every *other* defined flag (holes are excluded, so the
result stays a valid combination):

    Data d = ~Two;      // One | Three

### Reading the integer value

A `bitfield` never implicitly becomes an integer. To get the underlying value you
must ask explicitly, with a cast or an `.as_uN` accessor:

    u32 v = (u32)a;
    u32 w = a.as_u32;
    u64 x = a.as_u64;

The width is checked at compile time against the *type's* capacity — its widest
flag — not the runtime value. A set that could ever hold `1 << 8` cannot be read
as a `u8` even if the value currently fits:

    bitfield All { a, b, c, d, e, f, g, h, i };   // widest flag is 1 << 8
    All p = All::d;
    u8  q = (u8)p;      // error: needs at least 9 bits
    u32 r = (u32)p;     // ok

Storage is an unsigned integer: `u32` for up to 32 flag positions, `u64` for up to
64 (more than 64 is an error). Assigning anything but the same `bitfield` (or a
literal `0`, the empty set) requires an explicit cast, and the flag compound
assignments `&= |= ^=` are the only ones permitted.

## Lambdas

SIC has C++-style lambda expressions for inline, anonymous functions — handy for
callbacks and small local helpers:

    auto sq = [](int x) { return x * x; };
    return sq(10);                       // 100

The form is `[captures](params) -> ret { body }`. The `-> ret` is optional (the
return type is inferred from the body), and there is a concise expression-body
sugar `=> expr` (equivalent to `{ return expr; }`):

    auto add = [](int a, int b) => a + b;

A **captureless** lambda (empty `[]`) is exactly a function — it lifts to an
ordinary top-level function and the expression evaluates to a plain function
pointer. So it drops straight into any C API that takes a callback, and into a
function-pointer variable, with no runtime cost:

    int (*fp)(int) = [](int x) { return x - 1; };
    qsort(a, n, sizeof(int),
          [](const void *x, const void *y) { return *(const int*)x - *(const int*)y; });

### Captures

A non-empty capture list binds names from the enclosing scope:

- `[x]` — captures `x`. A **scalar/pointer** is captured **by value** (a cheap
  copy); a larger value (**struct, `string`, `tuple`, container, …**) is captured
  **by reference** — no copy — so the closure sees its live value.
- `[@x]` — **shared borrow** (explicit): the closure reads `x`'s live value.
- `[@mut x]` — **mutable borrow**: the closure reads and writes the original `x`.
- `[weak x]` — **weak capture** of a container: the closure observes `x` without
  keeping it alive, so a closure stored inside the very container it captures does
  not form an ownership cycle. Inside the body `x` is a [`weak`](#weak-references)
  reference — upgrade it with `x.get` (see below).

```sic
int n = 100;
auto addn = [n](int x) { return x + n; };   // by value
addn(5);                                     // 105

int sum = 0;
auto add = [@mut sum](int x) { sum += x; };  // mutable borrow
add(10); add(32);
sum;                                         // 42
```

A capturing lambda is a **closure**: code plus a reference-counted environment
holding the captured values (or, for a borrow, a pointer to the original),
allocated on the heap and freed automatically. That is what lets a closure be
returned and stored — so **currying** works by returning a lambda that captures
the outer parameter:

    auto add = [](int a) { return [a](int b) { return a + b; }; };
    add(10)(32);                         // 42

### Naming a closure type — `Fn<ret(params)>`

A closure carries state, so it is not a plain function pointer. To name one — as a
parameter, a return type, or a variable — use `Fn<ret(params)>`:

    int          apply(Fn<int(int)> f, int x) { return f(x); }
    Fn<int(int)> adder(int n)                 { return [n](int x) { return x + n; }; }

    apply([n](int x) { return x + n; }, 2);   // pass a stateful closure
    apply([](int x) { return x + 1; }, 9);    // a captureless lambda works too
    Fn<int(int)> a = adder(40);               // store one
    a(2);

Lambdas cross the [module](#imports) boundary: a module can take a closure
parameter, return a closure, and export a module-level lambda (a captureless
lambda bound to a function pointer at file scope).

A captured refcounted value — a `string`, `tuple`, `list`/`dict`/`set`, or another
closure — is **retained for the closure's lifetime**: it is kept alive as long as
the closure lives and released when the closure is destroyed. So a closure that
captures such a value can safely be returned and outlive the scope it was created
in:

    Fn<int()> make() {
        tuple t = tuple(40, 2);
        return [t]() { return (int)t[0] + (int)t[1]; };   // `t` stays alive
    }
    make()();                            // 42

The exceptions are borrows that alias non-refcounted storage — a plain (C) struct
`[x]`, or an explicit `@`/`@mut` — which point at the original and so must not
outlive it (as with a C++ `[&]` capture). A closure capturing only scalars and
refcounted values (strings, tuples, containers, closures) is always safe.

The compiler enforces this: a closure that borrows a local — directly, or by
capturing another such closure — may be called, kept in local `Fn` variables and
passed down as an argument, but **returning it or storing it** in a field, a
global, `*p`, a container, or a struct/enum value is a compile error:

```sic
Fn<int()> bad() { struct H h; return [h]() => h.k; }   // error: closure borrows local `h`
```

(Passing a borrowing closure to a function that keeps it is not detected.)

## Macros

Rust-style declarative macros, `macro_rules`, invoked without `!` (full guide:
doc/macros.md). The bracket of a rule's matcher decides when `name…` is an
invocation, so a macro and a function can share a name:

```
int pick(int a, int b) { return a - b; }
macro_rules pick {
    [$($x:expr),*] => ( 100 );
}
pick(5, 3);   // function: the macro has no `(…)` rules
pick[5, 3];   // macro
```

If the bracket fits but no rule matches, an earlier-declared function of that name
is called; otherwise it is an error. Variables may not take a macro's name.
Fragments: `expr`, `ident`, `ty`, `literal`, `block`, `stmt`, `path`, `tt`;
repetition `$(…) sep? *|+|?`; transcriber built-ins `$str(…)`, `$file`, `$line`.
Expansions are parsed as a whole expression (parenthesized), statements, or
file-scope declarations; template locals are renamed (hygiene); nesting is
limited to 128.

Built-in: `assert(cond)` / `assert(cond, msg)` — always checked; prints the
condition's text and location, then aborts. A user `assert` replaces it.
`unreachable;` / `unreachable(msg);` marks a point control never reaches; reaching
it reports the location and aborts (see doc/macros.md).


## Weak references

Reference counting keeps shared values alive but cannot reclaim a *cycle* — two
containers that (transitively) hold each other never reach zero. A `weak<T>`
reference breaks the cycle: it points at a reference-counted container without
keeping it alive.

    list<int> a;
    a.add(42);
    weak<list<int>> w = a;      // does NOT keep `a` alive

`.get` upgrades a weak reference back to a strong handle — the live container if
it still exists, or a null (empty) handle once its last strong owner is gone, so
you always find out rather than dangling:

    list<int> s = w.get;        // the live list while `a` is alive
    // … after the container is dropped, `w.get` yields an empty handle

A `weak<T>` **struct field** is the usual home for such a back-pointer — an
observer that refers to its subject, a child that refers to its parent — so the
strong ownership forms a tree and the weak links close the loops:

    struct Observer { weak<list<int>> subject; };
    struct Observer o;
    o.subject = data;            // does not own `data`
    o.subject.get;               // the live list, or null once `data` is gone

A **closure** can capture a container weakly with `[weak x]`, for the same reason —
so a closure held inside the container it captures does not keep it alive:

    auto observe = [weak data]() -> int { return (int)(data.get).size; };

A container **element** can also be weak — a `list`/`set` element or a `dict` value
declared `weak<T>` is a non-owning reference. This is what lets one container refer
to another *without* forming a strong cycle (a graph of nodes, an observer list):

    list<weak<list<int>>> observers;   // each element observes a list, owns none
    observers.add(data);
    observers[0].get;                  // the live list, or empty once `data` is gone

    dict<int, weak<list<int>>> by_id;  // weak values (a weak key is meaningless)
    by_id[1] = data;

Reassigning or removing a weak element, or freeing the container, drops only the weak
reference. Currently `weak<T>` covers the reference-counted containers
(`list`/`dict`/`set`) as a local, a struct field, a closure capture, or a container
element/value.

## Switch - case

One problematic construct is `switch` and its `case`.
The biggest problem is the fallthrough when a `break` is missing.

We are breaking `switch` and making the end of a case mandatory:
`break` or `fallthrough` must be stated explicitly:

    int test(int x)
    {
        int r = 0;
        int a = 0;
        switch (x) {
            case 1: r = 111; a = 1;
                break;
            case 2:
                int tmp = x;
                r = 222;
                a = 1 + tmp;
                break;
            case 3: r = 333;
                break;
            case 4:
                r = 444;
                a = 2;
                break;
            case 5: r = 555;
                break;
            case 6: fallthrough;
            case 7: fallthrough;
            case 8: r = 678;
                break;
            case 9: r = 999; a = 3;
                break;
            default: r = 0;
                break;
        }
        return r + a;
    }

It is a compile error if a `case` does not end with `break` or `fallthrough` (or
another statement that leaves it, such as `return`).
No code is allowed between a `break` or `fallthrough` and the next `case` statement.
Multiple `break` or `fallthrough` statements, or a combination of them, are a compile error.
Compared to C this is a breaking change, but existing C code can easily be made compatible by adding the missing `fallthrough` statements.

## Rotate and shift

Original C has only shift left and shift right operators, but no rotate,
even though some CPUs have instructions for it, and it is widely used in programs.

Introducing rotate left `<<<` and rotate right `>>>` operators.  Example:

    int main()
    {
        unsigned int a = 0x12345678;
        // Should print 0x34567812
        printf("0x%x\n", a <<< 8);
    }

That would print out `0x34567812`.

Shifts are exactly specified:

- Left shift `<<`
  * Always fills zero
- Right shift `>>`
  * Unsigned fills always zero
  * Signed fills always sign bit
- Shift count can be anything
  * In case of overflow result is zero, except if signed right shift, it's filled with sign bit
  * If count is zero or negative, value is not shifted at all.

Examples:

    int main()
    {
        unsigned int a = 0x12345678;
        int b = -88888888;
        printf("%x\n", a << 100);
        printf("%x\n", a << -1);
        printf("%x\n", b >> 0);
        printf("%x\n", b >> 16);
        printf("%x\n", b >> 32);
    }

Results would be: `0`, `0x12345678`, `0xfab3a9c8`, `0xfffffab3`, `0xffffffff`.

## Arrays and lists

Arrays and lists get some helpful sugar. Let's take an example:

    int main()
    {
        int values[5];
        int tail[5];
        string test = "Hello world!";

        for (int i = 0; i < values.length; i++) {
            values[i] = i;
            tail[i] = i + values.size;
        }

        printf("String: %s, len: %d\n", test, test.length);

        int combined[20] = values + tail;
        // Will print 20, and not 10
        // Contents: values (0..4), then tail (20..24), then zeros
        printf("Combined length: %d\n", combined.length);
        // int combined[7] = values + tail // Would be a compile error

        // Will print 10
        printf("Combined2 length: %d\n", (values + tail).length);
    }

Thus arrays (and strings) have both `size` and `length` values, which are
usually calculated at compile time, but might be updated at runtime.
The recommendation is to use `length` for the number of elements.
The value of `size` depends on the element size.
For example int takes 4 bytes thus `values.size` is 5 * 4 = 20,
while `values.length` is 5.
For a string, `length` is the number of Unicode characters (code points)
in the string, and `size` is the size of all the characters in bytes.

The values are also used to perform runtime bound checks for extra safety and
to prevent out of bounds errors.

## Tuples

SIC has a built-in tuple type. It makes it easy, for example, to return multiple values from a function:

    tuple get_two(int x)
    {
        return tuple(x * 2, x * 3);
    }

    int main()
    {
        int a, b;

        tuple(a, b) = get_two(42);

        printf("Got: %d and %d\n", a, b);

        return 0;
    }

Thus the keyword "tuple" works in three ways:

- type: tuple tmp;
- pack values as: tmp = tuple(pack1, pack2, ...);
- unpack values as: tuple(unpack1, unpack2, ...) = tmp;

One can also access tuples with indexes, like arrays:

    tuple tmp;

    tmp = tuple(88, 66, 42);

    printf("First : %d\n", tmp[0]);
    printf("Second: %d\n", tmp[1]);
    printf("Third : %d\n", tmp[2]);

Values in tuples are strongly typed.
The types are assigned when the tuple is created.
The elements of a tuple may each have a different type.
Types are checked when unpacking.
Tuples are always immutable after creation.

### Static and dynamic tuples

`tuple<int, string>` names a tuple shape explicitly. A plain `tuple` is statically
typed whenever the compiler can infer its shape (an initializer, assignments in
straight-line code, agreeing call sites / returns), and **dynamically typed**
otherwise (a struct field, a parameter called with different shapes or exported from
a module, a local assigned different shapes under a branch or loop, a container of
mixed shapes). Every tuple block records its shape, so static → dynamic is free; on
a dynamic tuple `t[i]` is an `any` that converts only to the element's exact type
(else a run-time error), unpacking checks the arity, and `tuple<…> x = t` checks the
whole shape once. A static shape mismatch is a compile error. See
[doc/arrays-and-tuples.md](doc/arrays-and-tuples.md#static-and-dynamic-tuples).

### Ownership of tuple elements

A tuple **owns** the reference-counted values it holds (a `string`, a
`list`/`dict`/`set`, a nested tuple, a closure). Only the thin handle or descriptor
is copied into the tuple; the shared payload is reference-counted, never deep-copied.
So an element outlives the binding it was built from — a tuple may be returned from
the function that created its contents — and every element is released when the
tuple's last reference is dropped:

    tuple make() {
        list<int> xs; xs.add(1); xs.add(2);
        return tuple(xs, "tag");   // the list and string outlive this frame
    }

Extracting a refcounted element — `x = t[i]`, `T x = t[i]`, or an unpack
`tuple(a, b) = t` — takes its **own** reference on the receiver, so the extracted
value's lifetime is independent of the tuple's.

Because a container stored in a tuple is *shared* (the tuple keeps it alive, and
mutations through either handle are visible to both), a reference **cycle** through
a tuple is not reclaimed — the usual reference-counting trade-off. The compiler
emits a low-severity note where a raw `list`/`dict`/`set` is put into a tuple.
Keep the tuple as the strong owner and hold any back-reference to the same container
weakly (a [`weak<T>`](#weak-references) local, struct field, or closure capture)
so the strong references stay acyclic.

The reverse also works: a tuple can be stored **in** a container. A `list<tuple>`
or `dict<K, tuple>` owns its tuple elements, and the element's field layout is taken
from the first insertion, so indexing, iteration and unpack are all typed:

    list<tuple> rows;
    rows.add(tuple(1, "a"));
    tuple r = rows[0];        // r[0] == 1, r[1] == "a"
    for (tuple e : rows) { … }

## Swap

SIC has a built-in swap operation, which can be compiled to a single instruction
on target architectures that support it.

    int a = 6;
    int b = 20;

    a <> b;   // Swap values

    printf("%d\n", a); // prints 20
    printf("%d\n", b); // prints 6

The types of the swapped values should be the same, or differ by a trivial
conversion. Complex casting is not supported, but one can cast manually:

    i64 a = 5;
    i32 b = 1;

    (i32)a <> b;

    // a <> (i64)b; // An error, since the 64-bit value of `a` can't fit into
                    // the 32-bit `b`. This would be the default as well.

(Not implemented yet: swapping values of different types, and the cast form; today
both sides must be variables of the same type.)

## Memory barriers

Two statements order memory accesses for multi-threaded code:

```c
data = 40;
fence;      // full memory fence
ready = 1;
```

- `fence;` is a full, sequentially consistent fence. No load or store moves
  across it, neither by the compiler nor by the CPU (`mfence` on x86-64). It
  equals C's `atomic_thread_fence(memory_order_seq_cst)`.
- `barrier;` is a compiler-only barrier. The compiler may not cache memory in
  registers or move accesses across it, but no instruction is emitted. Use it
  where only compiler reordering matters (e.g. against a signal handler), or as
  an acquire/release fence on x86-64, whose memory model already orders those.

Both are contextual keywords: they are recognised only as a whole statement, so
`fence` and `barrier` stay usable as variable or function names.

## Errors and exceptions

> Planned: this section describes a design. Today `std::file` reports errors with
> `file::Status` values (see doc/standard-library.md), and the `&mut` parameters
> and the check that a result is handled are not implemented.

We have been talking about errors and exceptions earlier in this document, but haven't yet specified how they work.
In SIC most errors are actually just slightly better error codes. Let's take an example:

    int readbyte(&mut std::file::File f) {
        return f.read(1);
    }

This simple function tries to read one byte from a file. We get the file as a reference, read one byte from it and return the value.
Instead of the C API we use the SIC API, its `std::file` interface, which implements SIC-style errors.

When we try to compile that example, it fails. The reason is that we didn't handle the possible error.
For that we have two options: handle it locally, or pass it forward. Here's an example that handles it there:

    int readbyte(&mut std::file::File f) {
        Result<int, string> res = f.read(1);

        match (res) {
            Ok(val): return val;
            Err(msg): printf("Can't read from file!\n");
        }
    }

As you can see, the error in this case is just a wrapper around an enum
(`Result` is built into the language, not part of `std`). To pass it forward, one just writes:

    Result<int, string> readbyte(&mut std::file::File f) {
        return f.read(1);
    }

This passes the result forward, and it is the caller's responsibility to handle it.

Some operations may raise exceptions, for example division by zero in unsafe mode
(note that in normal mode the result would be `0`, without any exception):

    int dodiv(int a, int b) {
        unsafe {
            return a / b;
        }
    }

    printf("Res: %d\n", dodiv(10, 0));

On these primitive exceptions the program is terminated. A stack trace or some other error message might be printed.
To handle the exception instead of crashing the program, one can use the exception keywords `overflow`, `divide_by_zero` and `exception`:

    int dodiv(int a, int b) {
        unsafe {
            int res;
            if (divide_by_zero { res = a / b; }) {
                return 0;
            }
            return res;
        }
    }

    printf("Res: %d\n", dodiv(10, 0));

In this case the example works exactly as it would in normal mode, without the manual handling.

## Multiline strings

We're borrowing the multiline string syntax from Python:

    string multistring = """This is a multiline string.
        It starts with three quotation marks, and ends
        at the next three quotation marks.
        Thus it's valid to insert " or ' inside here.
        To have three quotation marks in the text,
        one can always escape them like \"\"\" this.
        One escape works too: \""".

        In this kind of string, newlines and indentation are NOT kept
        (a line break and the indentation after it become one space),
        unless the string is marked as a raw string.
        That happens by putting r before the first quotation mark.
        """;

    string raw_multistring = r"""This is raw multiline string.

        All formatting, newlines, etc. are preserved.
        Suitable for making templates that should be printed or written as-is.
        """;

Those strings can be used like any strings.

## Namespace

SIC supports namespaces, as in C++:

    namespace test {
        int a = 4;
    };

    if (test::a != 4) return 1;
    test::a = 5;

Inside the namespace its members are also reachable by their bare names (a local
or parameter of the same name shadows them). An enum declared in a namespace is
scoped to it — `test::Status` outside, `Status` inside — so two namespaces can each
define a `Status`.
