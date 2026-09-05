# SIC - Slightly Improved C specification

Slightly Improved C is a programming language that borrows a lot from C,
but is not afraid to introduce breaking changes in order to improve it.

**REMARK** Most of the features described here are only planned, and **NOT** yet implemented.
For now the focus has been implementing more or less standard C compiler.

## Limit undefined behavior

One of C's optimization strategies is "undefined behavior"
when compiler may do whatever it wants.

We remove that freedom and try to specify what to do on each of the cases.

Reason is to avoid hard to debug undefined behavior cases.
Our thesis is, compiler can do good enough code even with
these rules, and same time prevent unnecessary lost human time.

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

Traditionally in C the size of `int` may be different according the system where it's compiled into.
We specify size of all types explicitly:

- 8-32 bits: one unicode character as UTF-8 (u8char)
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

Extending to bigger types is trivial, in case hardware support comes available.
However compiler supports built-in bigint, which allows arbitrary big integers.
These are not any specific bit/byte size, but can grow any size when needed.
This of course has it's performance and storage size cost.
Otherwise bigints can be used like any other integer type:

    i32 a = 12345;
    i64 b = 567890;
    bigint c = 123456789123456789001234567890;

    bigint d = a + b;
    d += c;

In case it's specificly needed there's two types for machine word size:

- isize: signed machine word size (32/64 bits)
- usize: unsigned machine word size (32/64 bits)

These can be used to produce optimal code for the target architecture. Should not be used in portable code.

## Integer overflow

Integer overflow is not undefined behavior.
Instead these rules apply:

- By default signed and unsigned overflow causes wrap around
- For example: unsigned 8 bit integer `255` plus one becomes `0`
- For example: signed 8 bit integer `127` plus one becomes `-128`
- Divide by zero results in `0`

There's possibility to relax these checks and make all operations unsafe.
Thus operations must be wrapped inside `unsafe` block:

    unsafe {
        int a = MAX_INT;
        a++;
    }

That would cause exception instead of becoming `MIN_INT`.
Only way to guard and prevent exception inside `unsafe` block is to
enclose operation into `overflow` keyword.
The usage of `overflow` is not limited to `unsafe` blocks
and it can be used to detect overflow situations.

Example:

    int main()
    {
        int a = MAX_INT - 5;

        unsafe {
            while (a > MAX_INT - 10 || a < 5) {
                if (overflow { a++ }) {
                    a = 0;
                }
            }
        }

        return 0;
    }

Without `overflow` keyword execution of program would be
ended with an exception. Now it just iterates first from
MAX_INT - 5 to MAX_INT, then assigns a = 0, and continues
iteration until 5.

By default the rules applies and this example is perfectly valid:

    int main()
    {
        int a = MAX_INT - 5;

        while (a > MAX_INT - 10 || a < 5) {
            a++;
        }

        return 0;
    }

That would turn from MAX_INT to MIN_INT, and then continue until would reach 5.
On functionality way it's not same as the first example.
Thus most logical way to use `overflow` is without unsafe:

    int main()
    {
        int a = MAX_INT - 5;

        while (a > MAX_INT - 10 || a < 5) {
            if (overflow { a++ }) {
                a = 0;
            }
        }

        return 0;
    }


In case of overflow no values are changed.
Thus let's consider this example:

    int main()
    {
        int a = MAX_INT;
        int b = 0;

        unsafe {
            overflow { a++ };
            // Value of a is unchanged, so it's still MAX_INT
            int c = overflow {
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

        assert(a == MAX_INT);
        assert(b == 1);

        return c;
    }

That program would exit with error code, but would not fail at any point.
Without `overflow` keywords execution would be ended at first `a++`.
Also, here we first time take return value `overflow` and assign it into
and integer. Earlier example in case of `if` works same way.
So `overflow` return `0` in case of success, and `1` if overflow was detected.

## Built-in fixed point, and extended floats

Floating point is great, but sometimes more exact representation is needed.
Solution if fixed point math, and it improves precision, for example,
on financial calculations.

For float:

- 32 bits: f32, float
- 64 bits: f64, double
- 80 bits: f80
- 128 bits: f128

Fixed point precision contains two parts: integral and fraction.
It's possible to select precision for both of them separately.
From integral part one bit is reserved for sign flag.
Syntax for fixed number types is `fixed<a,b>`
where `a` is max meaningful digits for integral part,
and `b` is max meaningful digits for fraction part.

- fixed<2,4>: 2 digits for integral, 4 digits for fraction allowing -99.9999 to 99.9999
- fixed<2,2>: 2 digits for integral, 2 digits for fraction allowing -99.99 to 99.99
- fixed<10,1>: 10 digits for integral, 1 digit for fraction allowing -9999999999.9 to 9999999999.9

One can use plain `fixed` but it's in most cases sub-optimal.
Compiler tries to determine maximum value, but sometimes that's just impossible.
On these cases plain `fixed` needs to be extended during runtime to a bigger precision,
and in practice this is always based on bigint.
That might be expensive and compiler is unable to produce optimal code, which iw could be allowed
in case the values would have fit inside of traditional integers.
It's always recommended to define precision for fixed types.

On can perform operations on different sized fixed numbers with certain constraints.
Result of the operation must fit into the combined bigger precision limits.
Compiler takes bigger integral and fraction parts and uses that as result type.

For example:

    fixed<10,2> a = 123456789.55;
    fixed<1,9> b = 1.123456789;

    // Prints fixed<10,9>
    printf("%s\n", type(a + b).str);

Similar way if storing the result to new fixed point number, reserved precision must be matching or bigger:

    fixed<10,2> a = 123456789.55;
    fixed<1,9> b = 1.123456789;

    fixed<10,9>  c = a + b;
    fixed<11,11> d = a + b;
    fixed<5,4>   f = a + b;  // Compiler failure

Fixed numbers are most effective when the whole precision fits into 64 bit number, but are not limited to that.
One just need to keep in mind, that compiler can generate way much more optimal code if the numbers does not
exceed certain limits.
Otherwise it might need to rely on bigint feature, which means most of the time a performance hit.

Fixed point number may overflow and that can be cheked with `overflow` operator.
Without the overflow operator fixed point math causes exception. This differs
from integer math.


## Built-in string

We have built in string type, which creates optimal code to target.
Traditional null terminated strings are of course still supported as well...

Built-in strings supports natively UTF-8.

Conversion to traditional null terminated can be performed easily,
with certain constraints. For example strings might not be null terminated,
and conversion to null terminated string may cause a copy.

This allows indexes and ranged from string to be just plain offsets to the
original data.

Strings support concatenate and substring:

    int main()
    {
        string test = "Hello world!"
        string another = test + " And all others!";

        printf("%s\n", test);
        printf("%s\n", another);
        // Substring, will print "world", open interval
        printf("%s\n", another[6:11]);
    }

Support easy comparison without strcmp:

    string test = "Hello world!"
    string h = test[6:10];

    if (h != "world")
        return 1;
    return 0;


## Empty brackets pointer

This is not valid:

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

Is internally reorganized by type size:

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
4. **The size is overridable.** A struct can pin its declared order (see below),
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

`-d` prints the chosen build seed. Because the resulting permutation (for any mode)
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

A dict may be heap-allocated with `new` (and its handle is itself a pointer):

    dict<int, string> *test = new dict<int, string>;

The implementation is a CPython-style insertion-ordered hash table (a compact
entries array plus a sparse index), so iteration order will be stable and deletions
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

We borrow `new` keyword from C++ to create new "objects".
However they're not fat objects like in C++, but structs which can have
constructor and destructor:

    struct test {
        test() {
            val = new int(8);
        }
        ~test() {
            del val;
        }
        int *val;
    }


These looks like C++ classes, but we do not support directly other member methods
than the constructor and destructor. Like in C++ they're automatically called on creation,
and when getting out of scope:


    void test()
    {
        struct test a; // constructor of 'test' for 'a' is called here
        struct test *b = new struct test; // constructor of 'test' for 'b' is called here

        // destructor of 'test' for 'a' called here, and 'a' is released,
        // however 'b' is not released since it's not getting ouf of scope
    }

All dynamically allocated memory is reference counted.
Accessing dynamically allocated memory causes boundary checks.

Using `new` and `del` is recommended instead of C style malloc/free.
Let's see this example bit closer:

    int *val = new int(10);
    val[10] = 0;
    del val;

This would either cause compile error or runtime exception.
First `new int(10)` allocates memory for 10 ints so it's same as `sizeof(int) * 10`.
In order to allocate just one integer `new int` is enough.

Returned pointer is so called fat pointer. It will include information about the size of the allocation:

- start_of_allocation
- size_of_allocation
- reference_cnt
- data

It will have reference_cnt set as 1.
On every access to the data is protected with boundary checks. Thus the next line will end up making this check:

    (10 * sizeof(int)) < size_of_allocation

Since we have allocated `10 * sizeof(int)` but we're accessing element starting at `10 * sizeof(int)` this check will fail.
Failed check will cause runtime (or build time) exception.

In case there would not be any overflows we would end up deleting the allocation.
It will free the memory in case reference_cnt is decremented to 0.
It's also possible that reference to the allocation has been passed forward to a thread.
On that case reference_cnt is still not 0, and memory will be freed when the reference gets out of scope.

## Defer keyword

Borror `defer` syntax from Go to allow automatic action on every return.

For example:

    void test()
    {
        int *tmp = new int(10);
        defer del tmp;
        int *tmp2 == new int(5);
        if (!tmp2)
            return; // Defer statemen is run after this return
        tmp[0] = 10;
    } // Defer statenment is run here when exiting the scope

## Safe access

We support ternary operation, but also elvis operator `?:` and safe
access `?.` operator.

For example:

    // If parse_port(s) causes NULL or error, port will be 8080
    int port = parse_port(s) ?: 8080;

    // If "user" is null "username" becomes NULL without exception
    // Otherwise it will be result of "user.name()" call.
    char *username = user?.name();

On top of this we have `else` guard to trigger custom action:

    int port = parse_port(s) else return 0;
    auto val = table.find(key) else return -1;

    x > 0 else return EINVAL;

## References

First we have a reference, which is indicated by `@` at the beginning of the type declaration.
When taking a reference of a variable it's name is also prefixed with `@`:

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
Difference is that a reference to variable `name` is taken instead of passing `name` as plain pointer.
Pointer would normally be passed as-is, but since we use `@` we're handling new kind of references.
This referece has it's scope, and is automatically freed when getting out of scope.
Thus it's valid only inside `calculate_length()` function.
Inside the function variable `s` itself can be utilized as it would be a normal immutable pointer passed there.

There's few things that happens:
First one is reference counting.
In case `name` would be freed on another context, freeing up the memory is not done until the last reference is dropped.
It's safe to pass references around, since they can never point to freed memory.
Reference to NULL is not allowed.
This means that one can't call `free` on a reference.
Dereferencing is not allowed. Thus references are **always** scoped.

Note that on previous example the reference itself is mutable, but the value it's referring to is not.
It would be totally fine to do even one step closed to "normal C":

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

In order to pass reference to mutable variable one needs to explicitly state that:

    int calculate_length(@mut char* s) {
        int v = *(++s);

        // We can mutate value referenced by "s"
        *s = 0;
        return v;
    }

On that example both the reference itself and the value it's referring to are both mutable.
One should rarely pass reference to a mutable variable.
First of all, passing `@mut` makes the function to receive exclusive reference to the variable.
Referenced variables may have either multiple readers, or only one writer.
When a write reference is taken, other reads (or write) is not possible.
Taking another reference to a variable with a mutable reference is not allowed by compiler.

Second, if you end up using this kind of construction, it's highly recommended to reconsider if you really need it.
There is still legit use cases for this, thus it's not restricted by the language.

Returning a reference to local variable is not allowed. However if one wants to keep the reference alive
it can be returned back to the caller:

    @char *tst(@char *s) {
        printf("Ref: %s\n", s);
        return s;
    }

    char *name = "test";
    @char *ret = tst(@name);
    printf("Still: %s\n", ret);

After the return reference is kept alive, it's scope just changes.
This would cause compile error:

    @int tst() {
        int x = 42;
        return @x;
    }

    @int ret = tst();

Variable `x` is local, and it's lifetime is bounded on the function scope.
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

When passing a reference as a parameter a new reference is formed, and the reference count of original variable is increased.

## Strict mode

As another addition we add more rusty like features, which are optional by default.
In order to enable those a new strict mode is introduced.
This can be applied per function, or per compilation unit.

To enable it for whole compilation unit do:

    using strict;

To use it for a single function:

    strict int fn() {
        return 42;
    }

It changes few things:

All variables are by default immutable after initial assign.
Thus introduce new `mut` keyword to change this:

    int meaning = 42;
    mut int life = 123;

On that example variable `meaning` can't be changed, but `life` can.
This is the opposite of the default in C.
Mutable variable can be automatically promoted to immutable,
but not the other way around.

Another change is passing pointers.
We are adding borrowing, reference counting and ownership to all pointer by default.

### Ownership, and moving it

One big thing is ownership. Variables are always owned by someone.
Let's see example in strict mode:

    const char *text = "Hello";
    char *another = text;

First we have `text` which refers to const string `Hello`.
In strict mode one can omit `const` since all variables are by default immutable,
that's why variable `another` doesn't need `const`.

This flow is different from C.
In strict mode instead of doing assign, the value is moved.
This means that `text` is not valid any more after assignment `another = text`.
Thus only variable `another` is usable after the assignment.
In C and non-strict mode both `text` and `another` would be valid and referring
to same data.

If one needs to copy the value in two different variables, there's clone keyword:

    char *text = "Hello";
    char *another = clone text;

This makes a clone of the value of `text` and assigns it to `another`.
After this both variables are valid and can be used.

Cloning might me expensive operation, and is done recursively if needed.
For example:

    struct test1 {
        int a;
        int b;
    };

    struct test2 {
        int a;
        float b;
    };

    struct test3 {
        struct test1 a;
        struct test2 b;
    };

    struct test4 {
        struct test3 a;
        struct test3 *b;
        @struct test3 *c;
    };

    struct test4 *val1 = new struct test4;
    val1->b = new struct test3;
    val1->c = @val1->b;
    struct test4 *val2 = clone val1;

At this example `clone` needs to check all the other structs inside of it,
and call clone on them. This is done recursively until done.
References can't be cloned as is, but a new similar reference is formed.
In this example `val2->c` would still refer to `val1->b`,
but `val2->b` would be different from `val1->b`.

Remark that cloning and moving is meant for only non-primitive types.
All primitive types (int, float, etc.) can be simply assigned:

    int a = 4;
    int b = a;

On that example both `a` and `b` are still valid and usable.

Ownership is moved similar way when passing as parameter:

    void tst1(char *s) {
        // Ownership of "s" is moved here
        printf("Passed: %s\n", s);
    }

    void tst2(int v) {
        printf("Passed: %v\n", v);
    }

    char *text = "Hello";
    int val = 42;

    tst1(name);
    // "name" is not usable here any more
    tst2(val);

This example follows the rules defined earlier.
After calls to function `name` is not usable on the caller, but value of `val` would be usable since it's primitive.
Ownership of a variable can be passed back by returning the passed variable:

    char *print_and_return(char *s) {
        printf("Passed: %s\n", s);
        return s;
    }

    char *text = "Hello";
    char *text2 = print_and_return(text);
    // "text" is not usable here any more but "text2" is basically the same

    printf("Returned: %s\n", @text2);

This is perfectly valid, since ownership is first taken, and then returned.
Since `text` is not mutable, one can't assign the return value back to it,
but need to reserve new variable for it.
Rules state also that `text` is moved and not useable after the call.

Instead of moving ownership, reference can be passed:

    void print_ref(@char *s) {
        printf("Passed: %s\n", s);
    }

    char *text = "Hello";
    print_ref(@text);
    // "text" is still usable after the function call returns
    // since it was passed as a reference

    printf("Returned: %s\n", @text);

## Assignment and equals

We define clear rules for assignment and equals operators,
which is not always the case in C.

Example in C:

    while (c = getc(in) != EOF)
        putc(c, out);

This is actually:

    while (c = (getc(in) != EOF))
        putc(c, out);

Which is wrong on that case, and code should have been written as:

    while ((c = getc(in)) != EOF)
        putc(c, out);


Same problem applies to:

    if (x = y)
        foo();

Which is just typo, and should be:

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

Third option is to keep with what we have, for example `for` statement would be:

    for (char *c = getc(int); c != EOF; c = getc(int))
        putc(c, out);

But we still have our repeated calls to `getc`.

This leads to conclusion, that our solutions so far might not be the best ones.
Better is to mandate usage of braces with assignment operators when using
in evaluation expression. Mandate to write the assignment as this:

    while ((c = getc(in)) != EOF)
        putc(c, out);

This would be valid with braces, if that's what you want:

    while (c = (getc(in) != EOF))
        putc(c, out);

The another case looks bit more stupid with double braces, but tells compiler you really mean it:

    if ((x = y))
        foo();

On that case compiler is allowed to optimize this to:

    x = y;
    foo();

## Dangling else

Force curly braces for non-trivial if-statement.

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

Now it's clear to which `if` the `else` branch belongs to.

## Imports

Current C-preprocessor mechanism of include, headers and main units works
but has it's drawbacks.

Add support for real modules, which can be imported.

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


Everything is by default exported, unless defined as static.
Difference from C headers is, that implementation is not exported,
but only definitions of non-static symbols from the module.

To use the module:

    import test;

    void main()
    {
        printf("%d\n", test.double_int(5));
        printf("%d\n", test.power(5));
        printf("%d\n", test.meaning);
    }

Note that exported symbols are accessible only from module's namespace.
We can import specific symbols from module, or assign a new local identifier to them:

    // Imports only "double_int" from test and specifies it as "double_int" here
    import test.double_int;
    // Imports "power" from test, but renames it to "my_power"
    import test.power as my_power;
    // Module "test" itself is NOT imported, only those two symbols from it

    void main()
    {
        printf("%d\n", double_int(5));
        printf("%d\n", my_power(5));
    }

Idea of modules is to be separate compilation units, which can be tested and exported separately.
Modules could be described as libraries.
For C compatibility normal header files can be generated from the module.
On that case, module usage would be (in C):

    #include "module_test.h"

    void main()
    {
        printf("%d\n", test_double_int(5));
        printf("%d\n", test_power(5));
    }

Module can spread into multiple compilation units.
Files of the module must be located under one folder (subfolders not allowed),
and it's considered to be different module if files located in different folder.
Headers and other files can be included still with preprocessor `#include`
from outside the module folder.

Example of multi file module. First `test.sic`:

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

While these all are under same folder they can form a module. The folder may
contain other files, but in case they're not marked with same `module` tag
they're not counted in.

When compiling a module in C compatiblae mode, it produces these outputs
(in Linux system):

- [module\_name]\_[file\_name].o
- [module\_name].a
- module\_[module\_name].h
- module\_[module\_name].def
- module\_[module\_name].sicmod

TODO FIXME: See C++20 modules and import, compatibility?

## Match

New alternative to traditional `switch` and `case`.
Match takes an instance of `enum`. It follows largely Rust syntax.
Old C style enums are imporoved a bit:

    enum Option {
        Some<int>,
        None
    };

    enum Result {
        Ok<int>,
        Err<string>
    };

Every value in enum may have values and the values may have different types.
Type is defined after the name inside < and >.

With these two we can make something like:

    Option a = Option::Some(5);
    Option b = Option::None;

    function check_option(Option opt) {
        match (opt) {
            // We can use Option::None here, but not needed since type
            // can be resolved from `opt`
            Some(val): printf("Some value: %d\n", val);
            None: printf("None value");
        }
    }
    check_option(a);
    check_option(b);

    // Same here, type is Result, and even Ok would be defined on another
    // enum, Result::Ok is used.
    Result r = Ok(5);
    Result e = Err("Some error");

    void check_result(Result res) {
        match (r) {
            Ok(val): printf("Result: %d\n", val);
            Err(msg): {
                printf("Error: %s\n", msg);
                exit(1);
            }
        }
    }

    check_result(r);
    check_result(e);

Thus enum itself may contain type of the value.
All entries in the enum contains name, and optionally a type.
Instances of enums can contain value value of the defined type.
All entries may have different type.

Old C enums works as it. And the new format follows it still. Every item has
it's integer value like enums in C. For example:

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

This is because enumeration value of c is 4 (after GREEN = 3). In order to get
get value inside of `c` one must use the wrapper:

    printf("Val of c: %d\n", Test::CUSTOM(c));

The Test::CUSTOM will unwrap the value from c. It will cause exception if value
of c in not CUSTOM. Better is to use:

    if (int cv = Test::CUSTOM(c))
    {
        printf("Val of c: %d\n", cv);
    }

## Switch - case

One problematic construction is `switch` and it's `case`.
Biggest problem is the fallthrough in case of missing break.

We're breaking `switch` and making case end mandatory.
Thus `break` and `fallthrough` must be specifically stated:

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

It's compiler fault in case there's missing `break` or `fallthrough` statement after every `case`.
It's not allowed to have any code between `break` or `fallthrough` and the next `case` statement.
Multiple `break` or `fallthrough` or their combinations is compiler error.
Compared to C this is a breaking change, however current C code can easily made compatible by adding missing `fallthrough` statements.

## Rotate and shift

Original C has only shift left and shift right operators, but missing rotate,
even thought there's instructions for it on some CPU's, and it's widely utilized on programs.

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

Extend arrays and list handling with helpful sugar. Let's take an example:

    int main()
    {
        int values[5];
        int tail[5];
        string test = "Hello world!"

        for (int i = 0; i < values.length; i++) {
            values[i] = i;
            tail[i] = i + values.size;
        }

        printf("String: %s, len: %d\n", test, test.length);

        int combined[20] = values + tail;
        // Will print 20, and not 10
        // Contents will be 1..10 and rest zeros
        printf("Combined length: %d\n", combined.length);
        // int combined[7] = values + tail // Would be an compiler error

        // Will print 10
        printf("Combined2 length: %d\n", (values + tail).length);
    }

Thus arrays (and strings) has both `size` and `length` values, which are
calculated usually at compile time, but might get updated at runtime.
Recommendation is to use `length` to determine number of elements.
Value of `size` depend on the element size.
For example int takes 4 bytes thus `values.size` is 5 * 4 = 20,
while `values.length` is 5.
In case of string `length` tells number of unicode characters (or code points)
in the string, but string `size` is the size of all the characters in bytes.

The values are also used to perform runtime bound checks for extra safety and
to prevent out of bounds errors.

## Tuples

Support for built-in tuple type. Eases for example returning multiple values from function:

    tuple get_two(int x)
    {
        return tuple(x * 2, x * 3)
    }

    int main()
    {
        int a, b;

        tuple(a, b) = get_two(42);

        printf("Got: %d and %d\n", a, b);

        return 0;
    }

Thus keyword "tuple" works in three ways:

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
Types are assigned when tuple is created.
All elements in tuple may have different type.
Types are checked when unpacking.
Tuples are always immutable after creation.

## Swap

Support built-in swap operation, which can be compiled to assembly instruction
on target architectures supporting it.

    int a = 6;
    int b = 20;

    a <> b;   // Swap values

    printf("%d\n", a); // prints 20
    printf("%d\n", b); // prints 6

Types of the values swapped should be the same or trivial conversion.
Complex casting is not supported. However one can manually cast:

    i64 a = 5;
    i32 b = 1;

    (i32)a <> b;

    // a <> (i64)b; // This would cause error since 64-bit "a" can't fit into
                      // 32-bit "b". This would be the default as well.

## Errors and exceptions

We have been talking about errors and exceptions earlier in this document, but haven't yet specified how they work.
In case of SIC most errors are actually just bit better error codes. Let's take an example:

    int readbyte(&mut std::File f) {
        return f.read(1);
    }

This simple function tries to read one byte from a file. We get the file as reference, read one byte from there and return the value.
Instead of C API we use SIC API and it's `std::File` interface which implements SIC style errors.

When we try to compile that example it fails. Reason is that we didn't actually handle the possible exception.
For that we have two options: handle it locally, or pass it forward. Here's an example to just handle it there:

    int readbyte(&mut std::File f) {
        std::Result<int, string> res = f.read(1);

        match (res) {
            Ok(val): return val;
            Err(msg): printf("Can't read from file!\n");
        }
    }

As you can see the error in this case is actually just wrapper around an enum. In order to pass it forward one just:

    std::Result<int, string> readbyte(&mut std::File f) {
        return f.read(1);
    }

Which passes the result forward and it's caller's responsibility to handle it.

There's exceptions that may be triggered by some operations. For example divide by zero in unsafe mode
(Remark that in normal mode result would be `0` instead without any exceptions):

    int dodiv(int a, int b) {
        unsafe {
            return a / b;
        }
    }

    printf("Res: %d\n", dodiv(10, 0));

On these primitive exceptions the program in question is terminated. Stack trace might be printed, or some other error message.
In order to handle the exeption instead of crashing the program one can use specific exception keywords: `overflow`, `divide_by_zero` and `exception`:

    int dodiv(int a, int b) {
        unsafe {
            int res:
            if (divide_by_zero { res = a / b }) {
                return 0;
            }
            return res;
        }
    }

    printf("Res: %d\n", dodiv(10, 0));

On this case the example works exacly as it would in normal mode without the manual handling.

## Multine strings

We're borrowing multiline string syntax from Python:

    string multistring = """This is multine string.
        It starts with three quotation marks, and ends
        until three quotations marks are found.
        Thus it's valid to insert " or ' inside here.
        In case one would like to have three quotation marks,
        one can always escape it like \"\"\" this.
        One escape would also work: \""""

        Inside this quotation newlines and indent is NOT saved unless
        the string is marked as raw string.
        That happens by giving identifier r before fist quotation mark.
        """;

    string raw_multistring = r"""This is raw multiline string.

        All formatting, newlines, etc. is preserved.
        Suitable for making templates that should be printed or written as-is.
        """;

Those strings can be used like any strings.

## Namespace

Support for namespaces like in C++

    namespace test {
        int a = 4;
    };

    if (test::a != 4) return 1;
    test::a = 5;
