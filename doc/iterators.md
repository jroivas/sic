# Methods & iterators

## Struct methods

A struct may declare **member functions** in its body. A method takes the receiver
explicitly as its first parameter — a pointer named `self` by convention — and is
called with `obj.method(args)` (or `p->method(args)` for a pointer):

```sic
struct Point {
    int x;
    int y;
    int sum(struct Point *self)        { return self->x + self->y; }
    void shift(struct Point *self, int d) { self->x += d; self->y += d; }
};

struct Point p;
p.x = 1; p.y = 2;
p.shift(10);          // p is now {11, 12}
int s = p.sum();      // 23
```

The receiver is passed automatically: `p.shift(10)` calls the method with `&p` as
`self`, so a method can read and mutate the object. A method may return anything,
including an aggregate.

## Constructors & destructors

Beyond methods, a struct may define a **constructor** `S()` and a **destructor**
`~S()` (sic.md §"Memory safety"). They are called automatically — the constructor
when a local of that type is declared, the destructor when it goes out of scope
(on every exit path). Inside them `self` is implicit, so a bare field name refers
to the field:

```sic
struct Buf {
    int *data;
    Buf()  { data = new int(8); data[0] = 1; }   // runs at declaration
    ~Buf() { del data; }                          // runs at scope exit
};

void use() {
    struct Buf b;         // Buf() called here
    b.data[0] = 42;
}                         // ~Buf() called here — del frees the block
```

Notes:

- The constructor runs **only when there is no explicit initializer**. `struct Buf
  b = { … };` is a plain aggregate initializer and does **not** call `Buf()`.
- A local that shadows a field name wins inside the constructor/destructor — that
  name refers to the local, not `self->field`.
- Destructors compose with the rest of sic's scope cleanup (defer, string/`new`
  release), all in reverse order of declaration.

## Range-`for`

`for (auto item : iterable)` walks an iterable, binding each element to `item`
(its type inferred from the iterable). `break`/`continue` work as in a normal loop.

```sic
int xs[3] = {10, 20, 30};
int total = 0;
for (auto x : xs) { total += x; }     // 60
```

It works over several kinds of iterable:

### Arrays and slices

Yields each element by value, in order.

```sic
for (auto x : xs) { use(x); }
```

### Containers

`list`, `set`, and `dict` iterate too (see [containers](containers.md)): a `list`
yields `tuple(index, value)`, a `set` yields each element, and a `dict` yields
`tuple(key, value)`. Use `.keys` / `.values` to iterate one side:

```sic
dict<string, int> ages;
for (tuple kv : ages) { string k = kv[0]; int v = kv[1]; }
for (int v : ages.values) { … }

list<int> xs;
for (int v : xs.values) { … }
```

### Strings → code points

A `string` iterates its **UTF-8 code points** as `u8char` (not raw bytes):

```sic
string s = "héllo";
int n = 0;
for (auto cp : s) { n++; }   // n == 5  (é is one code point, two bytes)
```

For raw bytes, index the string (`s[i]`); for the code-point array directly, use
`s.utf8`.

### Enum types

Naming an enum **type** iterates its variant values, in declaration order:

```sic
enum Dir { N, E, S, W };
for (auto d : Dir) {
    printf("%s = %d\n", d.str.ptr, (int)d);
}
```

### Custom iterators

Any struct with a `next()` method returning the built-in `Iterator<T>` is iterable.
`Iterator<T>` is a prelude tagged enum:

```sic
Iterator<T> { Stop, Next(T) }
```

`next(self)` returns `Iterator::Next(x)` to yield `x`, or `Iterator::Stop` to end.
The loop advances a **copy** of the iterable, so the original is left untouched:

```sic
struct Countdown {
    int n;
    Iterator<int> next(struct Countdown *self) {
        if (self->n <= 0) return Iterator::Stop;
        int v = self->n;
        self->n -= 1;
        return Iterator::Next(v);
    }
};

struct Countdown c;
c.n = 3;
for (auto v : c) { printf("%d ", v); }   // 3 2 1
// c.n is still 3 here — the loop iterated a copy
```

Under the hood the loop desugars to the obvious `match` over `next()`:

```sic
auto it = c;
for (;;) {
    match (it.next()) {
        Next(v): { /* body, with item = v */ }
        Stop:    break;
    }
}
```

Next: [memory & ownership](memory-and-ownership.md).
