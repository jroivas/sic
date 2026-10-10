# Atomics

`atomic` is a type qualifier for lock-free shared state — the sic spelling of
C11's `_Atomic`. An atomic object may only be operated on through operations that
map to a single lock-free machine instruction, so the cost model is honest: every
allowed operation is one atomic instruction, never a hidden retry loop. All atomic
operations are **sequentially consistent**.

```sic
atomic int counter = 0;
atomic u64 flags = 0;
```

Only lock-free scalar types are allowed: a 1/2/4/8-byte integer, `bool`, or a
pointer. `atomic double`, `atomic` structs, etc. are a compile error.

## Operations on an atomic integer

Ordinary syntax becomes atomic because the *type* is atomic — there's no special
operator to remember:

```sic
atomic int a = 5;
int x = a;        // atomic load
a = 10;           // atomic store
a += 2;           // atomic fetch-add   (also -=)
a &= MASK;        // atomic fetch-and   (also |=  ^=)
a++;  --a;        // atomic increment / decrement
```

`a++` yields the old value, `++a` the new one — the natural fetch semantics.

Operations that have **no** single lock-free instruction are rejected: `*=`, `/=`,
`%=`, `<<=`, `>>=`. If you need one of those atomically, write an explicit `.cas`
loop.

## `.swap` and `.cas`

Two pseudo-methods, available **only** on an atomic lvalue (never on an ordinary
value):

```sic
int old = a.swap(20);          // atomic exchange: store 20, return the previous value

if (a.cas(expected, desired))  // compare-and-swap: if a == expected, set desired;
    …                          // returns whether it succeeded (bool)
```

`.cas` is the primitive for lock-free algorithms. Its result tells you whether the
swap happened, so it drops straight into a retry loop:

```sic
// atomic increment-if-below-cap
int cur;
do { cur = a; } while (cur < CAP && !a.cas(cur, cur + 1));
```

## Atomic struct fields

A struct field can be `atomic` too. Every access to it — through `->`, through
`.` on a struct value, or through `.` on a struct pointer — is atomic, and it
takes `.swap` / `.cas` like an atomic variable:

```sic
struct Job {
    Fn<void()> work;
    atomic int state;            // RUNNING / FINISHED / DETACHED
};

j->state = RUNNING;                       // atomic store
j->state++;                               // one atomic RMW
if (!j->state.cas(RUNNING, FINISHED))     // exactly one side wins
    cleanup(j);
```

The same lock-free rule applies: an `atomic double` field is a compile error.

## Atomic pointers

A pointer whose *own* value is read/written atomically is spelled with the
parenthesized form (matching C11's `_Atomic(T)`), which disambiguates it from a
pointer to an atomic value:

```sic
atomic(int *) q;      // the POINTER is atomic
atomic int  *p;       // a pointer TO an atomic int (the pointee is atomic)
```

An atomic pointer supports load, store, `.swap`, and `.cas` — but **no
arithmetic** (`q++`, `q += n` are compile errors), since atomic pointer arithmetic
is almost always a mistake:

```sic
atomic(node *) head = 0;
node *cur = head;                 // atomic load
head = n;                         // atomic store
node *prev = head.swap(n);        // atomic exchange
if (head.cas(cur, n)) { … }       // lock-free push
```

## Memory barriers

Two statements order memory accesses for code that shares plain (non-atomic)
data between threads:

```sic
data = 40;
fence;          // full barrier: no load/store crosses it (compiler + CPU, mfence)
ready = 1;
barrier;        // compiler-only: nothing is cached or moved across it, no instruction
```

`fence;` equals C11's `atomic_thread_fence(memory_order_seq_cst)`. `barrier;` is
enough against a signal handler on the same thread, or as an acquire/release
fence on x86-64. Both are contextual keywords — `fence` and `barrier` remain
usable as names. In C, `__atomic_thread_fence`, `__atomic_signal_fence` and
`__sync_synchronize` map to the same operations.

## Summary

| | read / `=` | `+= -= &= |= ^=` `++ --` | `.swap` | `.cas` | `*= /= %= <<= >>=` |
|---|:---:|:---:|:---:|:---:|:---:|
| `atomic` integer / bool (variable or struct field) | ✅ | ✅ | ✅ | ✅ | ✗ |
| `atomic(T *)` pointer | ✅ | ✗ | ✅ | ✅ | ✗ |

Next: [standard library](standard-library.md).
