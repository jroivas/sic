# The standard library

`import std;` brings in the SIC standard library. It is an ordinary
[module](modules.md) — plain SIC source shipped with the compiler and installed
in the sysroot, so no flags are needed — and it demonstrates the language's own
features (RTTI, `any`, `va_array`, ownership) rather than being compiler magic.

Today `std` provides formatted output (`Fmt`, `Print`, `Println`), file I/O
(`std::file`), byte buffers (`std::buffer`), threads (`std::thread`) and
synchronization (`std::sync`), math (`std::math`), random numbers
(`std::random`), filesystem operations (`std::fs`) and TCP sockets (`std::net`).

**Naming:** namespaces are lowercase; everything they export — functions,
types, enums, constants — is CamelCase (`std::file::Open`, `std::file::File`,
`std::math::Pi`, `std::random::Rng`). Struct methods stay lowercase, like the
built-in ones (`g.gen64()`, `s.trim()`, `l.add(x)`).

`Option<T>` and `Result<T, E>` are not part of `std` — they are built into the
language ([enums & matching](enums-and-matching.md)); `std`'s functions simply
return them where a result may be absent or fail.

## Formatting

All three use `{}` placeholders, each substituted by the next argument formatted
according to its runtime type. `{{` and `}}` are literal braces.

```sic
import std;

int main() {
    string who   = "World";
    fixed  price = 19.99;

    std::Println("Hello, {}!", who);                 // Hello, World!
    std::Println("{} items at {} each", 3, price);   // 3 items at 19.99… each
    string s = std::Fmt("{{}} then {}", 42);         // "{} then 42"
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
std::Println("{}", value);
```

### Named placeholders

A `{name}` placeholder is filled from a `name = value` argument (a keyword
argument, collected into a `va_dict`), so order doesn't matter and positional and
named arguments can mix:

```sic
std::Print("{name}={val}\n", val = 42, name = "answer");   // answer=42
std::Println("mix {} and {k}", 7, k = "named");            // mix 7 and named
```

## File I/O

The file API lives in `std::file`. Every call returns a `std::file::Status`
tagged enum instead of an error code, and data moves through a `std::buffer`:

```sic
import std;

int main()
{
    match (std::file::Open("hello.txt", std::file::OpenMode::Read)) {
        std::file::Status::Opened(f): {
            std::buffer::Buffer *buf = std::buffer::Create(4096);
            match (std::file::Read(f, 4096, buf)) {
                std::file::Status::Read(n): std::Println("read {} bytes", n);
                _: std::Println("read failed");
            }
            del buf;
            std::file::Close(f);
        }
        std::file::Status::NotFound: { std::Println("no such file"); return 1; }
        _: return 1;
    }
    return 0;
}
```

| Call | Result on success |
|---|---|
| `Open(name, OpenMode::Read / Write / RW)` | `Status::Opened(File*)` |
| `Read(f, size, buf)` / `ReadFrom(f, offset, size, buf)` | `Status::Read(bytes)` |
| `Write(f, buf)` / `WriteTo(f, offset, buf)` | `Status::Wrote(bytes)` |
| `Size(f)` | `Status::Size(bytes)` |
| `Close(f)` | `Status::Success` (also frees `f`) |
| `Eof(f)` | `bool` |
| `Stdin()` / `Stdout()` / `Stderr()` | the standard streams as `File*` |

Failures are other `Status` variants: `NotFound`, `InvalidObject`, `IO`,
`InvalidFileHandle`, `ReadError`, `WriteError`, `OutOfMemory`, `InvalidOffset`.
`File` and `Buffer` are managed structs that release themselves (`del`/scope
exit) across the module boundary.

## Threads

`std::thread` runs a closure on a new POSIX thread:

```sic
import std;

atomic int total = 0;

int main()
{
    std::thread::Thread *workers[4];
    for (int i = 0; i < 4; i++) {
        int n = i + 1;
        match (std::thread::Spawn([n]() { for (int k = 0; k < 1000; k++) total += n; })) {
            std::thread::Status::Created(t): workers[i] = t;
            _: return 1;
        }
    }
    for (int i = 0; i < 4; i++) std::thread::Join(workers[i]);

    list args;
    args.add("sum");
    args.add(32);
    match (std::thread::Create([](list a) { string s = a[0]; int v = a[1]; std::Println("{} = {}", s, v); }, args)) {
        std::thread::Status::Created(t): std::thread::Join(t);
        _: return 1;
    }
    std::Println("total = {}", total);         // 10000
    return 0;
}
```

| Call | Result |
|---|---|
| `Spawn(Fn<void()> f)` | `Status::Created(Thread*)` — runs `f()` |
| `Create(Fn<void(list)> f, list args)` | `Status::Created(Thread*)` — runs `f(args)` |
| `Join(t)` | `Status::Joined`; waits, then frees `t` |
| `Detach(t)` | `Status::Detached`; the thread frees itself when it ends |
| `Id()`, `Sleep(ms)`, `Yield()` | the calling thread's id, sleep, yield |

Failures are `Status::Error(errno)`, `NoMemory` and `InvalidObject`. After
`Join`/`Detach` the handle must not be used. A closure's (and a tuple's)
reference count is atomic, so handing one to a thread is safe; strings and
containers still use plain counts — hand them over to the thread rather than
using them from both threads at once. Share counters through
[atomics](atomics.md).

## Synchronization

`std::sync` wraps POSIX mutexes and condition variables (used through pointers):

```sic
auto m = std::sync::CreateMutex() else return 1;
auto cv = std::sync::CreateCond() else return 1;
std::sync::Lock(m);
while (!ready) std::sync::Wait(cv, m);              // or TimedWait(cv, m, ms)
std::sync::Unlock(m);
std::sync::NotifyOne(cv);                           // NotifyAll(cv)
std::sync::DestroyCond(cv);
std::sync::DestroyMutex(m);
```

`TryLock(m)` returns whether it got the lock. `TimedWait` waits on the
monotonic clock and returns `false` on timeout.

## Math

`std::math` wraps libm: `Sin`, `Cos`, `Tan`, `Asin`, `Acos`, `Atan`,
`Atan2(y, x)`, `Sinh`, `Cosh`, `Tanh`, `Sqrt`, `Pow`, `Exp`, `Log`, `Log10`,
`Log2`, `Floor`, `Ceil`, `Round`, `Fabs`, `Fmod`, `Hypot`, and the constants
`Pi` and `E` (all `f64`).

```sic
f64 r = std::math::Hypot(3.0, 4.0);                 // 5
f64 one = std::math::Sin(std::math::Pi / 2.0);
```

## Random numbers

`std::random` has four generators. Each factory returns an `Option` of its
generator struct; seed `0` (the default) seeds it from the system's entropy,
any other seed reproduces the same sequence.

| Factory | Generator struct | Notes |
|---|---|---|
| `Rng()` | `SplitMix64Type` | system-seeded default |
| `SplitMix64(seed)` | `SplitMix64Type` | fast, 64-bit state |
| `PCG32(seed)` | `PCG32Type` | 32-bit output |
| `Xoshiro256PP(seed)` | `Xoshiro256PPType` | 256-bit state, long period |
| `ChaCha12(seed)` | `ChaCha12Type` | system-seeded: fit for secrets |

```sic
auto g = std::random::Rng() else return 1;
u64 x = g.gen64();                                  // also g.gen32()
u8 key[32];
auto n = std::random::GetRandom(key, 32) else return 1;   // system entropy
```

A generator is a plain value: separate instances are independent (use one per
thread), and copying one duplicates its sequence. An explicit `u64` seed gives
at most 64 bits of entropy.

## Filesystem

`std::fs`: `MkDir(path, mode = 0755)`, `RmDir`, `Unlink`, `Rename(from, to)`,
`ChDir`, `Exists`, `IsFile`, `IsDir` (all `bool`), `GetCwd()` (`Option<string>`)
and `ReadDir(path)` (`Option<list<string>>`, `None` if it cannot be opened):

```sic
auto names = std::fs::ReadDir(".") else return 1;
for (string name : names.values) std::Println("{}", name);
```

## Networking

`std::net` provides IPv4 TCP sockets. A `Socket` owns its descriptor and
closes it when it goes out of scope (or on `Close(&s)`):

```sic
auto l = std::net::TcpListen("127.0.0.1", 8080) else return 1;
auto c = std::net::TcpConnect("127.0.0.1", 8080) else return 1;
auto a = std::net::Accept(&l) else return 1;
u8 msg[6] = "hello";
std::net::Write(&c, msg, 6);                        // writes all bytes or -1
u8 buf[64];
isize n = std::net::Read(&a, buf, 64);              // 0 at EOF
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
