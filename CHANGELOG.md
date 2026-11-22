# Changelog

## 0.3.0 (unreleased)

### Back ends

- An optional **LLVM back end** (`crates/sic-llvm`, through inkwell, in process):
  `./build.sh --backend llvm`, `cranelift,llvm` or `all`. The back end is picked at
  run time with `-fbackend=` or `$SIC_BACKEND`; `-print-backends` lists them. The
  first one given to `--backend` is the default. See [doc/backends.md](doc/backends.md).
- `--version`, `.comment` and `DW_AT_producer` name the back end that compiled.
- LLVM: `-g` (DWARF lines, functions, parameters, locals and their types).
- LLVM: inline assembly is LLVM's own on x86-64 too (not sic's out-of-line
  helpers, whose plain `ret`s objtool reported under return thunks);
  `noreturn` is passed on; definitions in a PIE are reached directly.
- LLVM: `-S` is LLVM's own assembly, inline asm as written (Linux's
  `asm-offsets.h` and `devicetable-offsets.h` come from it).
- LLVM: `-fno-delete-null-pointer-checks` (Linux) is honoured.
- LLVM: `__attribute__((target("avx2")))` gives the function its own CPU
  features (`arch=` its CPU), and sic does not inline it into a caller of
  another target; a read-write `"+x"` operand on a `vector_size` value, of
  any width (QEMU's `util/bufferiszero.c`).
- LLVM: a `static` that only inline asm names is kept, as on Cranelift;
  `-g` no longer panics in a debug build of sic (on a local variable).
- `-m32`: `.S` files are assembled as i386; `sizeof(long)` and pointer
  sizes in attribute arguments (`aligned(2 * sizeof(long))`) are i386's.
- Fixed: a `switch`'s `default:` ending in `__builtin_unreachable()` ran on
  into the code after the switch.
- The inliner leaves calls of `noreturn` functions alone, and judges a
  function by its size after its own inlining.
- LLVM: an asm input tied to a narrower output (`"=c"(int)`, `"0"(ptr)`)
  widens the output, as clang does; the input was cut to the output's width
  (Linux's `put_user` lost the user address's upper half: exec failed with
  EFAULT).
- LLVM: `asm goto` with outputs (Linux's `unsafe_get_user`): which label was
  taken is an output of the asm, not a store through a pointer that an
  output's register could overwrite.
- LLVM: Linux's mitigations, as clang: return thunks, retpolines through the
  external thunks with the `cs` prefix, the stack protector with Linux's guard and
  `no_stack_protector`, call padding (`-fpatchable-function-entry`, `notrace`),
  `-mharden-sls`, `-fcf-protection`, `-fzero-call-used-regs`, `-mstack-alignment`.
- An unknown `-O` level is an error (it was `-O0`); `-Ofast` optimizes as `-O3`,
  `-Og` and a bare `-O` as `-O1`.
- LLVM: non-PIC code reaches symbols without the GOT, `-mno-red-zone` is honoured,
  imports are declared at their size, `-O1` is LLVM's O1, and at `-O0`
  `always_inline` functions are inlined and constant branches folded, as clang does.
- **`-m32`**: i386 with the LLVM back end whenever sic has it, whatever the default
  (the System V i386 ABI and data model, i386 macros, inline assembly as LLVM's own,
  `asm goto` included). Without LLVM it is handed to clang or gcc, as before.

### C

- A block-scope `static __thread` / `_Thread_local` variable is one per thread
  (every thread shared one).
- **`_Complex`** types: imaginary constants, arithmetic (libgcc's `__mulXc3` and
  `__divXc3`, as GCC), conversions, `__real__`/`__imag__`, `__builtin_complex`,
  constant initializers, and the System V calling convention, including
  `_Complex long double` returns in x87 registers. They were compiled as a plain
  `double`.
- **Variable-length arrays** on the stack (LLVM; Cranelift: up to 512 bytes, `calloc`
  beyond), and `alloca` on LLVM. They were `calloc`ed.
- **Symbol visibility**: the attribute, `#pragma GCC visibility` and
  `-fvisibility=`, on both back ends.
- `volatile` accesses happen as written, through pointers, members, typedefs,
  `typeof` and bit-fields.
- Static initializers: floating constant expressions, `sizeof`/`_Alignof` of a
  local, a `const` object's value, `__builtin_types_compatible_p`.
- Fixes:
  - an array parameter in a function type is a pointer;
  - `typeof` of a function name is its function type;
  - a static assertion in a function sees the function's names;
  - unary `+` keeps a negative zero;
  - every object of an array or struct is constructed;
  - `bigint` literals past `long`;
  - `sizeof` of a string literal is its array's (it was a pointer's 8);
  - `\u` and `\U` escapes name a character: UTF-8 in a narrow literal, a
    surrogate pair in `u""` (they were read as the letter);
  - `u'x'` is a `char16_t`, `U'x'` a `char32_t` and `L'x'` a `wchar_t` (they
    were all `int`);
  - `_Generic` and `__builtin_types_compatible_p` tell `long` from `long long`
    (and `int` from `long` on i386), pointers to them too: they were one
    type, and `long long` took the `long` association.
- `-fshort-wchar` (Linux): `wchar_t` and `L""` are 16-bit `unsigned short`,
  with GCC's macros. A wide literal initializing an array of narrower
  units no longer writes past it: Linux's EFI code overwrote its saved
  registers, and the Cranelift kernel failed in `do_one_initcall`.
- Preprocessor: `L'x'`, `u'x'`, `U'x'` (and C23 `u8'x'`) with every escape in
  `#if`; `-ffreestanding` makes `__STDC_HOSTED__` 0.
- Driver: an input without a source suffix is a linker input, as with gcc (libtool's
  `.lo`); `-x <language>` is honoured.
- What sic accepts but does not do is a warning, which plain `-Werror` leaves a
  warning (`-Werror=<name>` makes it an error):
  - `-Wignored-option`: the mitigation and hardening options (`-fstack-protector*`,
    `-mfunction-return=`, `-mindirect-branch=`, `-fcf-protection`,
    `-fpatchable-function-entry=`, `-fsanitize=`, …), and `-g` with LLVM;
  - `-Wunsupported-attribute`: a function defined `ms_abi`, and on i386 `regparm`,
    `stdcall`, `fastcall`;
  - `-Wunsupported-alloca`: `alloca` on Cranelift (LLVM's is on the stack).

### SIC

- Closures: a plain function is wrapped where a closure is wanted; a lambda's
  result type comes from its `Fn`.
- Constants fold at every level, strings and ternaries too.
- A second constructor, destructor or same-named method is an error.
- The last owner of a reference-counted struct clears its whole count
  pointer, not the low 4 bytes of it.
- A backward `goto` across a move of an object declared before its label
  runs the cleanups after the label: it skipped one.
- `string`, `list`, `dict`, `set`, tuple and `stringbuilder` counts are atomic, as struct,
  closure and `new` counts were: sharing one between threads freed it twice.
  A weak reference and the last strong owner no longer race to free a
  container's handle.
- **Async functions run as tasks**: `async`/`await` used to run the function
  at once and keep its result in one 64-bit slot (a string, struct or list
  result was garbage, awaiting twice freed the task twice). Now a call makes a
  task, which a cooperative scheduler runs on a stack of its own (256 KiB with
  a guard page) when the thread waits; `await` gives a copy of the result, and
  `Task<T>` handles are counted like structs with destructors. Async struct
  methods and generic functions work. `art` is the scheduler's API —
  `yield_now`, `sleep(ms)` (new), `spawn`, `run`, `pending` — and its
  coroutines and async tasks share the one scheduler, which the program holds
  (a module's async functions run on it too). Each thread has its own.
- An `Option` read out of a list or dict binds, assigns and iterates like any
  other (`Option<int> x = l[0];`, `for (Option<int> o : l.values)` were
  compile errors); a stored bare `None` no longer crashes, and a missing dict
  key reads as `None`.
- A `bigint` or `fixed` list or dict element is the container's own copy: it
  was the source's block and was freed under the container; a number stored
  into a `fixed` element (`d[1] = 2.5`) kept the double's bits as an address;
  and a `fixed` element type kept its digits (it came back as `any`).
- Task stacks are registered with valgrind (its client request, a no-op
  outside it), which took a switch to one for a frame of megabytes and
  reported uninitialised values.
- An enum owning its payload (`Option<string>`) is owned once wherever it
  goes: a ternary of them copied its arms without a reference (a call's
  payload leaked), a call's passed straight to a function was never released,
  and a list or dict element was a plain copy — sharing a local's payload
  without a reference (freed under the list) and never releasing a call's.
- **`?.` method calls**: `user?.name()` calls the method when `user` is a
  non-null pointer or a present `Option`, else gives the zero value of its
  result (`None` for an `Option`); the arguments are evaluated only when it
  is called.
- A generic function's call has the result type its type arguments give: it
  was taken for an `int` (`auto d = id(2.5)` was 2, and `std::Println` read a
  string result as a number).
- A bare variant constructor builds the enum its context expects: `Some(x)`
  into an `Option<string>` built whichever `Option` instance was registered
  first (`Option<i64>`) and crashed on reading it.
- A temporary made in one arm of `?:`, or on the elvis `?:`'s right side, is
  released in that arm: when the other arm ran, a string was released
  uninitialized (a crash) and a struct's destructor ran on garbage. A call's
  `Option` used by `?:` or `?.` is released (it leaked its payload).
- A reference-counted struct gets its count at its first copy: one never
  copied allocates nothing for it (binarytrees made twice the allocations
  of C).

### Tools

- `check.sh` builds both back ends and runs every suite with each, the compile
  tests in parallel, and `moduletest.sh` too.
- `setversion.sh` takes a pre-release suffix (`0.3.0-dev`).

### Known limitations

- `-g`: lines of the main source file only, without columns; no global variables;
  Cranelift's has no variables. The Cranelift back end ignores Linux's mitigation
  options (it warns).
- `_Generic` cannot tell a `long` literal (`1L`) from a `long long` one (`1LL`):
  for such an operand the first of the two matches. Variables, members,
  casts, typedefs and function results are told apart.
- `long double`, `_Complex long double` included, is computed in double precision;
  complex values cannot be passed through `...`.
- `-m16` and `-mx32` are handed to clang or gcc.
