# Changelog

## 0.3.0 (unreleased)

### Back ends

- An optional **LLVM back end** (`crates/sic-llvm`, through inkwell, in process):
  `./build.sh --backend llvm`, `cranelift,llvm` or `all`. The back end is picked at
  run time with `-fbackend=` or `$SIC_BACKEND`; `-print-backends` lists them. The
  first one given to `--backend` is the default. See [doc/backends.md](doc/backends.md).
- `--version`, `.comment` and `DW_AT_producer` name the back end that compiled.
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
  - `bigint` literals past `long`.
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

### Tools

- `check.sh` builds both back ends and runs every suite with each, the compile
  tests in parallel, and `moduletest.sh` too.
- `setversion.sh` takes a pre-release suffix (`0.3.0-dev`).

### Known limitations

- The LLVM back end ignores `-g`; the Cranelift back end ignores Linux's mitigation
  options (both warn).
- `_Generic` and `__builtin_types_compatible_p` cannot tell `int` from `long` on i386
  (nor `long` from `long long` on x86-64).
- `long double`, `_Complex long double` included, is computed in double precision;
  complex values cannot be passed through `...`.
- `-m16` and `-mx32` are handed to clang or gcc.
