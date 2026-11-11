# Back ends

sic lowers to its own IR and hands that to a back end, which returns an object file.
Which back ends exist is decided when sic is built, which one runs when it is run:

    ./build.sh release --backend cranelift,llvm   # cranelift (the default), llvm, a list, all
    sic -print-backends                           # what this sic has, the default first
    sic -fbackend=llvm -O2 a.c                    # or $SIC_BACKEND; the option wins

The first back end in `--backend` is the default: `cranelift,llvm` compiles with
Cranelift unless asked, `llvm,cranelift` with LLVM. `all` is `cranelift,llvm`, and a
build without `--backend` has Cranelift alone. LLVM is built only when asked for: it
needs LLVM 21 to build, and a sic with it needs `libLLVM` to start at all, whichever
back end it then uses. `SIC_DUMP_LLVM=1` prints the module.

`sic --version` names the back end a compile would use (the option, then
`$SIC_BACKEND`, then the default). A binary records what built it, in `.comment`,
once per distinct string, so both back ends show when both were used (and in
DWARF's `DW_AT_producer` under `-g`):

    $ readelf -p .comment a.out
      sic 0.3.0 (preprocessor: sic-cpp, backend: llvm)

## LLVM

`crates/sic-llvm`, through inkwell, in process: no LLVM tool is run. sic's own IR
passes run first, then LLVM's: `default<O1>` at `-O1`, `default<O2>` at `-O2` and
`-O3`, `default<Os>` at `-Os`/`-Oz`. At `-O0` it still inlines `always_inline`
functions and folds branches on constants, as clang does (an inline-asm `"i"`
operand is a constant only then, and asm in an arm a constant `switch` rules out is
not assembled).

Objects of both back ends link together, and `std` built with one works with code
built with the other.

Differences from Cranelift:

- A variable-length array is on the stack, released at the end of its scope, and
  `alloca` too, as with GCC. Cranelift has no dynamic stack allocation: a VLA of up
  to 512 bytes takes a fixed stack slot, a larger one `calloc`, and `alloca` is
  `malloc`ed and never freed.
- `setjmp` with a `volatile` local is correct at `-O2`; Cranelift's is not.
- `long double` is a real `x86_fp80` at memory and calls, but arithmetic is still
  sic's `double`, as the IR computes in `double`.
- A NaN computed from constants may have the other sign (IEEE leaves it open): the
  tests with a `.skip-llvm` marker pin x86's at `-O1` and above.
- Non-PIC code reaches every symbol directly (no GOT), and a hidden symbol is
  reached without one under PIC too, as Linux's link and vDSO need. In a
  position-independent executable (the default, `-fpie`) a definition is reached
  directly too, as with clang.
- Inline assembly is LLVM's own, the GCC template and constraints translated as
  clang does (`asm goto` too). Cranelift has none: there a statement runs out of
  line, in a helper function the call stands for, and vector-register (`"x"`)
  operands are not supported.
- `-S` writes LLVM's own assembly, inline asm in it as written. Cranelift's is
  the object written back as directives (`.byte`, `.reloc`), with the inline
  asm statements as text.
- A `noreturn` function (`_Noreturn`, `__attribute__((noreturn))`) is one to
  LLVM: nothing follows a call of it.

Linux's mitigation and hardening options are LLVM's, as with clang: return thunks
(`-mfunction-return=thunk-extern`), retpolines (`-mretpoline[-external-thunk]`,
`-mindirect-branch=`, `-mindirect-branch-cs-prefix`), the stack protector
(`-fstack-protector[-strong|-all]`, `-mstack-protector-guard[-reg|-symbol|-offset]=`,
the `no_stack_protector` attribute), call padding (`-fpatchable-function-entry=`,
`patchable_function_entry`, so `notrace`), `-mharden-sls=`, `-fcf-protection=`,
`-fzero-call-used-regs=` and `-mstack-alignment=`. Cranelift has none of them:
with it, sic warns that they are ignored (`-Wignored-option`), as for any option it
does not implement.

`-g` gives DWARF for the lines, the functions, their parameters and locals, and
their types (scalars, pointers, arrays, structs; a union without its members), so
a debugger breaks, steps, shows a backtrace and prints variables. Cranelift's
`-g` has the lines and functions, not the variables. Lines are those of the main
source file only, without columns (code from a header shows its line in the main
file), and global variables are not described yet.

## `-m32`

i386 code is compiled with the LLVM back end whenever sic has it, whatever the
default. A sic without LLVM hands `-m32` (and `-m16`, `-mx32` in any case) to clang or
gcc on `PATH`, as before.

- The System V i386 ABI: 4-byte `long`, pointers and `size_t`; `long long` and
  `double` 4-aligned in structs; a 12-byte `long double`; every struct passed on the
  stack and returned through the hidden pointer the callee pops (`_Complex float`
  in `edx:eax`, as clang); `va_list` a `char *`. The predefined macros are i386's
  (`__i386__`, `__ILP32__`, …), with SSE2 floating point as clang's `pentium4`.
- Inline assembly is LLVM's own, the GCC template and constraints translated as
  clang does, `asm goto` included; file-scope `asm` goes into the module.
- The system C driver links (`cc -m32`), so 32-bit libraries must be installed
  (`gcc-multilib`).

Not there yet: `_Generic` and `__builtin_types_compatible_p` cannot tell `int` from
`long` (both are the same 32-bit type in sic's IR, as `long` and `long long` are on
x86-64), and the SIC language's `std` is not built for i386.
