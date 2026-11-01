# Back ends

sic lowers to its own IR and hands that to a back end, which returns an object file.
Which back ends exist is decided when sic is built, which one runs when it is run:

    ./build.sh release --backend all    # cranelift (default), llvm, llvm,cranelift, all
    sic -print-backends                 # what this sic has, the default first
    sic -fbackend=llvm -O2 a.c          # or $SIC_BACKEND; the option wins

Cranelift is built in by default and stays the default when both are. LLVM is built
only when asked for: it needs LLVM 21 to build, and a sic with it needs `libLLVM` to
start at all, whichever back end it then uses. `SIC_DUMP_LLVM=1` prints the module.

## LLVM

`crates/sic-llvm`, through inkwell, in process: no LLVM tool is run. sic's own IR
passes run first, then `default<O2>` (`default<Os>` for `-Os`/`-Oz`).

Objects of both back ends link together, and `std` built with one works with code
built with the other.

Differences from Cranelift:

- `setjmp` with a `volatile` local is correct at `-O2`; Cranelift's is not.
- `long double` is a real `x86_fp80` at memory and calls, but arithmetic is still
  sic's `double`, as the IR computes in `double`.
- A NaN computed from constants may have the other sign (IEEE leaves it open): the
  tests with a `.skip-llvm` marker pin x86's at `-O1` and above.

Not there yet: `-g` is ignored, and the kernel's flags (return thunks, retpolines,
`-mcmodel=kernel` details, `-mno-red-zone`, stack protector) are not passed on.
