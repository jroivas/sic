# SIC - Slightly Improved C

Slightly Improved C is a programming language that borrows a lot from C,
but is not afraid to introduce breaking changes in order to improve it.


To read more about the design see [sic.md](sic.md)


## Dependencies

You need to have bootstrapping C compiler (both gcc and clang should work).
For compiling with sic you need LLVM installed. Plus a linker.

System libc with headers is not mandatory but needed by few tests.


## Build and run

SIC uses meson and ninja for builds. Make sure you install those first. Then:

    mkdir build
    cd build
    meson setup ..
    ninja

To make static build instead issue this after setup step:

    meson configure -Ddefault_library=static


There's useful scripts in the scripts folder, for example to compile, build and
run tests. This assume "sic" has been built and found on current folder:

    ../scripts/compile.sh ../tests/test_0014.sic
    ../scripts/build.sh ../tests/test_0014.sic
    ../scripts/build_bin.sh ../tests/test_0014.sic
    ../scripts/run-test.sh ../tests/test_0014.sic

There's some environment variables to control the output of scripts:

    VERBOSE=1
    DUMP_IR=1
    DUMP_TREE=1

To run all the tests in a batch run:

    ../scripts/test-all.sh

## Output and manual steps

Output of sic compiler is by default LLVM IR in text format.
That can be assembled with `llvm-as` and compiled to binary with `llc`.

Thus manual steps would be:

    ./sic ../tests/test_0001.sic -o test_0001.sic.ir
    llvm-as test_0001.sic.ir
    llc -relocation-model=pic -filetype=obj test_0001.sic.ir.bc -o test_0001.ir.o
    # Linking with cc or any other method that suits you
    cc test_0001.ir.o -o test_0001.ir.bin -lm


## Roadmap

 - Full support for function typedefs
 - Functions as variables
 - Other missing C features to sic make self hosting
 - Start implementing [sic features](sic.md)
