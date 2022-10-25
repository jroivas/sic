# SIC - Slightly Improved C

Slightly Improved C is a programming language that borrows a lot from C,
but is not afraid to introduce breaking changes in order to improve it.


To read more about the design see [sic.md](sic.md)
REMARK: Features of sic is not currently implemented, focusing to implement minimal C compiler for now.


## Dependencies

You need to have bootstrapping C compiler (both gcc and clang should work).
For compiling with sic you need LLVM installed. Plus a linker.

System libc with headers is needed in order to compile most of the code.
SIC compiler should be able to parse and produce proper code with most headers.


## Build and run

There's custom [Makefile] to perform most of the builds.

First start with just `make` or `make test`.
That will compile sic and perform unit tests, plus compile test snippets under tests folder.

In order to also build and run the tests do:

    # Compile and one test
    make runtest TEST=0020

    # Compile and run all tests, check result
    make testsic

To just compile a test:

    make compiletest TEST=0020


## Output and manual steps

Output of sic compiler is by default compiled LLVM bitcode.
That can be compiled to native binary with `llc`.
In case one needs bitcode can be disassembled with `llvm-dis`.

Thus manual steps would be:

    LD_LIBRARY_PATH=build/: build/sic tests/test_0001.sic -o build/test_0001.sic.bc
    llc -relocation-model=pic -filetype=obj build/test_0001.sic.bc -o build/test_0001.o
    # Linking with cc or any other method that suits you
    cc build/test_0001.o -o build/test_0001.bin -lm


## Roadmap

 - Rework code generator
 - Other missing C features to sic make self hosting
 - Start implementing [sic features](sic.md)
