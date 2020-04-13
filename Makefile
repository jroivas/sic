INC_FILES := inc/*.h
SRC_FILES := src/*.c
#SRC_FILES = src/main.c src/scan.c src/parse.c
CFLAGS = -std=c99 -Wall -Werror -pedantic -O3 -Iinc/

build/sic: build $(INC_FILES) $(SRC_FILES)
	$(CC) $(CFLAGS) -o build/sic $(SRC_FILES)

test: build/sic
	CC=build/sic tests/runtest.sh build

testllvm: build/sic
	CC=build/sic tests/runtest.sh build llvm

testc:
	CC="$(CC) -c -x c" tests/runtest.sh build

tests: test

runtest: build/sic
	build/sic --dump-tree tests/test_$(TEST).sic -o build/test_$(TEST).sic.ir
	cat build/test_$(TEST).sic.ir

runllvmtest: runtest
	llvm-as build/test_$(TEST).sic.ir
	llc -O0 -relocation-model=pic -filetype=obj build/test_$(TEST).sic.ir.bc -o build/test_$(TEST).ir.o
	gcc build/test_$(TEST).ir.o -o build/test_$(TEST).ir.bin -lm
	build/test_$(TEST).ir.bin || true

build:
	mkdir -p build

clean:
	rm -rf build

.PHONY: test builddir clean runtest runllvmtest
