INC_FILES := inc/*.h
SRC_FILES := src/*.c
#SRC_FILES = src/main.c src/scan.c src/parse.c
CFLAGS = -std=c99 -Wall -Werror -pedantic -O3 -fPIC -Iinc/

build/sic: build build/libsic.so
	$(CC) $(CFLAGS) -o build/sic main.c build/libsic.so

build/libsic.so: $(INC_FILES) $(SRC_FILES)
	$(CC) $(CFLAGS) -shared -o build/libsic.so $(SRC_FILES)

test: build/sic unittest
	CC=build/sic HOSTCC=$(CC) tests/runtest.sh build

testllvm: build/sic
	CC=build/sic HOSTCC=$(CC) tests/runtest.sh build llvm

testc:
	CC="$(CC) -c -x c" HOSTCC=$(CC) tests/runtest.sh build

tests: test

buildtest: build/sic
	build/sic --dump-tree tests/test_$(TEST).sic -o build/test_$(TEST).sic.ir
	cat build/test_$(TEST).sic.ir

runtest: buildtest
	llvm-as build/test_$(TEST).sic.ir
	llc -O0 -relocation-model=pic -filetype=obj build/test_$(TEST).sic.ir.bc -o build/test_$(TEST).ir.o
	$(CC) build/test_$(TEST).ir.o -o build/test_$(TEST).ir.bin -lm
	build/test_$(TEST).ir.bin ; echo $$? || true

unittest:
	make -C tests/unit

build:
	mkdir -p build

clean:
	rm -rf build

.PHONY: test builddir clean runtest buildtest
