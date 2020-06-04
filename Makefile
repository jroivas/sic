INC_FILES := inc/*.h
SRC_FILES := src/*.c
#SRC_FILES = src/main.c src/scan.c src/parse.c
CFLAGS = -std=c99 -Wall -Werror -pedantic -O3 -fPIC -Iinc/

build/sic: build build/libsic.so
	$(CC) $(CFLAGS) -o build/sic main.c build/libsic.so

build/libsic.so: $(INC_FILES) $(SRC_FILES)
	$(CC) $(CFLAGS) -shared -o build/libsic.so $(SRC_FILES)

test: build/sic unittest
	CC=build/sic HOSTCC=$(CC) tests/compiletest.sh build

testsic: build/sic
	CC=build/sic HOSTCC=$(CC) tests/compiletest.sh build llvm

testc:
	CC="$(CC) -c -x c" HOSTCC=$(CC) tests/compiletest.sh build

tests: test

compiletest: build/sic
	build/sic --dump-tree tests/test_$(TEST).sic -o build/test_$(TEST).sic.ir
	cat build/test_$(TEST).sic.ir

buildtest: compiletest
	llvm-as build/test_$(TEST).sic.ir
	llc -O0 -relocation-model=pic -filetype=obj build/test_$(TEST).sic.ir.bc -o build/test_$(TEST).ir.o
	$(CC) build/test_$(TEST).ir.o -o build/test_$(TEST).ir.bin -lm

runtest: buildtest
	build/test_$(TEST).ir.bin ; echo $$? || true

unittest:
	make -C tests/unit

build:
	mkdir -p build

clean:
	rm -rf build

testall: test testsic

all: build/sic

help:
	@echo "SIC - Slighty Improved C"
	@echo ""
	@echo "make targets:"
	@echo " help             This help"
	@echo " test             Compilation with sic and unittest"
	@echo " unittest         Run unit tests"
	@echo " compiletest      Test compile with sic, define TEST env"
	@echo " buildtest        Test build one test with sic, define TEST env"
	@echo " runtest          Test build and run one test with sic, define TEST env"
	@echo " testsic          Test build all with sic"
	@echo " testc            Test build all with $$CC"
	@echo " testall          Test all sic related"
	@echo ""
	@echo "Env variable TEST should contain test number, eg. 0012"

.PHONY: help test clean runtest buildtest compiletest testsic testc unittest testall all
