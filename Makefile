INC_FILES := inc/*.h
SRC_FILES := src/*.c
CFLAGS_RELEASE = -std=c99 -Wall -Werror -pedantic -O3 -fPIC -Iinc/
CFLAGS_DEBUG = -std=c99 -Wall -Werror -pedantic -g -O0 -fPIC -Iinc/
CFLAGS = $(CFLAGS_DEBUG)

all: build/sic build/sic-static

build/sic-static: build
	$(CC) $(CFLAGS) -o build/sic-static -static main.c $(SRC_FILES)

build/sic: build build/libsic.so main.c
	$(CC) $(CFLAGS) -o build/sic -L build/ main.c build/libsic.so.0

build/libsic.so: $(INC_FILES) $(SRC_FILES)
	$(CC) $(CFLAGS) -shared -Wl,-soname,libsic.so.0 -o build/libsic.so.0.1 $(SRC_FILES)
	ln -sf libsic.so.0.1 build/libsic.so.0
	ln -sf libsic.so.0 build/libsic.so

test: build/sic build/tests unittest
	LD_LIBRARY_PATH=build/: CC=build/sic HOSTCC=$(CC) tests/compiletest.sh build/tests

testsic: build/sic build/tests
	LD_LIBRARY_PATH=build/: CC=build/sic HOSTCC=$(CC) tests/compiletest.sh build/tests llvm

testc: build/tests
	CC="$(CC) -c -x c -DNULL=0" HOSTCC=$(CC) tests/compiletest.sh build/tests

tests: test

compiletest_notree: build/sic build/tests
	LD_LIBRARY_PATH=build/: build/sic tests/test_$(TEST).sic -o build/tests/test_$(TEST).sic.ir
	cat build/tests/test_$(TEST).sic.ir

compiletest: build/sic build/tests
	LD_LIBRARY_PATH=build/: build/sic --dump-tree tests/test_$(TEST).sic -o build/tests/test_$(TEST).sic.ir
	cat build/tests/test_$(TEST).sic.ir

buildtest: compiletest build/tests
	llvm-as build/tests/test_$(TEST).sic.ir
	llc -O0 -relocation-model=pic -filetype=obj build/tests/test_$(TEST).sic.ir.bc -o build/tests/test_$(TEST).ir.o
	$(CC) build/tests/test_$(TEST).ir.o -o build/tests/test_$(TEST).ir.bin -lm

runtest: buildtest build/tests
	build/tests/test_$(TEST).ir.bin ; echo $$? || true

build/scantool: tools/scantool.c build/libsic.so
	$(CC) $(CFLAGS) -o build/scantool -L build/ tools/scantool.c build/libsic.so.0

tools: build/scantool

unittest:
	make -C tests/unit

build:
	mkdir -p build

build/tests: build
	mkdir -p build/tests

clean:
	rm -rf build

testall: test testsic

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
