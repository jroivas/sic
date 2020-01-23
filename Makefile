INC_FILES := inc/*.h
SRC_FILES = src/main.c src/scan.c src/parse.c
CFLAGS = -std=c99 -Wall -Werror -pedantic -O3 -Iinc/

build/sic: build $(INC_FILES) $(SRC_FILES)
	$(CC) $(CFLAGS) -o build/sic $(SRC_FILES)

test: build/sic
	CC=build/sic tests/runtest.sh build

testc:
	CC=$(CC) tests/runtest.sh build

tests: test

build:
	mkdir -p build

clean:
	rm -rf build

.PHONY: test builddir clean
