INC_FILES := inc/*.h
SRC_FILES = src/main.c src/scan.c
CFLAGS = -O3 -Iinc/

build/sic: build $(INC_FILES) $(SRC_FILES)
	$(CC) -o build/sic $(SRC_FILES) $(CFLAGS)

test: build/sic
	CC=build/sic tests/runtest.sh build

testc:
	CC=$(CC) tests/runtest.sh build

build:
	mkdir -p build

clean:
	rm -rf build

.PHONY: test builddir clean
