SIC ?= ../siccomp/target/release/sic

.PHONY: all clean test

all: sic-fmt

# One step: `import std;` is resolved and linked at compile time.
sic-fmt: src/main.sic
	$(SIC) src/main.sic -g -O2 -o sic-fmt

test: sic-fmt
	./test.sh

clean:
	rm -f sic-fmt
