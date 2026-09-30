SIC ?= ../siccomp/target/release/sic
CC  ?= cc

.PHONY: all clean

all: sic-cpp

# Build in one step: `import std;` is resolved and linked at compile time. A
# two-step `-c` to .o then a separate link cannot auto-link std — the .o no longer
# records the module dependency, so `std_*` come up undefined at link.
sic-cpp: src/main.sic
	$(SIC) src/main.sic -g -O2 -o sic-cpp

clean:
	rm -f sic-cpp
