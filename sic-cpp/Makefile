SIC ?= ../siccomp/target/release/sic
CC  ?= cc

.PHONY: all clean

all: sic-cpp

# The preprocessor is the `sicpp` module (lib/); the command is a thin main over it,
# linked statically, so a later change to libstd cannot break it.
sic-cpp: src/main.sic lib/sicpp.sic
	$(SIC) -g -O2 --emit-crate lib
	$(SIC) src/main.sic -I lib -static -g -O2 -o sic-cpp

clean:
	rm -f sic-cpp lib/libsicpp.a lib/libsicpp.so lib/module_sicpp.*
