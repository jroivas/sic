SRCS := $(wildcard test_*.c)
OBJS := $(addsuffix .o,$(basename $(SRCS)))
TARGETS := $(basename $(SRCS))
CFLAGS := -std=c99 -I../../inc $(CFLAGS)

all: test

test: runtest libsic.so
	LD_LIBRARY_PATH=. ./runtest

libsic.so:
	make -C ../.. build/libsic.so
	cp -f ../../build/libsic.so .
	ln -sf libsic.so libsic.so.0

test.o: test.c test.h

#runtest: test.o $(OBJS) libsic.so
runtest: test.o $(SRCS) libsic.so
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

%.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f runtest libsic.so libsic.so,* *.o

.PHONY: test runtest libsic.so
