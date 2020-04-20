SRCS := $(wildcard test_*.c)
OBJS := $(addsuffix .o,$(basename $(SRCS)))
TARGETS := $(basename $(SRCS))
CFLAGS := -std=c99 -I../../inc $(CFLAGS)

test: runtest
	./runtest

buffer.o: ../../src/buffer.c
	$(CC) -c $(CFLAGS) $< -o $@

scan.o: ../../src/scan.c
	$(CC) -c $(CFLAGS) $< -o $@

test.o: test.c test.h

runtest: test.o $(OBJS) buffer.o scan.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

%.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

.PHONY: test runtest
