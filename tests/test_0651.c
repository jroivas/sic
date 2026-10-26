// Non-PIC code (-fno-PIE, Linux's -mcmodel=kernel): direct calls and
// RIP-relative data (no GOT), and 64-bit constants that do not fit an
// immediate loaded from read-only data instead of a constant pool inside the
// code — Cranelift put them in .text, where Linux's objtool could not decode
// past them (0x20c49ba5e353f7cf, the ÷1000 multiplier, in init/main.o).
#include <stdio.h>
#include <string.h>

unsigned long fnv(const char *s) {
    unsigned long h = 0xcbf29ce484222325UL;
    while (*s) { h ^= (unsigned char)*s++; h *= 0x100000001b3UL; }
    return h;
}
unsigned long div1000(unsigned long x) { return x / 1000; }
long rem7(long x) { return x % 1000000007L; }
long mask(long x) { return x & 0x7fff0000ffff0000L; }
int is_magic(unsigned long x) { return x == 0x123456789aUL; }
void put(unsigned long *p) { *p = 0xdeadbeefcafeUL; }

int main(void) {
    int ok = 0;
    if (fnv("a") == 0xaf63dc4c8601ec8cUL) ok++;
    if (fnv("") == 0xcbf29ce484222325UL) ok++;
    if (div1000(123456789012UL) == 123456789UL) ok++;
    if (rem7(-3000000025L) == -4L) ok++;
    if (mask(-1L) == 0x7fff0000ffff0000L) ok++;
    if (is_magic(0x123456789aUL) && !is_magic(1)) ok++;
    unsigned long v; put(&v);
    if (v == 0xdeadbeefcafeUL) ok++;
    char buf[32];
    snprintf(buf, sizeof buf, "%lx", v);           // a call into libc
    if (!strcmp(buf, "deadbeefcafe")) ok++;
    return ok + 34;
}
