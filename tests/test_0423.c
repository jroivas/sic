/* The bool bit-field fix of test_0422 for a struct DEFINED SEPARATELY from its
 * typedef (QEMU decode-new.h: `typedef struct X86OpEntry X86OpEntry;` +
 * `struct X86OpEntry { … bool is_decode:1; };`), which is lowered by another
 * path that still used an i1 storage unit (-O2 dropped `e->is_decode = false`;
 * qemu-system-i386 still ran away). Returns 42. */
#include <stdbool.h>
typedef struct Entry Entry;
typedef void (*DecodeFunc)(Entry *);
struct Entry {
    DecodeFunc decode;
    unsigned char op0;
    unsigned check:16;
    unsigned intercept:8;
    bool has_intercept:1;
    bool is_decode:1;
};
static void last(Entry *e) { e->op0 = 7; }
__attribute__((noinline)) static int run(Entry *e) {
    int loops = 0;
    while (e->is_decode) {
        e->is_decode = false;
        e->decode(e);
        if (++loops >= 10) return -1;
    }
    return loops;
}
int main(void) {
    struct Entry e = { .decode = last, .check = 0xBEEF, .intercept = 3, .has_intercept = true, .is_decode = true };
    if (run(&e) != 1 || e.is_decode || !e.has_intercept || e.op0 != 7 || e.check != 0xBEEF) return 1;
    return 42;
}
