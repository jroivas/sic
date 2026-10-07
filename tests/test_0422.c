/* `bool x:1` bit-fields are stored in a byte unit: as i1 their masks were
 * 1-bit, -O2's algebraic pass dropped `e->is_decode = false` as a no-op, and
 * QEMU's decode loop `while (e->is_decode) { e->is_decode = false; e->decode(e); }`
 * never ended (qemu-system-i386 ate all memory). Returns 42. */
#include <stdbool.h>
typedef struct Entry {
    void (*decode)(struct Entry *);
    unsigned char op0;
    unsigned check:16;
    unsigned intercept:8;
    bool has_intercept:1;
    bool is_decode:1;
    bool mid:1;
    unsigned tail:5;
} Entry;
static void last(Entry *e) { e->op0 = 7; }           /* leaves is_decode alone */
__attribute__((noinline)) static int run(Entry *e) {
    int loops = 0;
    while (e->is_decode) {
        e->is_decode = false;
        e->decode(e);
        if (++loops >= 10) return -1;
    }
    return loops;
}
__attribute__((noinline)) static void toggle(Entry *e) { e->mid = !e->mid; e->has_intercept = false; }
int main(void) {
    Entry e = { .decode = last, .check = 0xBEEF, .intercept = 3, .has_intercept = true, .is_decode = true, .tail = 21 };
    if (run(&e) != 1 || e.is_decode || !e.has_intercept || e.op0 != 7) return 1;
    toggle(&e);
    if (!e.mid || e.has_intercept || e.is_decode || e.tail != 21 || e.check != 0xBEEF || e.intercept != 3) return 2;
    toggle(&e);
    if (e.mid) return 3;
    e.is_decode = 1; e.is_decode = 0;
    if (e.is_decode || e.tail != 21) return 4;
    return 42;
}
