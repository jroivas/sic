/* A `_Bool` bit-field must read/write exactly its 1 bit. sic used int_bits(_Bool)
 * = 1 as the shift width for the extraction, but the field is loaded as a byte
 * (8 bits), so the shift/mask was a no-op and a `_Bool:1` read its neighbour's
 * bit too (value 3 instead of 1). QEMU's i386 decoder loops on
 *   while (e->is_decode) { e->is_decode = false; e->decode(...); }
 * where is_decode is `_Bool:1`; the stale read made it an infinite loop that
 * stalled guest-code translation. */

struct Flags {
    unsigned int intercept : 8;   /* forces a wide storage unit */
    _Bool a : 1;
    _Bool b : 1;
    _Bool c : 1;
};

struct Only { _Bool x : 1; _Bool y : 1; };

int main(void)
{
    struct Flags f = { .intercept = 0xAB, .a = 1, .b = 0, .c = 1 };
    if (f.a != 1) return 1;                 /* read as 3 before the fix */
    if (f.b != 0) return 2;
    if (f.c != 1) return 3;
    if (f.intercept != 0xAB) return 4;      /* neighbour preserved */

    /* the exact while-loop pattern must terminate */
    f.a = 1;
    int iters = 0;
    while (f.a) {
        f.a = 0;                            /* clearing must stick */
        if (++iters > 3) return 5;          /* would loop forever before the fix */
    }
    if (iters != 1) return 6;
    if (f.b != 0 || f.c != 1) return 7;     /* clearing a didn't touch b/c */

    struct Only o = { .x = 1, .y = 1 };
    o.x = 0;
    if (o.x != 0 || o.y != 1) return 8;

    return 0;
}
