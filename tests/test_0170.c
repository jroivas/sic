/* `__builtin_choose_expr` in a static initializer must fold, with an accurate
 * `__builtin_constant_p` in its condition (1 for a compile-time constant). sic
 * conservatively folds __builtin_constant_p to 0 (so a runtime `?:` picks its
 * runtime arm), but __builtin_choose_expr selects at compile time and discards
 * the other arm — a wrong 0 there picked the un-foldable `(void)0`, and one
 * unfoldable field zero-fills the whole static aggregate. QEMU's MIN_CONST /
 * MAX_CONST (BDRV_REQUEST_MAX_SECTORS defaults in virtio_blk_properties):
 *   __builtin_choose_expr(__builtin_constant_p(a) && __builtin_constant_p(b),
 *                         (a) < (b) ? (a) : (b), ((void)0)) */
#include <stdint.h>

#define MIN_CONST(a, b) __builtin_choose_expr(                       \
    __builtin_constant_p(a) && __builtin_constant_p(b),              \
    (a) < (b) ? (a) : (b), ((void)0))

struct Prop { const char *name; long offset; unsigned val; };

static const struct Prop props[] = {
    { .name = "a", .offset = 8, .val = (unsigned)MIN_CONST(4096, 512) },
    { .name = "b", .offset = 16, .val = (unsigned)MIN_CONST(100, 999) },
    { .name = "c", .offset = 24 },
};

int main(void)
{
    if (props[0].name == 0) return 1;      /* whole array was zeroed */
    if (props[0].val != 512) return 2;     /* min(4096, 512) */
    if (props[1].val != 100) return 3;     /* min(100, 999) */
    if (props[2].name == 0 || props[2].name[0] != 'c') return 4;
    return 0;
}
