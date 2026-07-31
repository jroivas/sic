/* `offsetof(T, member)` where `member` lives inside an ANONYMOUS union/struct,
 * used in a static initializer, must fold. sic's compile-time offsetof resolver
 * only looked at direct fields (not anonymous members), so the field failed to
 * evaluate — and one unfoldable field zero-fills the whole aggregate. QEMU's
 * VirtIODevice wraps `host_features` in an anonymous union, and the static
 * `virtio_properties[]` table (built with DEFINE_PROP_BIT64 →
 * `.offset = offsetof(VirtIODevice, host_features) + ...`) came out all zeros,
 * so device_class_set_props read a NULL-named property and aborted at
 * qemu-system-* startup. */
#include <stdint.h>

struct VD {
    int a;
    union { uint64_t host_features; uint64_t host_features_ex[2]; };
    struct { int inner_x; int inner_y; };   /* anonymous struct too */
    int b;
};

struct Prop { const char *name; long offset; };

static const struct Prop props[] = {
    { .name = "hf", .offset = __builtin_offsetof(struct VD, host_features) },
    { .name = "iy", .offset = __builtin_offsetof(struct VD, inner_y) },
    { .name = "b",  .offset = __builtin_offsetof(struct VD, b) },
};

int main(void)
{
    if (props[0].name == 0) return 1;                 /* whole array was zeroed */
    if (props[0].offset != 8) return 2;               /* host_features via anon union */
    if (props[1].offset != 8 + 16 + 4) return 3;      /* inner_y in anon struct */
    if (props[2].name == 0 || props[2].name[0] != 'b') return 4;
    return 0;
}
