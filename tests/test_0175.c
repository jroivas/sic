/* A cast to a narrower integer type in a constant expression must truncate to
 * that width (and re-sign). sic's const-eval folded casts type-blind, so
 * `(uint32_t)-1` became a 64-bit -1 (0xFFFFFFFFFFFFFFFF) instead of 0xFFFFFFFF.
 * QEMU's DEFINE_PROP_UNSIGNED stores `.defval.u = (uint32_t)_defval`; the
 * guest-phys-bits default of -1 then serialized as 0xFFFFFFFFFFFFFFFF and failed
 * QAPI's uint32 range check (visit_type_uintN), aborting at CPU init. */
#include <stdint.h>

struct P { union { int64_t i; uint64_t u; } defval; };
static const struct P p = { .defval.u = (uint32_t)-1 };

static const uint64_t u32 = (uint32_t)-1;
static const uint64_t u16 = (uint16_t)-1;
static const uint64_t u8  = (uint8_t)-1;
static const int64_t  s32 = (int32_t)-1;      /* stays sign-extended */
static const uint64_t masked = (uint8_t)0x1ff; /* 0xff */

int main(void)
{
    if (p.defval.u != 0xFFFFFFFFULL) return 1;
    if (u32 != 0xFFFFFFFFULL) return 2;
    if (u16 != 0xFFFFULL) return 3;
    if (u8  != 0xFFULL) return 4;
    if (s32 != -1) return 5;                   /* int32 -1 sign-extends to -1 */
    if (masked != 0xFFULL) return 6;
    return 0;
}
