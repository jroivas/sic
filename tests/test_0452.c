/* Constant folding of a cast to a TYPEDEF'd integer type truncates/re-signs like
 * the real type: `(uint8_t)(U8 + 100)` folded to 300 (a typedef target kept the
 * value unchanged), so a constant `if` condition took the wrong branch. Also
 * case labels and global initializers through typedef casts. Returns 42. */
#include <stdint.h>
typedef unsigned short my_u16;
static const uint8_t U8 = 200;
static const int K = 0x1ff;
static const int8_t S8 = (int8_t)0xf0;          /* -16 */
static const uint32_t G = (uint8_t)0x1234;       /* 0x34 */
int main(void) {
    int r = 0;
    if ((uint8_t)(U8 + 100) != 44) r |= 1;
    if ((my_u16)(K << 8) != 0xff00) r |= 2;
    if (S8 != -16 || (uint16_t)S8 != 0xfff0) r |= 4;
    if (G != 0x34) r |= 8;
    switch (44) { case (uint8_t)300: r |= 0; break; case 300: r |= 16; break; default: r |= 32; }
    return r == 0 ? 42 : r;
}
