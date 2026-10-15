/* In C, an index that is a `+ - *` tree over narrow signed ints is computed
 * in 64 bits (`y*W + x`, `(i - 1) * 3 + j`): equal to the int result since
 * signed overflow is undefined. Negative intermediates included. Returns 42. */
static unsigned char grid[16 * 16];
int main(int argc, char **argv) {
    const int W = 16;
    for (int k = 0; k < 256; k++) grid[k] = (unsigned char)(k * 7);
    long s = 0, e = 0;
    for (int y = 0; y < 16; y++)
        for (int x = 0; x < 16; x++) {
            int ym = y == 0 ? W - 1 : y - 1;
            int xp = x == W - 1 ? 0 : x + 1;
            s += grid[ym * W + xp] + grid[y * W + x] + grid[(y - 1 + argc) * W - x + 15];
            e += (unsigned char)((ym * 16 + xp) * 7) + (unsigned char)((y * 16 + x) * 7)
               + (unsigned char)(((y) * 16 - x + 15) * 7);
        }
    short sh = (short)(argc + 2);                 /* 3 */
    s += grid[sh * sh * 2 - 1];                   /* 17 */
    e += (unsigned char)(17 * 7);
    int *p = (int *)0;
    (void)p;
    return s == e ? 42 : 1;
}
