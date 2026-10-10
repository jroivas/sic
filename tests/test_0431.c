/* -Wall -Werror must stay silent on valid code (QEMU builds every file with
 * them): uses only inside typeof/sizeof/asm operands, `unused`/cleanup
 * attributes, float division by zero, shifts within the
 * promoted width, prototypes in a body. Returns 42. */
#include <stdlib.h>
#define UNUSED __attribute__((unused))
static void freep(char **p) { free(*p); }
static int f(int x, unsigned char c, long l, double d) {
    int in_typeof = 1; __typeof__(in_typeof) t = 2;
    int in_sizeof = 1; int s = (int)sizeof in_sizeof;
    int in_asm = 3; __asm__ volatile("" : "+r"(in_asm));
    UNUSED int quiet = 4;
    int quiet2 __attribute__((unused)) = 5;
    __attribute__((cleanup(freep))) char *auto_freed = malloc(1);
    int helper(int);
    int g = c << 24, h = (int)(l << 62 >> 62), i = x >> 31;
    double inf = d / 0.0;
    unsigned long long w = 1ULL << 63;
    x /= 1; x <<= 3;
    return t + s + in_asm + g + h + i + (inf > 0) + (int)(w >> 63) + x - 8;
}
int main(void) { return f(1, 0, 0, 1.0) + 31; }
