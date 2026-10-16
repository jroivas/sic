/* A `float` literal (`1.5f`, `1.5F`) has type float and float precision (C
 * 6.4.4.2): it was a double — sizeof(1.0f) was 8, `double d = 0.1f;` held the
 * exact double 0.1, `16777217.0f` stayed 16777217, and `1.0f / 3.0f` folded in
 * double precision. Returns 42. */
#include <stdio.h>
volatile float vf = 0.1f;
int main(void) {
    double b = 0.1f;
    double d = 1.0f / 3.0f;
    double e = 16777217.0f;
    double big = -9000000000.0F;
    if (sizeof(1.0f) != 4 || sizeof(1.0) != 8 || sizeof(2.5F) != 4) return 1;
    if (b != (double)(float)0.1) return 2;
    if (d != (double)((float)1 / (float)3)) return 3;
    if (e != 16777216.0) return 4;
    if (big != -8999999488.0) return 5;
    if (vf != 0.1f || vf == 0.1) return 6;   /* float vs float equal; vs double not */
    return 42;
}
