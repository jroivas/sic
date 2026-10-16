/* An arithmetic expression's inferred type follows C's usual arithmetic
 * conversions (integer promotion, the wider float), as its value does: the
 * inference took the left operand's float (`float * double` was `float`) and
 * skipped promotion (`sizeof(c + c)` was 1), so sizeof/typeof/_Generic were
 * wrong. Returns 42. */
volatile char c = 'a'; volatile short s = 3; volatile unsigned char uc = 200;
volatile float f = 1; volatile double d = 1; volatile _Bool b = 1; volatile long l = 2;
#define TYPE(x) _Generic((x), int: 1, double: 2, float: 3, long: 4, default: 0)
int main(void) {
    if (sizeof(c + c) != 4 || sizeof(s * s) != 4 || sizeof(uc - uc) != 4 || sizeof(b + b) != 4) return 1;
    if (sizeof(f * d) != 8 || sizeof(d * f) != 8 || sizeof(f + 1) != 4 || sizeof(c + l) != 8) return 2;
    if (TYPE(c + c) != 1 || TYPE(f * d) != 2 || TYPE(f * f) != 3 || TYPE(c * l) != 4) return 3;
    __typeof__(f * d) t = 0.1;
    if (t != 0.1) return 4;                  /* a double, not a float */
    return 42;
}
