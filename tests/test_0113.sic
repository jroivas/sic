// Regression: float<->integer conversions where the integer side is narrower
// than 32 bits. x86-64 float/int conversion instructions require a 32/64-bit
// GPR, so `(signed char)f` panicked the cranelift backend. The fix widens the
// integer side to i32 first (with the correct signedness) and reduces after.

int main(void)
{
    float f = 200.7f;
    signed char c   = (signed char)f;    // 200 wraps to -56
    unsigned char uc = (unsigned char)f; // 200
    short s          = (short)f;         // 200
    if (c != -56) return 1;
    if (uc != 200) return 2;
    if (s != 200) return 3;

    double d = -5.9;
    signed char c2 = (signed char)d;     // truncates toward zero -> -5
    if (c2 != -5) return 4;

    // int -> float, small signed/unsigned sources.
    signed char cx = -5;
    float ff = (float)cx;
    if (ff > -4.9f || ff < -5.1f) return 5;

    unsigned char ux = 250;
    float fu = (float)ux;
    if (fu < 249.9f || fu > 250.1f) return 6;

    short sx = -1000;
    double du = (double)sx;
    if (du > -999.9 || du < -1000.1) return 7;

    // Round-trip through a narrow int.
    for (int i = -3; i <= 3; i++) {
        signed char t = (signed char)((float)i);
        if (t != i) return 8;
    }

    return 0;
}
