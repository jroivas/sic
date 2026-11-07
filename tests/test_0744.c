// Unary plus keeps its operand's value: `+(-0.0)` is -0.0 and `+NaN` keeps its
// sign (it was `0 + x`); integers are still promoted (`sizeof(+c)`).
int main(void)
{
    volatile double z = -0.0;
    double p = +z;
    if (!__builtin_signbit(p)) return 1;
    volatile float nf = -__builtin_nanf("");
    if (!__builtin_signbit(+nf)) return 2;
    char c = 'a';
    if (sizeof(+c) != sizeof(int) || +c != 'a') return 3;
    unsigned char u = 200;
    if (+u != 200 || sizeof(+u) != sizeof(int)) return 4;
    int a[+3];
    if (sizeof a != 3 * sizeof(int)) return 5;
    switch (2) { case +2: break; default: return 6; }
    long long big = -9223372036854775807LL - 1;
    if (+big != big) return 7;
    return 0;
}
