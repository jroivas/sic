/* A shift's type is its promoted LEFT operand's (C 6.5.7p3); sic used the usual
 * arithmetic conversions of both operands, so `(short)1 << 1L` was a long and
 * `-8 >> 1u` became a logical (unsigned) shift. c-testsuite 00200. Returns 42. */
int main(void) {
    int m8 = -8;
    unsigned one = 1u;
    long L = 1;
    short s = 3;
    unsigned char uc = 0x81;
    if ((m8 >> one) != -4 || (m8 >> 1L) != -4 || (-1 >> one) != -1) return 1;
    if (sizeof(s << L) != sizeof(int) || sizeof(1 << 1LL) != sizeof(int)) return 2;
    if (sizeof(uc << 1) != sizeof(int) || (uc << 1) != 258) return 3;
    if ((0x80000000u >> 31L) != 1u || sizeof(1u << 2L) != sizeof(unsigned)) return 4;
    if (sizeof(1L << one) != sizeof(long)) return 5;
    return 42;
}
