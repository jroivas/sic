/* A floating constant expression initializes an integer object: converted to its
   type, truncating (QEMU's hw/audio/fmopl.c tables, from 96.0/4096). */
#define EG_ENT 4096
#define EG_STEP (96.0/EG_ENT)
#define DV (EG_STEP/2)
#define SC(db) (db*((3/EG_STEP)*(1<<16)))+100
static const unsigned t[4] = { 0.000/DV, 0.750/DV, 1.500/DV, 12.000/DV };
static const int s[2] = { SC(0), SC(2) };
static const int neg[2] = { -1.5 * 2, -7 / 2.0 };
static int one = 1.5 * 2;
static const char c = 65.9;
static const unsigned char uc = 250.5;
static long l = 1e10;
static unsigned long ul = 1e19;
static _Bool b1 = 0.5, b0 = 0.0;
static struct { int a : 4; unsigned b : 3; } bf = { 2.5 * 2, 1.5 * 2 };
static int cast1 = (int)(3.5 * 2);
static unsigned cast2 = (unsigned)3.9 + 1;
static int cmp1 = 3.5 > 1, cmp2 = 1.5 == 2.5, cmp3 = 3.5 > 1 ? 10 : 20;
static int tr = 0.5 ? 1 : 2, tr0 = 0.0 ? 1 : 2, nt = !0.5, nt0 = !0.0;
static int and = 0.5 && 2, or = 0.0 || 0.0;
static double half = (double)1 / 2, fl = 7 / 2, mix = 3 / 2 * 1.5;
static float f = (float)1 / 4;
static int fi = (double)5 / 2 * 2, fc = (double)1 / 2 > 0, ft = (double)1 / 2 ? 1 : 2;
static int nest = ((double)1 / 2 > 0) + 1, nf = !((double)1 / 2), ca = (int)((double)3 / 2) + 1;
static double fq = 1 ? 1.5 : 2, fr = 3 + (double)1 / 2, ng = -(double)1 / 4;
int main(void) {
    static const int local[2] = { 2.5 * 2, 9 / 2.0 };
    if (t[0] != 0 || t[1] != 64 || t[2] != 128 || t[3] != 1024) return 1;
    if (s[0] != 100 || s[1] != 2 * (128 << 16) + 100) return 2;
    if (neg[0] != -3 || neg[1] != -3) return 3;
    if (one != 3 || c != 65 || uc != 250) return 4;
    if (l != 10000000000L || ul != 10000000000000000000UL) return 5;
    if (b1 != 1 || b0 != 0) return 6;
    if (bf.a != 5 || bf.b != 3) return 7;
    if (cast1 != 7 || cast2 != 4) return 8;
    if (cmp1 != 1 || cmp2 != 0 || cmp3 != 10) return 9;
    if (tr != 1 || tr0 != 2 || nt != 0 || nt0 != 1) return 10;
    if (and != 1 || or != 0) return 11;
    if (half != 0.5 || fl != 3.0 || mix != 1.5 || f != 0.25f) return 12;
    if (fi != 5 || fc != 1 || ft != 1) return 14;
    if (fq != 1.5 || fr != 3.5 || ng != -0.25) return 15;
    if (nest != 2 || nf != 0 || ca != 2) return 16;
    if (local[0] != 5 || local[1] != 4) return 13;
    return 0;
}
