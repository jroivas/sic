// `ms_abi` callers for the differential test (abi.sh); see ms_callee.c.
#include <stdio.h>
#include "ms_abi.h"

#define MS __attribute__((ms_abi))

MS long ints8(int, long, short, char, long, int, unsigned char, long);
MS double mixed(int, double, long, float, double, int, double);
MS float fsum(float, float, float, float, float);
MS void *ptrs(void *, char *, long);
MS long aggs(S1, S2, S3, S4, S8, S16, S24, int);
MS S1 ret1(int);
MS S4 ret4(int);
MS S8 ret8(long);
MS S3 ret3(int);
MS S16 ret16(long, long);
MS S24 ret24(long);
MS double retd(double);
MS long vsum(int, ...);
MS double vmix(int, ...);
MS long apply(MS long (*)(long, long), long, long);
MS long calls_sysv(long);

typedef long efi_fn_t(long a, long b);
struct table {
    efi_fn_t MS *sub;
    long (MS *mul)(long, long);
};
extern struct table the_table;

// A callback the callee calls: ms_abi as well.
static MS long cb(long a, long b) { return a * 100 + b; }

int main(void) {
    char buf[8];
    printf("ints8 %ld\n", ints8(1, 2, 3, 4, 5, 6, 7, 8));
    printf("ints8n %ld\n", ints8(-1, -2, -3, -4, -5, -6, 250, -8));
    printf("mixed %.3f\n", mixed(1, 2.5, 3, 4.25f, 5.5, 6, 7.75));
    printf("fsum %.3f\n", fsum(1.5f, 2.5f, 3.5f, 4.5f, 5.5f));
    printf("ptrs %ld\n", (long)((char *)ptrs(buf, buf, 3) - buf));
    S1 a = { 1 }; S2 b = { 2 }; S3 c = { { 3, 4, 5 } }; S4 d = { 6 };
    S8 e = { 7 }; S16 f = { 8, 9 }; S24 g = { 10, 11, 12 };
    printf("aggs %ld\n", aggs(a, b, c, d, e, f, g, 13));
    printf("unchanged %ld %ld %d\n", f.a, g.c, c.a[1]);
    printf("ret1 %d ret4 %d ret8 %ld\n", ret1(9).a, ret4(9).a, ret8(9).a);
    S3 r3 = ret3(20);
    printf("ret3 %d %d %d\n", r3.a[0], r3.a[1], r3.a[2]);
    S16 r16 = ret16(21, 22);
    S24 r24 = ret24(30);
    printf("ret16 %ld %ld ret24 %ld %ld %ld\n", r16.a, r16.b, r24.a, r24.b, r24.c);
    printf("retd %.3f\n", retd(3.0));
    printf("vsum0 %ld\n", vsum(0));
    printf("vsum %ld\n", vsum(7, 1L, 2L, 3L, 4L, 5L, 6L, 7L));
    S24 big = { 100, 200, 300 }; S8 small = { 4 };
    printf("vmix %.3f\n", vmix(4, 0, 1.25, 1, big, 2, small, 0, 2.5));
    printf("apply %ld\n", apply(cb, 3, 4));
    printf("calls_sysv %ld\n", calls_sysv(20));
    printf("table %ld %ld\n", the_table.sub(10, 3), the_table.mul(10, 3));
    MS long (*p)(long, long) = the_table.mul;
    printf("ptr %ld\n", p(6, 7));
    return 0;
}
