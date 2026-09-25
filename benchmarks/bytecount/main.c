/* Count the bytes with the high bit set (>= 128) in a large buffer, over several
   passes — a predicate reduction over bytes. LLVM auto-vectorizes it (pcmpgtb /
   pcmpeqb + pmovmskb + popcount, 16 bytes at a time); a scalar back end does a
   compare + branch per byte. Integer count, so it is exact regardless of order.
   Prints the count. */
#include <stdio.h>

#define N 20000000
#define P 20

static unsigned char buf[N];

int main(void) {
    for (int i = 0; i < N; i++) buf[i] = (unsigned char)((i * 131 + 7) & 0xff);
    long cnt = 0;
    for (int p = 0; p < P; p++)
        for (int i = 0; i < N; i++)
            if (buf[i] >= 128) cnt++;
    printf("%ld\n", cnt);
    return 0;
}
