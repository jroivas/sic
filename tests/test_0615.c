// Small constant-size memcpy/memmove/memset are expanded inline (loads and
// stores, all loads first); every size 0..70 must match a byte loop,
// overlapping memmove in both directions, memset with a runtime byte, and the
// calls still return the destination. ggml reads each f16 via memcpy(&s, &f, 2).
#include <string.h>
#include <stdint.h>

static unsigned char src[160], dst[160], ref[160];

static void fill(unsigned char *p, int n, int seed)
{
    for (int i = 0; i < n; i++)
        p[i] = (unsigned char)(i * 7 + seed);
}

static int same(void)
{
    return memcmp(dst, ref, sizeof dst) == 0;
}

#define CHECK_COPY(N)                                                   \
    do {                                                                \
        fill(src, 160, 1); fill(dst, 160, 99); fill(ref, 160, 99);      \
        if (memcpy(dst + 3, src + 5, N) != dst + 3) return 1;           \
        for (int i = 0; i < N; i++) ref[3 + i] = src[5 + i];            \
        if (!same()) return 2;                                          \
        fill(dst, 160, 4); fill(ref, 160, 4);                           \
        memmove(dst + 2, dst + 1, N);                                   \
        for (int i = N - 1; i >= 0; i--) ref[2 + i] = ref[1 + i];       \
        if (!same()) return 3;                                          \
        fill(dst, 160, 5); fill(ref, 160, 5);                           \
        memmove(dst + 1, dst + 4, N);                                   \
        for (int i = 0; i < N; i++) ref[1 + i] = ref[4 + i];            \
        if (!same()) return 4;                                          \
        fill(dst, 160, 6); fill(ref, 160, 6);                           \
        if (memset(dst + 1, byte, N) != dst + 1) return 5;              \
        for (int i = 0; i < N; i++) ref[1 + i] = (unsigned char)byte;   \
        if (!same()) return 6;                                          \
    } while (0)

static float table[65536];

static inline float lookup(uint16_t f)
{
    uint16_t s;
    memcpy(&s, &f, sizeof(uint16_t));
    return table[s];
}

int main(int argc, char **argv)
{
    (void)argv;
    int byte = 0x1c0 + argc; // only the low byte is stored
    CHECK_COPY(0);  CHECK_COPY(1);  CHECK_COPY(2);  CHECK_COPY(3);
    CHECK_COPY(4);  CHECK_COPY(5);  CHECK_COPY(6);  CHECK_COPY(7);
    CHECK_COPY(8);  CHECK_COPY(9);  CHECK_COPY(13); CHECK_COPY(15);
    CHECK_COPY(16); CHECK_COPY(17); CHECK_COPY(31); CHECK_COPY(33);
    CHECK_COPY(63); CHECK_COPY(64); CHECK_COPY(65); CHECK_COPY(70);
    table[1234] = 42.0f;
    uint16_t h = 1234;
    double d = 3.5, e;
    __builtin_memcpy(&e, &d, sizeof d);
    if (e != 3.5) return 7;
    return (int)lookup(h);
}
