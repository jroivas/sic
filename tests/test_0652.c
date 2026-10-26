// -mno-sse -mno-mmx -mno-sse2 -mno-80387 (Linux's kernel flags) are honoured:
// no SSE in the code — small copies use integer moves (they used 16-byte
// vector moves), a variadic function saves no vector registers — and no
// __SSE__/__MMX__ macros. (A floating-point value is an error: test_0653.)
#include <stdarg.h>
#include <string.h>

#if defined(__SSE__) || defined(__SSE2__) || defined(__MMX__)
#error "SSE/MMX macros with -mno-sse -mno-mmx"
#endif

struct big { long a[9]; char tail[3]; };

static long sum(int n, ...) {
    va_list ap;
    va_start(ap, n);
    long s = 0;
    while (n--) s += va_arg(ap, long);
    va_end(ap);
    return s;
}

int main(void) {
    struct big a, b;
    for (int i = 0; i < 9; i++) a.a[i] = i * 3;
    memcpy(a.tail, "xy", 3);
    b = a;
    memset(&a, 0, sizeof a);
    int ok = (b.a[8] == 24) + (b.tail[1] == 'y') + (a.a[4] == 0);
    return ok + (int)sum(8, 1L, 2L, 3L, 4L, 5L, 6L, 7L, 11L);  // 3 + 39 = 42 (two args on the stack)
}
