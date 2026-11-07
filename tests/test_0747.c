// A small VLA needs no allocator: musl's dynamic linker declares one before it
// has relocated itself, when calling `calloc` jumps to address 0. sic took every
// VLA from `calloc`.
#include <stdlib.h>

void *calloc(size_t n, size_t size) { (void)n; (void)size; abort(); }

static int f(int n)
{
    long a[n];
    for (int i = 0; i < n; i++) a[i] = i * 2;
    return (int)a[n - 1];
}

int main(void)
{
    return f(3) == 4 && f(60) == 118 ? 0 : 1;
}
