/* Link mode -fPIE -pie: sic rejected gcc's -pie / -no-pie / -static-pie, so QEMU's
 * configure printed "Disabling PIE due to missing toolchain support". The
 * program exercises absolute relocations (function and data pointers in
 * initialized data), thread-local storage and libc. Returns 42. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static __thread int tls_counter = 40;
static int add(int a, int b) { return a + b; }
static int (*const table[])(int, int) = { add };
static const char *const names[] = { "pie", "relocs" };
int main(void) {
    char buf[32];
    snprintf(buf, sizeof buf, "%s-%s", names[0], names[1]);
    char *heap = strdup(buf);
    if (strcmp(heap, "pie-relocs") != 0) return 1;
    free(heap);
    tls_counter++;
    return table[0](tls_counter, 1);
}
