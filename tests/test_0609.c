// A `__builtin_memcpy` used before the header is included: its implicit
// declaration agrees with the header's. Returns 42.
static int early(char *d, const char *s) { __builtin_memcpy(d, s, 3); return d[2]; }
#include <string.h>
#include <stdio.h>
int main(void)
{
    char d[4] = {0};
    if (early(d, "xyz") != 'z') return 1;
    memcpy(d, "ab", 3);
    __builtin_fprintf(stdout, "%s\n", d);
    return strcmp(d, "ab") == 0 ? 42 : 2;
}
