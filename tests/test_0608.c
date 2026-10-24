// `__builtin_<libc function>` works without the function's header, as in GCC
// and Clang (sic declares it from its prototype); it was "unknown function"
// unless the header was included. Returns 42.
int main(void)
{
    char a[8] = "abcdef", b[8];
    __builtin_memcpy(b, a, 7);
    if (__builtin_strlen(b) != 6 || __builtin_memcmp(a, b, 7) != 0) return 1;
    if (__builtin_strchr(b, 'd') != b + 3) return 2;
    if (__builtin_abs(-5) != 5 || __builtin_labs(-6L) != 6) return 3;
    if (__builtin_sqrt(16.0) != 4.0 || __builtin_fmax(2.0, 3.0) != 3.0) return 4;
    int e;
    if (__builtin_frexp(8.0, &e) != 0.5 || e != 4) return 5;
    char buf[16];
    if (__builtin_snprintf(buf, sizeof buf, "%d-%s", 7, "x") != 3 || __builtin_strcmp(buf, "7-x") != 0) return 6;
    void *p = __builtin_malloc(16);
    if (!p) return 7;
    __builtin_memset(p, 1, 16);
    __builtin_free(p);
    return 42;
}
