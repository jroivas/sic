// sic presents itself as Clang 17.0.6 (Linux 7.3 requires Clang >= 17.0.1),
// as the kernel's scripts/cc-version.sh reads it.
#define STR2(x) #x
#define STR(x) STR2(x)

int main(void)
{
#if !defined(__clang__) || __clang_major__ != 17 || __clang_minor__ != 0 || __clang_patchlevel__ != 6
    return 1;
#endif
    const char *v = __clang_version__;
    return (v[0] == '1' && v[1] == '7' && v[2] == '.') ? 42 : 2;
}
