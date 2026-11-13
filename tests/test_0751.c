/* -fshort-wchar (Linux, EFI): wchar_t and L"…" are 16-bit unsigned short, as
 * with GCC and clang. Linux's setup_efi_kvm_sev_migration() initializes an
 * efi_char16_t array from L"SevLiveMigrationEnabled": sic wrote 4-byte units,
 * twice the array, over the saved registers of the frame. Returns 42. */
#include <stddef.h>

static const unsigned short g[] = L"Ab";

__attribute__((noinline)) static int use(const unsigned short *s, int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) sum += s[i];
    return sum;
}

__attribute__((noinline)) static int efi_shape(void) {
    volatile long before = 7;
    unsigned short name[] = L"SevLiveMigrationEnabled";
    volatile long after = 9;
    if (sizeof(name) != 48 || name[3] != 'L' || name[22] != 'd' || name[23] != 0) return 1;
    if (use(name, 3) != 'S' + 'e' + 'v') return 2;
    return before == 7 && after == 9 ? 0 : 3;
}

int main(void) {
    if (sizeof(wchar_t) != 2 || __SIZEOF_WCHAR_T__ != 2 || __WCHAR_MAX__ != 0xffff) return 1;
    if ((wchar_t)-1 < 0) return 2;                      /* unsigned */
    if (sizeof(L"abc") != 8 || sizeof(L'a') != 2) return 3;
    if (sizeof(g) != 6 || g[0] != 'A' || g[1] != 'b' || g[2] != 0) return 4;
    unsigned short e[] = L"a\U0001F600";                /* UTF-16: a surrogate pair */
    if (sizeof(e) != 8 || e[1] != 0xd83d || e[2] != 0xde00) return 5;
    if (efi_shape()) return 10 + efi_shape();
    return 42;
}
