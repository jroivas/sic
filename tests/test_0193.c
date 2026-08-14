/* __int128 has 16-byte size AND 16-byte alignment on x86-64 SysV. sic capped
 * integer alignment at the pointer size (8), so it laid out any struct with a
 * 128-bit member wrong — e.g. QEMU's MemoryRegion (`Int128 size;`) and hence
 * every device state embedding it, and it broke 128-bit atomics. */
#include <stddef.h>

struct HasI128 {
    char c;
    __int128 v;   /* must be 16-aligned -> offset 16 */
};

struct AfterI128 {
    __int128 v;
    char c;       /* struct size rounds up to 16-alignment -> 32 */
};

int main(void)
{
    if (sizeof(__int128) != 16)   return 1;
    if (_Alignof(__int128) != 16) return 2;
    if (_Alignof(unsigned __int128) != 16) return 3;

    if (_Alignof(struct HasI128) != 16) return 4;
    if (offsetof(struct HasI128, v) != 16) return 5;
    if (sizeof(struct HasI128) != 32) return 6;

    if (sizeof(struct AfterI128) != 32) return 7;

    /* 64-bit and narrower keep natural alignment (regression guard) */
    if (_Alignof(long long) != 8) return 8;
    if (_Alignof(int) != 4) return 9;

    return 0;
}
