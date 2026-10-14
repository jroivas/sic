/* Wide string literals (L"…" wchar_t, u"…" char16_t with surrogates, U"…"
 * char32_t) were lexed as narrow byte strings: `wchar_t s[] = L"hello"` held
 * garbage. c-testsuite 00220. Returns 42. */
#include <wchar.h>
#include <uchar.h>
wchar_t g[] = L"g€";
const wchar_t *gp = L"ptr";
char16_t g16[] = u"a😀";
char32_t g32[] = U"z😀";
struct M { int k; wchar_t name[4]; } gm = {7, L"ab"};
wchar_t g5[5] = L"xy";
int main(void) {
    wchar_t l[] = L"loc" L"al";
    wchar_t mix[] = L"a" "b" L"c";
    const wchar_t *p = L"\x4F60\101";
    if (sizeof g != 12 || sizeof g16 != 8 || sizeof g32 != 12 || sizeof l != 24 || sizeof(L"ab") != 12) return 1;
    if (g[1] != 0x20AC || g[2] != 0 || g16[1] != 0xD83D || g16[2] != 0xDE00 || g32[1] != 0x1F600) return 2;
    if (wcscmp(gp, L"ptr") != 0 || wcscmp(l, L"local") != 0 || wcscmp(mix, L"abc") != 0) return 3;
    if (gm.k != 7 || wcscmp(gm.name, L"ab") != 0 || p[0] != 0x4F60 || p[1] != 'A') return 4;
    if (sizeof g5 / sizeof g5[0] != 5 || g5[1] != 'y' || g5[4] != 0 || L'€' != 0x20AC) return 5;
    return 42;
}
