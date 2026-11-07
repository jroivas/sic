// Character constants in #if: encoding prefixes (L u U) are part of the
// constant, not identifiers (musl's stdint.h: `#if L'\0'-1 > 0`), and every
// escape has its value, as gcc evaluates them.
#define L 7
#define u 7
#define U 7

#if L'\0'-1 > 0
#error "wchar_t is signed"
#endif
#if !(u'\0'-1 > 0) || !(U'\0'-1 > 0)
#error "char16_t and char32_t are unsigned"
#endif
#if '\377' != -1 || '\xff' != -1 || L'\xff' != 255 || 'ab' != 24930 || 'abcde' != 'bcde'
#error "narrow constants"
#endif
#if '\a' != 7 || '\\' != 92 || '\'' != 39 || '\101' != 65 || '\e' != 27 || '\?' != 63 \
    || '\v' != 11 || '\f' != 12 || '\b' != 8 || '"' != 34 || '\400' != 0 || '\x100' != 0
#error "escapes"
#endif
#if L'\xffffffff' != -1 || U'\xffffffff' != 4294967295 || u'\xffff' != 65535
#error "wide ranges"
#endif
#if L'é' != 233 || u'é' != 233 || U'é' != 233 || L'\U0001F600' != 128512 || L'ab' != 'b'
#error "wide characters"
#endif

int main(void)
{
    // The prefixes stayed with their constants: the macros were not expanded.
    if (L'x' != 'x' || u'y' != 'y' || U'z' != 'z') return 1;
    if (sizeof(L"ab") != 12 || sizeof(u"ab") != 6) return 2;
    return 0;
}
