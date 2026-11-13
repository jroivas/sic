/* A prefixed character constant has its C type: u'x' a char16_t (unsigned
 * short), U'x' a char32_t (unsigned int), L'x' a wchar_t (int here). sic made
 * every one an int. Returns 42. */
static const int folded = u'a' + U'b';                 /* constant expressions */

int main(void) {
    if (sizeof(u'a') != 2 || sizeof(U'a') != 4 || sizeof(L'a') != 4) return 1;
    if (_Generic(u'a', unsigned short: 1, default: 0) != 1) return 2;
    if (_Generic(U'a', unsigned int: 1, default: 0) != 1) return 3;
    if (_Generic(L'a', int: 1, default: 0) != 1) return 4;
    if (!(U'\xffffffff' > 0) || L'\xffffffff' != -1 || u'\xffff' != 65535) return 5;
    if (u'é' != 0xe9 || folded != 'a' + 'b') return 6;
    switch (u'q') { case u'q': break; default: return 7; }
    return 42;
}
