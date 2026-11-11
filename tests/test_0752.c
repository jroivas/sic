/* A string literal is a char[N] for sizeof (sic said 8, a pointer's size),
 * and \u / \U name a character: UTF-8 in a narrow literal, a surrogate pair in
 * a u"" one, one unit in U"" and L"" (sic read `\U` as the letter U).
 * Returns 42. */
int main(void) {
    if (sizeof("abc") != 4 || sizeof("ab\x41") != 4 || sizeof("") != 1) return 1;
    const char *n = "é!";
    if (sizeof("é!") != 4 || (unsigned char)n[0] != 0xc3 || (unsigned char)n[1] != 0xa9 || n[2] != '!') return 2;
    const unsigned short u[] = u"\U0001F600";
    if (sizeof(u) != 6 || u[0] != 0xd83d || u[1] != 0xde00) return 3;
    const unsigned int U[] = U"\U0001F600é";
    if (sizeof(U) != 12 || U[0] != 0x1F600 || U[1] != 0xe9) return 4;
    const int L[] = L"é";
    if (sizeof(L) != 8 || L[0] != 0xe9) return 5;
    if ('A' != 'A') return 6;
    return 42;
}
