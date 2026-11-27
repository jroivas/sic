// Numbers, characters, strings and escapes.
int i[] = { 0, 42, 0x1F, 0XaBcD, 0b1011, 0B0, 017, 123u, 123U, 7l, 7LL, 7ull, 7uLL, 0x10ULL };
double d[] = { 1.0, .5, 5., 1e10, 1E-3, 2.5e+7, 0x1p64, 0x1.8p-3, 0X.8P1, 1.0f, 2.0F, 3.0L,
               1.0f16, 1.0f128, 1e5f };
_Complex double z[] = { 2i, 1.0fi, 3.0j, 4I, 5J, 6il };
int t = 1i2;
char c[] = { 'a', '\n', '\t', '\\', '\'', '"', '\0', '\7', '\17', '\177', '\x41', '\x7f', '\a', '\b',
             '\f', '\v', '\r', '\?', '\q', 'ab', L'x', u'y', U'z', 'é', '\U0001F600', 'é' };
const char *s[] = { "", "plain", "esc\n\t\\\"", "\x41\x42", "\xe2\x94\x80", "\342\224\200",
                    "é☺", "\U0001F600", "\uD800", "\x1234", "\777", "tab\there", "é ü ☺ 😀",
                    "a" "b", u8"utf8 é", "\N", "\" quote" };
const int *w[] = { (const int *)L"wide é", (const int *)L"\x41é\U0001F600", (const int *)L"😀" };
const short *u16[] = { u"utf16 é", u"😀", u"\U0001F600\uD800\x12345", u"" };
const int *u32[] = { U"utf32 😀", U"\U0001F600\x12345" };
int ops = 1 <<= 2 >>= 3 << 4 >> 5 ++ -- += -= *= /= %= &= |= ^= && || -> == != <= >= ... ? : ; , . ~ ! @ $ ::;
