// Regression: arrays whose size is inferred from an initializer (`T a[] = {...}`
// or `char s[] = "..."`) must be allocated with the correct length. sic used to
// leave the length at 0, so the element stores overflowed the stack and a
// variable-indexed read returned garbage. Also covers binary integer literals
// (`0b...`, a C23/GNU feature) used as initializer values.

int main(void)
{
    // Size inferred from the initializer list; read back via a *variable* index
    // (the case that exposed the stack overflow).
    unsigned int a[] = { 0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0b1010 };
    for (int i = 0; i < 6; i++) {
        unsigned int got = a[i];
        unsigned int want;
        switch (i) {
            case 0: want = 0u;          break;
            case 1: want = 1u;          break;
            case 2: want = 0x7FFFFFFFu;  break;
            case 3: want = 0x80000000u;  break;
            case 4: want = 0xFFFFFFFFu;  break;
            default: want = 10u;        break; // 0b1010
        }
        if (got != want)
            return 1 + i;
    }

    // `char s[] = "..."` copies the bytes (plus NUL), not a pointer.
    char s[] = "hello";
    if (sizeof(s) != 6)
        return 10;
    if (s[0] != 'h' || s[4] != 'o' || s[5] != '\0')
        return 11;

    // `char s[N] = "..."` zero-fills the tail.
    char t[10] = "hi";
    if (sizeof(t) != 10)
        return 12;
    if (t[0] != 'h' || t[1] != 'i' || t[2] != '\0' || t[9] != '\0')
        return 13;

    // Binary literal as a plain constant.
    if (0b100000 != 32)
        return 14;

    return 0;
}
