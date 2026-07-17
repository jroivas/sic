// Regression: octal (`\ooo`) and hex (`\xHH`) escape sequences in a string
// literal denote a single raw byte. sic built string literals as a Rust String
// and pushed each escape value as a Unicode scalar, so a byte like `\342`
// (0xE2) was re-encoded as the UTF-8 of U+00E2 (0xC3 0xA2) — corrupting e.g.
// SQLite's box-drawing output (each 3-byte UTF-8 glyph became 6 bytes).

int my_strlen(const char *s) { int n = 0; while (s[n]) n++; return n; }

int main(void)
{
    // U+2500 as a 3-byte UTF-8 sequence via octal escapes.
    const char *box = "\342\224\200";
    if (my_strlen(box) != 3) return 1;
    if ((unsigned char)box[0] != 0xE2) return 2;
    if ((unsigned char)box[1] != 0x94) return 3;
    if ((unsigned char)box[2] != 0x80) return 4;
    if (box[3] != 0) return 5;

    // Same bytes via hex escapes.
    const char *h = "\xe2\x94\x80";
    if (my_strlen(h) != 3) return 6;
    if ((unsigned char)h[0] != 0xE2) return 7;
    if ((unsigned char)h[2] != 0x80) return 8;

    // A high byte on its own.
    const char *one = "\377";        // 0xFF
    if (my_strlen(one) != 1) return 9;
    if ((unsigned char)one[0] != 0xFF) return 10;

    // Low-value escapes and mixed content.
    const char *mixed = "A\102\x43-\n";  // 'A' 'B' 'C' '-' '\n'
    if (my_strlen(mixed) != 5) return 11;
    if (mixed[0] != 'A' || mixed[1] != 'B' || mixed[2] != 'C') return 12;
    if (mixed[3] != '-' || mixed[4] != '\n') return 13;

    // Adjacent string-literal concatenation must preserve raw bytes too.
    const char *cat = "\342\224" "\200X";
    if (my_strlen(cat) != 4) return 14;
    if ((unsigned char)cat[0] != 0xE2 || (unsigned char)cat[2] != 0x80 || cat[3] != 'X')
        return 15;

    return 0;
}
