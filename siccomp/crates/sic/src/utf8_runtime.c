extern void *malloc(unsigned long);
__attribute__((weak)) unsigned int *__sic_utf8_decode(const char *data, unsigned long size, unsigned long *out_count) {
    unsigned int *out = (unsigned int *)malloc((size + 1) * sizeof(unsigned int));
    unsigned long n = 0, i = 0;
    while (i < size) {
        unsigned char c = (unsigned char)data[i];
        unsigned int cp;
        unsigned long len;
        if (c < 0x80) { cp = c; len = 1; }
        else if (c < 0xE0) { cp = (unsigned int)(c & 0x1F); len = 2; }
        else if (c < 0xF0) { cp = (unsigned int)(c & 0x0F); len = 3; }
        else { cp = (unsigned int)(c & 0x07); len = 4; }
        unsigned long k;
        for (k = 1; k < len && i + k < size; k++)
            cp = (cp << 6) | ((unsigned int)((unsigned char)data[i + k]) & 0x3F);
        out[n++] = cp;
        i += len;
    }
    *out_count = n;
    return out;
}
