/* The x86 SIMD builtins too involved to expand inline: the SSE4.2 string
   comparisons and the F16C float-to-half conversion, following Intel's SDM.
   Prepended (post-preprocess) only when the unit uses them; weak-linked.

   String comparisons (pcmpestri/pcmpestrm/pcmpistri/pcmpistrm and their flag
   forms):

   `la`/`lb` are the explicit lengths (their absolute values, at most the
   element count), unused when `implicit` (each string ends at its first zero
   element). `what`: 0 index, 1 mask (written to `mask`), 2 CF,
   3 ZF, 4 SF, 5 OF, 6 "above" (CF and ZF both clear). */

static int __sic_pcmpstr_elem(const unsigned char *p, int i, int imm) {
    switch (imm & 3) {
    case 0: return p[i];
    case 1: return p[2 * i] | p[2 * i + 1] << 8;
    case 2: return (signed char)p[i];
    default: return (short)(p[2 * i] | p[2 * i + 1] << 8);
    }
}

static int __sic_pcmpstr_len(const unsigned char *p, long long len, int implicit, int n, int imm) {
    if (implicit) {
        int i = 0;
        while (i < n && __sic_pcmpstr_elem(p, i, imm) != 0) i++;
        return i;
    }
    if (len < 0) len = -len;
    return len > n ? n : (int)len;
}

__attribute__((weak)) int __sic_pcmpstr(const void *va, int ea, const void *vb, int eb, int implicit, int imm, int what, void *mask) {
    const unsigned char *a = va, *b = vb;
    int n = (imm & 1) ? 8 : 16;
    int la = __sic_pcmpstr_len(a, ea, implicit, n, imm);
    int lb = __sic_pcmpstr_len(b, eb, implicit, n, imm);
    unsigned res1 = 0;
    for (int j = 0; j < n; j++) {
        int bj = __sic_pcmpstr_elem(b, j, imm), vbj = j < lb, r = 0;
        switch ((imm >> 2) & 3) {
        case 0: /* equal any */
            for (int i = 0; i < la && !r; i++)
                r = vbj && __sic_pcmpstr_elem(a, i, imm) == bj;
            break;
        case 1: /* ranges: a[i] <= b[j] <= a[i+1] for even i */
            for (int i = 0; i + 1 < la && !r; i += 2)
                r = vbj && __sic_pcmpstr_elem(a, i, imm) <= bj && bj <= __sic_pcmpstr_elem(a, i + 1, imm);
            break;
        case 2: { /* equal each */
            int vaj = j < la;
            r = (!vaj && !vbj) ? 1 : (vaj && vbj) ? __sic_pcmpstr_elem(a, j, imm) == bj : 0;
            break;
        }
        default: /* equal ordered: a occurs in b at j */
            r = 1;
            for (int i = 0; i < n - j && r; i++) {
                int vai = i < la, vbk = j + i < lb;
                if (!vai) continue;
                r = vbk && __sic_pcmpstr_elem(a, i, imm) == __sic_pcmpstr_elem(b, j + i, imm);
            }
            break;
        }
        res1 |= (unsigned)r << j;
    }
    unsigned all = (1u << n) - 1, res2;
    switch ((imm >> 4) & 3) {
    case 1: res2 = ~res1 & all; break;
    case 3: res2 = res1 ^ ((1u << lb) - 1); break;
    default: res2 = res1; break;
    }
    switch (what) {
    case 0:
        if (!res2) return n;
        if (imm & 0x40) { int i = n - 1; while (!((res2 >> i) & 1)) i--; return i; }
        { int i = 0; while (!((res2 >> i) & 1)) i++; return i; }
    case 1: {
        unsigned char *m = mask;
        for (int i = 0; i < 16; i++) m[i] = 0;
        if (imm & 0x40) {
            int w = (imm & 1) ? 2 : 1;
            for (int j = 0; j < n; j++)
                if ((res2 >> j) & 1)
                    for (int k = 0; k < w; k++) m[j * w + k] = 0xff;
        } else {
            m[0] = res2 & 0xff;
            m[1] = res2 >> 8;
        }
        return 0;
    }
    case 2: return res2 != 0;
    case 3: return lb < n;
    case 4: return la < n;
    case 5: return res2 & 1;
    default: return res2 == 0 && !(lb < n);
    }
}

/* `f` as an IEEE half, rounded by `mode`: 0 to nearest even, 1 down, 2 up,
   3 toward zero (vcvtps2ph). NaNs are quieted, keeping their high payload. */
__attribute__((weak)) unsigned short __sic_f32_to_f16(float f, int mode) {
    union { float f; unsigned u; } v;
    v.f = f;
    unsigned sign = (v.u >> 16) & 0x8000u, exp = (v.u >> 23) & 0xffu, man = v.u & 0x7fffffu;
    if (exp == 0xff) return (unsigned short)(sign | 0x7c00u | (man ? 0x200u | (man >> 13) : 0));
    /* The value is m * 2^(e - 23); its half quantum is 2^(e - 10) when it is a
       normal half (e >= -14), else 2^-24. */
    int e = exp ? (int)exp - 127 : -126;
    unsigned m = exp ? (man | 0x800000u) : man;
    int shift = e >= -14 ? 13 : -1 - e;
    unsigned r, rem, half;
    if (shift > 25) { r = 0; rem = m; half = 1u << 25; }
    else { r = m >> shift; rem = m & ((1u << shift) - 1); half = 1u << (shift - 1); }
    switch (mode & 3) {
    case 0: if (rem > half || (rem == half && (r & 1))) r++; break;
    case 1: if (sign && rem) r++; break;
    case 2: if (!sign && rem) r++; break;
    default: break;
    }
    /* r carries the implicit bit (0x400) for a normal half, and a carry out of
       the mantissa moves into the exponent. */
    unsigned bits = e >= -14 ? ((unsigned)(e + 14) << 10) + r : r;
    if (bits >= 0x7c00u) {
        int inf = (mode & 3) == 0 || ((mode & 3) == 2 && !sign) || ((mode & 3) == 1 && sign);
        bits = inf ? 0x7c00u : 0x7bffu;
    }
    return (unsigned short)(sign | bits);
}
