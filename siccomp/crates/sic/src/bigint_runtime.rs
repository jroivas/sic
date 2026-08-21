//! Self-contained arbitrary-precision integer runtime for sic's `bigint`
//! (sic.md §"Integer sizes"). Written in plain C using only `malloc`/`free`
//! (already in libc) — no external bignum library. It is prepended to a
//! translation unit *only when that unit uses `bigint`* (see `uses_bigint`), so
//! programs without bigint pay nothing. Every function is `__attribute__((weak))`
//! so the copies emitted into each object dedupe at link and unused ones are
//! garbage-collected.
//!
//! Representation: sign-magnitude with base-2^32 little-endian limbs.
//! `{ int sign; unsigned len; unsigned limbs[]; }` — `sign` is 0 for zero,
//! ±1 otherwise; `len` counts significant limbs (no leading zeros).

/// The runtime source, prepended (post-preprocess) ahead of the user code.
pub const BIGINT_RUNTIME: &str = r#"
extern void *malloc(unsigned long);
extern void free(void *);

typedef struct __sic_bi { int sign; unsigned len; unsigned limbs[]; } __sic_bi;

__attribute__((weak)) __sic_bi *__sic_bi_alloc(unsigned n) {
    if (n < 1) n = 1;
    __sic_bi *r = (__sic_bi *)malloc(sizeof(__sic_bi) + (unsigned long)n * sizeof(unsigned));
    r->sign = 0; r->len = 0;
    for (unsigned i = 0; i < n; i++) r->limbs[i] = 0;
    return r;
}

__attribute__((weak)) void __sic_bi_free(__sic_bi *a) { if (a) free(a); }

__attribute__((weak)) void __sic_bi_norm(__sic_bi *r) {
    while (r->len > 0 && r->limbs[r->len - 1] == 0) r->len--;
    if (r->len == 0) r->sign = 0;
}

__attribute__((weak)) __sic_bi *__sic_bi_clone(const __sic_bi *a) {
    __sic_bi *r = __sic_bi_alloc(a->len);
    r->sign = a->sign; r->len = a->len;
    for (unsigned i = 0; i < a->len; i++) r->limbs[i] = a->limbs[i];
    return r;
}

__attribute__((weak)) __sic_bi *__sic_bi_from_u64(unsigned long long u) {
    __sic_bi *r = __sic_bi_alloc(2);
    r->limbs[0] = (unsigned)(u & 0xffffffffu);
    r->limbs[1] = (unsigned)(u >> 32);
    r->len = 2;
    __sic_bi_norm(r);
    r->sign = r->len ? 1 : 0;
    return r;
}

__attribute__((weak)) __sic_bi *__sic_bi_from_i64(long long v) {
    unsigned long long u = v < 0 ? (unsigned long long)(-(v + 1)) + 1ull : (unsigned long long)v;
    __sic_bi *r = __sic_bi_from_u64(u);
    if (r->len && v < 0) r->sign = -1;
    return r;
}

__attribute__((weak)) __sic_bi *__sic_bi_muladd_small(const __sic_bi *a, unsigned m, unsigned add) {
    __sic_bi *r = __sic_bi_alloc(a->len + 2);
    unsigned long long carry = add;
    unsigned i;
    for (i = 0; i < a->len; i++) {
        unsigned long long cur = (unsigned long long)a->limbs[i] * m + carry;
        r->limbs[i] = (unsigned)(cur & 0xffffffffu);
        carry = cur >> 32;
    }
    unsigned n = a->len;
    while (carry) { r->limbs[n++] = (unsigned)(carry & 0xffffffffu); carry >>= 32; }
    r->len = n;
    __sic_bi_norm(r);
    r->sign = r->len ? 1 : 0;
    return r;
}

__attribute__((weak)) __sic_bi *__sic_bi_from_str(const char *s) {
    int neg = 0;
    if (*s == '-') { neg = 1; s++; } else if (*s == '+') s++;
    __sic_bi *r = __sic_bi_from_i64(0);
    while (*s) {
        if (*s >= '0' && *s <= '9') {
            __sic_bi *t = __sic_bi_muladd_small(r, 10, (unsigned)(*s - '0'));
            __sic_bi_free(r);
            r = t;
        }
        s++;
    }
    if (r->len && neg) r->sign = -1;
    return r;
}

/* magnitude compare: -1 / 0 / 1 */
__attribute__((weak)) int __sic_bi_ucmp(const __sic_bi *a, const __sic_bi *b) {
    if (a->len != b->len) return a->len < b->len ? -1 : 1;
    unsigned i = a->len;
    while (i) { i--; if (a->limbs[i] != b->limbs[i]) return a->limbs[i] < b->limbs[i] ? -1 : 1; }
    return 0;
}

__attribute__((weak)) __sic_bi *__sic_bi_uadd(const __sic_bi *a, const __sic_bi *b) {
    unsigned n = a->len > b->len ? a->len : b->len;
    __sic_bi *r = __sic_bi_alloc(n + 1);
    unsigned long long carry = 0;
    for (unsigned i = 0; i < n; i++) {
        unsigned long long s = carry;
        if (i < a->len) s += a->limbs[i];
        if (i < b->len) s += b->limbs[i];
        r->limbs[i] = (unsigned)(s & 0xffffffffu);
        carry = s >> 32;
    }
    r->limbs[n] = (unsigned)carry;
    r->len = n + 1;
    __sic_bi_norm(r);
    return r;
}

/* magnitude subtract, requires |a| >= |b| */
__attribute__((weak)) __sic_bi *__sic_bi_usub(const __sic_bi *a, const __sic_bi *b) {
    __sic_bi *r = __sic_bi_alloc(a->len);
    long long borrow = 0;
    for (unsigned i = 0; i < a->len; i++) {
        long long s = (long long)a->limbs[i] - borrow - (i < b->len ? (long long)b->limbs[i] : 0);
        if (s < 0) { s += 0x100000000ll; borrow = 1; } else borrow = 0;
        r->limbs[i] = (unsigned)s;
    }
    r->len = a->len;
    __sic_bi_norm(r);
    return r;
}

__attribute__((weak)) __sic_bi *__sic_bi_add(const __sic_bi *a, const __sic_bi *b) {
    if (a->sign == 0) return __sic_bi_clone(b);
    if (b->sign == 0) return __sic_bi_clone(a);
    __sic_bi *r;
    if (a->sign == b->sign) {
        r = __sic_bi_uadd(a, b);
        r->sign = r->len ? a->sign : 0;
    } else {
        int c = __sic_bi_ucmp(a, b);
        if (c == 0) return __sic_bi_from_i64(0);
        if (c > 0) { r = __sic_bi_usub(a, b); r->sign = r->len ? a->sign : 0; }
        else       { r = __sic_bi_usub(b, a); r->sign = r->len ? b->sign : 0; }
    }
    return r;
}

__attribute__((weak)) __sic_bi *__sic_bi_neg(const __sic_bi *a) {
    __sic_bi *r = __sic_bi_clone(a);
    if (r->len) r->sign = -r->sign;
    return r;
}

__attribute__((weak)) __sic_bi *__sic_bi_sub(const __sic_bi *a, const __sic_bi *b) {
    __sic_bi *nb = __sic_bi_neg(b);
    __sic_bi *r = __sic_bi_add(a, nb);
    __sic_bi_free(nb);
    return r;
}

__attribute__((weak)) __sic_bi *__sic_bi_mul(const __sic_bi *a, const __sic_bi *b) {
    if (a->sign == 0 || b->sign == 0) return __sic_bi_from_i64(0);
    __sic_bi *r = __sic_bi_alloc(a->len + b->len);
    for (unsigned i = 0; i < a->len; i++) {
        unsigned long long carry = 0;
        for (unsigned j = 0; j < b->len; j++) {
            unsigned long long cur = (unsigned long long)a->limbs[i] * b->limbs[j]
                                   + r->limbs[i + j] + carry;
            r->limbs[i + j] = (unsigned)(cur & 0xffffffffu);
            carry = cur >> 32;
        }
        r->limbs[i + b->len] += (unsigned)carry;
    }
    r->len = a->len + b->len;
    r->sign = a->sign * b->sign;
    __sic_bi_norm(r);
    return r;
}

__attribute__((weak)) int __sic_bi_cmp(const __sic_bi *a, const __sic_bi *b) {
    if (a->sign != b->sign) return a->sign < b->sign ? -1 : 1;
    int u = __sic_bi_ucmp(a, b);
    return a->sign < 0 ? -u : u;
}

__attribute__((weak)) long long __sic_bi_to_i64(const __sic_bi *a) {
    unsigned long long u = 0;
    if (a->len > 0) u = a->limbs[0];
    if (a->len > 1) u |= (unsigned long long)a->limbs[1] << 32;
    long long v = (long long)u;
    return a->sign < 0 ? -v : v;
}

/* magnitude divmod by a small divisor; returns quotient, stores remainder */
__attribute__((weak)) __sic_bi *__sic_bi_divmod_small(const __sic_bi *a, unsigned d, unsigned *rem) {
    __sic_bi *q = __sic_bi_alloc(a->len);
    unsigned long long r = 0;
    unsigned i = a->len;
    while (i) {
        i--;
        unsigned long long cur = (r << 32) | a->limbs[i];
        q->limbs[i] = (unsigned)(cur / d);
        r = cur % d;
    }
    q->len = a->len;
    __sic_bi_norm(q);
    *rem = (unsigned)r;
    return q;
}

/* decimal string (malloc'd); caller frees */
__attribute__((weak)) char *__sic_bi_to_str(const __sic_bi *a) {
    if (a->sign == 0) { char *s = (char *)malloc(2); s[0] = '0'; s[1] = 0; return s; }
    unsigned cap = a->len * 10 + 3;
    char *buf = (char *)malloc(cap);
    unsigned pos = 0;
    __sic_bi *cur = __sic_bi_clone(a);
    cur->sign = 1;
    while (cur->len > 0) {
        unsigned rem = 0;
        __sic_bi *q = __sic_bi_divmod_small(cur, 10, &rem);
        __sic_bi_free(cur);
        cur = q;
        buf[pos++] = (char)('0' + rem);
    }
    __sic_bi_free(cur);
    if (a->sign < 0) buf[pos++] = '-';
    unsigned lo = 0, hi = pos - 1;
    while (lo < hi) { char t = buf[lo]; buf[lo] = buf[hi]; buf[hi] = t; lo++; hi--; }
    buf[pos] = 0;
    return buf;
}

/* ── fixed-point support (sic.md §"Built-in fixed point") ──────────────────
   A `fixed<I,F>` value is a bigint mantissa scaled by 10^F; the scale lives in
   the compile-time type. These helpers rescale a mantissa and format one with a
   decimal point — both purely on bigints, no floats. */

/* 10^n as a bigint */
__attribute__((weak)) __sic_bi *__sic_bi_pow10(unsigned n) {
    __sic_bi *r = __sic_bi_from_i64(1);
    for (unsigned i = 0; i < n; i++) {
        __sic_bi *t = __sic_bi_muladd_small(r, 10, 0);
        __sic_bi_free(r);
        r = t;
    }
    return r;
}

/* a / 10^n, truncating toward zero (for down-scaling a fixed mantissa) */
__attribute__((weak)) __sic_bi *__sic_bi_divpow10(const __sic_bi *a, unsigned n) {
    __sic_bi *cur = __sic_bi_clone(a);
    for (unsigned i = 0; i < n; i++) {
        unsigned rem = 0;
        __sic_bi *q = __sic_bi_divmod_small(cur, 10, &rem);
        __sic_bi_free(cur);
        cur = q;
    }
    return cur;
}

/* Format a fixed mantissa `m` at scale `scale` as a decimal string with a point
   (e.g. m=1234567, scale=3 -> "1234.567"). malloc'd; caller frees. */
__attribute__((weak)) char *__sic_fx_to_str(const __sic_bi *m, int scale) {
    char *digits = __sic_bi_to_str(m);              /* "-1234567" / "1234567" / "0" */
    if (scale <= 0) return digits;
    int neg = digits[0] == '-';
    char *d = digits + neg;
    unsigned dl = 0; while (d[dl]) dl++;
    unsigned s = (unsigned)scale;
    unsigned intlen = dl > s ? dl - s : 0;          /* integer-part digit count */
    unsigned pad = dl > s ? 0 : s - dl;             /* leading fraction zeros */
    unsigned outlen = (unsigned)neg + (intlen ? intlen : 1) + 1 + s + 1;
    char *out = (char *)malloc(outlen);
    unsigned p = 0;
    if (neg) out[p++] = '-';
    if (intlen == 0) out[p++] = '0';
    else for (unsigned i = 0; i < intlen; i++) out[p++] = d[i];
    out[p++] = '.';
    for (unsigned i = 0; i < pad; i++) out[p++] = '0';
    for (unsigned i = intlen; i < dl; i++) out[p++] = d[i];
    out[p] = 0;
    free(digits);
    return out;
}

/* ── division, shifts, bitwise ─────────────────────────────────────────────── */

/* magnitude division q = |a|/|b|, *rem = |a|%|b| (binary long division).
   Requires |b| != 0. Both outputs are non-negative. */
__attribute__((weak)) __sic_bi *__sic_bi_udivmod(const __sic_bi *a, const __sic_bi *b, __sic_bi **rem_out) {
    __sic_bi *q = __sic_bi_alloc(a->len);
    for (unsigned i = 0; i < a->len; i++) q->limbs[i] = 0;
    q->len = a->len;
    __sic_bi *r = __sic_bi_from_i64(0);
    int total = (int)a->len * 32;
    for (int i = total - 1; i >= 0; i--) {
        unsigned bit = (a->limbs[i / 32] >> (i % 32)) & 1u;
        __sic_bi *nr = __sic_bi_muladd_small(r, 2, bit);   /* r = (r<<1) | bit */
        __sic_bi_free(r);
        r = nr;
        if (__sic_bi_ucmp(r, b) >= 0) {
            __sic_bi *sr = __sic_bi_usub(r, b);
            __sic_bi_free(r);
            r = sr;
            q->limbs[i / 32] |= (1u << (i % 32));
        }
    }
    __sic_bi_norm(q);
    q->sign = q->len ? 1 : 0;
    r->sign = r->len ? 1 : 0;
    *rem_out = r;
    return q;
}

/* signed divmod: quotient truncates toward zero, remainder takes the dividend's
   sign (C semantics). Division by zero yields 0 (sic's defined behavior). */
__attribute__((weak)) __sic_bi *__sic_bi_divmod(const __sic_bi *a, const __sic_bi *b, __sic_bi **rem_out) {
    if (b->sign == 0) { *rem_out = __sic_bi_from_i64(0); return __sic_bi_from_i64(0); }
    __sic_bi *rmag;
    __sic_bi *q = __sic_bi_udivmod(a, b, &rmag);
    q->sign = q->len ? a->sign * b->sign : 0;
    rmag->sign = rmag->len ? a->sign : 0;
    *rem_out = rmag;
    return q;
}

__attribute__((weak)) __sic_bi *__sic_bi_div(const __sic_bi *a, const __sic_bi *b) {
    __sic_bi *r; __sic_bi *q = __sic_bi_divmod(a, b, &r); __sic_bi_free(r); return q;
}

__attribute__((weak)) __sic_bi *__sic_bi_mod(const __sic_bi *a, const __sic_bi *b) {
    __sic_bi *r; __sic_bi *q = __sic_bi_divmod(a, b, &r); __sic_bi_free(q); return r;
}

/* a << n (a * 2^n); sign preserved */
__attribute__((weak)) __sic_bi *__sic_bi_shl(const __sic_bi *a, unsigned n) {
    if (a->sign == 0) return __sic_bi_from_i64(0);
    unsigned ls = n / 32, bs = n % 32;
    __sic_bi *r = __sic_bi_alloc(a->len + ls + 1);
    for (unsigned i = 0; i < a->len + ls + 1; i++) r->limbs[i] = 0;
    for (unsigned i = 0; i < a->len; i++) {
        unsigned long long v = (unsigned long long)a->limbs[i] << bs;
        r->limbs[i + ls]     |= (unsigned)(v & 0xffffffffu);
        r->limbs[i + ls + 1] |= (unsigned)(v >> 32);
    }
    r->len = a->len + ls + 1;
    __sic_bi_norm(r);
    r->sign = r->len ? a->sign : 0;
    return r;
}

/* a >> n (magnitude / 2^n, truncating toward zero); sign preserved */
__attribute__((weak)) __sic_bi *__sic_bi_shr(const __sic_bi *a, unsigned n) {
    unsigned ls = n / 32, bs = n % 32;
    if (ls >= a->len) return __sic_bi_from_i64(0);
    unsigned rl = a->len - ls;
    __sic_bi *r = __sic_bi_alloc(rl);
    for (unsigned j = 0; j < rl; j++) {
        unsigned lo = a->limbs[j + ls] >> bs;
        unsigned hi = 0;
        if (bs && (j + ls + 1) < a->len) hi = a->limbs[j + ls + 1] << (32 - bs);
        r->limbs[j] = lo | hi;
    }
    r->len = rl;
    __sic_bi_norm(r);
    r->sign = r->len ? a->sign : 0;
    return r;
}

/* fill out[0..W) with the two's-complement limbs of `a` over W limbs */
__attribute__((weak)) void __sic_bi_tc(const __sic_bi *a, unsigned W, unsigned *out) {
    for (unsigned i = 0; i < W; i++) out[i] = i < a->len ? a->limbs[i] : 0;
    if (a->sign < 0) {
        for (unsigned i = 0; i < W; i++) out[i] = ~out[i];
        unsigned long long carry = 1;
        for (unsigned i = 0; i < W && carry; i++) {
            unsigned long long s = (unsigned long long)out[i] + carry;
            out[i] = (unsigned)s; carry = s >> 32;
        }
    }
}

/* bitwise over infinite two's-complement: op 0=&, 1=|, 2=^ */
__attribute__((weak)) __sic_bi *__sic_bi_bitop(const __sic_bi *a, const __sic_bi *b, int op) {
    unsigned W = (a->len > b->len ? a->len : b->len) + 1;
    unsigned *ta = (unsigned *)malloc((unsigned long)W * 4);
    unsigned *tb = (unsigned *)malloc((unsigned long)W * 4);
    __sic_bi_tc(a, W, ta);
    __sic_bi_tc(b, W, tb);
    __sic_bi *r = __sic_bi_alloc(W);
    for (unsigned i = 0; i < W; i++) {
        unsigned v = op == 0 ? (ta[i] & tb[i]) : op == 1 ? (ta[i] | tb[i]) : (ta[i] ^ tb[i]);
        r->limbs[i] = v;
    }
    int neg = (r->limbs[W - 1] >> 31) & 1;
    if (neg) {
        for (unsigned i = 0; i < W; i++) r->limbs[i] = ~r->limbs[i];
        unsigned long long carry = 1;
        for (unsigned i = 0; i < W && carry; i++) {
            unsigned long long s = (unsigned long long)r->limbs[i] + carry;
            r->limbs[i] = (unsigned)s; carry = s >> 32;
        }
    }
    r->len = W;
    __sic_bi_norm(r);
    r->sign = r->len ? (neg ? -1 : 1) : 0;
    free(ta); free(tb);
    return r;
}

__attribute__((weak)) __sic_bi *__sic_bi_and(const __sic_bi *a, const __sic_bi *b) { return __sic_bi_bitop(a, b, 0); }
__attribute__((weak)) __sic_bi *__sic_bi_or (const __sic_bi *a, const __sic_bi *b) { return __sic_bi_bitop(a, b, 1); }
__attribute__((weak)) __sic_bi *__sic_bi_xor(const __sic_bi *a, const __sic_bi *b) { return __sic_bi_bitop(a, b, 2); }

/* ~a = -a - 1 */
__attribute__((weak)) __sic_bi *__sic_bi_not(const __sic_bi *a) {
    __sic_bi *na = __sic_bi_neg(a);
    __sic_bi *one = __sic_bi_from_i64(1);
    __sic_bi *r = __sic_bi_sub(na, one);
    __sic_bi_free(na); __sic_bi_free(one);
    return r;
}
"#;

/// True if `src` (post-preprocess text) uses `bigint` or `fixed` as a whole
/// word — the signal to prepend [`BIGINT_RUNTIME`] (fixed-point is built on the
/// same runtime). A bare substring match is avoided so `bigintish`/`fixedly` or a
/// string literal doesn't trigger it.
pub fn uses_bignum(src: &str) -> bool {
    word_present(src, "bigint") || word_present(src, "fixed")
}

fn word_present(src: &str, word: &str) -> bool {
    let bytes = src.as_bytes();
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while let Some(off) = src[i..].find(word) {
        let start = i + off;
        let end = start + word.len();
        let before_ok = start == 0 || !is_ident(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_ident(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        i = start + 1;
    }
    false
}
