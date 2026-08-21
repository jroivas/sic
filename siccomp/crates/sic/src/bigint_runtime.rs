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
"#;

/// True if `src` (post-preprocess text) uses the `bigint` keyword as a whole
/// word — the signal to prepend [`BIGINT_RUNTIME`]. A bare substring match is
/// avoided so `bigintish` or a string literal doesn't trigger it.
pub fn uses_bigint(src: &str) -> bool {
    let bytes = src.as_bytes();
    let word = b"bigint";
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while let Some(off) = src[i..].find("bigint") {
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
