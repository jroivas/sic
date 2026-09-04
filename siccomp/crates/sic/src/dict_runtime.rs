//! Self-contained hash-map runtime for sic's built-in `dict` (sic.md §"Dict").
//! Plain C over `malloc`/`realloc`/`free` — no external library — prepended to a
//! translation unit only when it uses `dict` (see [`uses_dict`]). Every function is
//! `__attribute__((weak))` so copies dedupe at link and unused ones are dropped.
//!
//! Design follows CPython's dict: an insertion-ordered `entries` array plus a
//! sparse open-addressing `index` table of entry slots, so iteration order is stable
//! and deletions leave the order of surviving keys intact. Keys are tagged
//! `(kind, a, b)`: kind 1 = integer (`a` = value), kind 2 = string (`a` = byte
//! pointer, `b` = length; the bytes are copied and owned by the dict), kind 3 =
//! pointer (`a` = address). Values are a single 64-bit slot (an integer or a
//! pointer). This is enough for `dict<K,int>` and `dict` with int/pointer values;
//! richer value types build on the same table.
//!
//! Keeping the key kind explicit leaves room for the planned type-specialized
//! optimization: when the frontend knows the key is, say, `int`, it can eventually
//! call a monomorphic fast path instead of the tagged one.

/// The runtime source, prepended (post-preprocess) ahead of the user code.
pub const DICT_RUNTIME: &str = r#"
extern void *malloc(unsigned long);
extern void *realloc(void *, unsigned long);
extern void free(void *);
extern void *memcpy(void *, const void *, unsigned long);
extern int memcmp(const void *, const void *, unsigned long);

typedef struct __sic_dent {
    unsigned long hash;
    unsigned long a;     /* int value / string byte pointer / address */
    unsigned long b;     /* string length (0 otherwise) */
    unsigned long val;   /* value slot */
    int kind;            /* 1 int, 2 string, 3 pointer */
    int live;            /* 0 = tombstone */
} __sic_dent;

typedef struct __sic_dict {
    int *index;          /* open-addressing slots: -1 empty, -2 deleted, else entry # */
    unsigned long cap;   /* index size, power of two */
    __sic_dent *ents;    /* entries in insertion order */
    unsigned long nents; /* entries used (incl. tombstones) */
    unsigned long ecap;  /* entries capacity */
    unsigned long live;  /* live entry count */
} __sic_dict;

__attribute__((weak)) unsigned long __sic_dict_hash(int kind, unsigned long a, unsigned long b) {
    unsigned long h = 1469598103934665603UL; /* FNV-1a offset */
    if (kind == 2) {
        const unsigned char *p = (const unsigned char *)a;
        for (unsigned long i = 0; i < b; i++) { h ^= p[i]; h *= 1099511628211UL; }
    } else {
        unsigned long x = a;
        for (int i = 0; i < 8; i++) { h ^= (x & 0xff); h *= 1099511628211UL; x >>= 8; }
    }
    if (h == 0) h = 1;
    return h;
}

__attribute__((weak)) int __sic_dent_eq(const __sic_dent *e, int kind, unsigned long a, unsigned long b) {
    if (e->kind != kind) return 0;
    if (kind == 2) return e->b == b && (b == 0 || memcmp((const void *)e->a, (const void *)a, b) == 0);
    return e->a == a;
}

__attribute__((weak)) __sic_dict *__sic_dict_new(void) {
    __sic_dict *d = (__sic_dict *)malloc(sizeof(__sic_dict));
    d->cap = 8;
    d->index = (int *)malloc(sizeof(int) * d->cap);
    for (unsigned long i = 0; i < d->cap; i++) d->index[i] = -1;
    d->ecap = 8;
    d->ents = (__sic_dent *)malloc(sizeof(__sic_dent) * d->ecap);
    d->nents = 0;
    d->live = 0;
    return d;
}

/* Probe the index for a key; returns the index slot. On a match, *ent is the entry
   number; otherwise *ent is -1 and the slot is where an insert would go (preferring
   the first tombstone seen). */
__attribute__((weak)) unsigned long __sic_dict_probe(
        __sic_dict *d, unsigned long h, int kind, unsigned long a, unsigned long b, int *ent) {
    unsigned long mask = d->cap - 1;
    unsigned long i = h & mask;
    long first_del = -1;
    for (;;) {
        int slot = d->index[i];
        if (slot == -1) { *ent = -1; return (first_del >= 0) ? (unsigned long)first_del : i; }
        if (slot == -2) { if (first_del < 0) first_del = (long)i; }
        else {
            __sic_dent *e = &d->ents[slot];
            if (e->live && e->hash == h && __sic_dent_eq(e, kind, a, b)) { *ent = slot; return i; }
        }
        i = (i + 1) & mask;
    }
}

__attribute__((weak)) void __sic_dict_grow_index(__sic_dict *d) {
    unsigned long ncap = d->cap * 2;
    int *ni = (int *)malloc(sizeof(int) * ncap);
    for (unsigned long i = 0; i < ncap; i++) ni[i] = -1;
    unsigned long mask = ncap - 1;
    for (unsigned long e = 0; e < d->nents; e++) {
        if (!d->ents[e].live) continue;
        unsigned long i = d->ents[e].hash & mask;
        while (ni[i] != -1) i = (i + 1) & mask;
        ni[i] = (int)e;
    }
    free(d->index);
    d->index = ni;
    d->cap = ncap;
}

__attribute__((weak)) void __sic_dict_set(
        __sic_dict *d, int kind, unsigned long a, unsigned long b, unsigned long val) {
    unsigned long h = __sic_dict_hash(kind, a, b);
    int ent;
    unsigned long slot = __sic_dict_probe(d, h, kind, a, b, &ent);
    if (ent >= 0) { d->ents[ent].val = val; return; }
    /* Grow the index if it is getting full (load factor 2/3), then re-probe. */
    if ((d->live + 1) * 3 >= d->cap * 2) {
        __sic_dict_grow_index(d);
        slot = __sic_dict_probe(d, h, kind, a, b, &ent);
    }
    if (d->nents >= d->ecap) {
        d->ecap *= 2;
        d->ents = (__sic_dent *)realloc(d->ents, sizeof(__sic_dent) * d->ecap);
    }
    unsigned long ka = a;
    if (kind == 2) { /* own a copy of the key bytes */
        unsigned char *p = (unsigned char *)malloc(b ? b : 1);
        if (b) memcpy(p, (const void *)a, b);
        ka = (unsigned long)p;
    }
    unsigned long e = d->nents++;
    d->ents[e].hash = h; d->ents[e].kind = kind; d->ents[e].a = ka;
    d->ents[e].b = b; d->ents[e].val = val; d->ents[e].live = 1;
    d->index[slot] = (int)e;
    d->live++;
}

__attribute__((weak)) int __sic_dict_get(
        __sic_dict *d, int kind, unsigned long a, unsigned long b, unsigned long *out) {
    unsigned long h = __sic_dict_hash(kind, a, b);
    int ent;
    __sic_dict_probe(d, h, kind, a, b, &ent);
    if (ent < 0) { *out = 0; return 0; }
    *out = d->ents[ent].val;
    return 1;
}

__attribute__((weak)) int __sic_dict_del(__sic_dict *d, int kind, unsigned long a, unsigned long b) {
    unsigned long h = __sic_dict_hash(kind, a, b);
    int ent;
    unsigned long slot = __sic_dict_probe(d, h, kind, a, b, &ent);
    if (ent < 0) return 0;
    if (d->ents[ent].kind == 2) free((void *)d->ents[ent].a);
    d->ents[ent].live = 0;
    d->index[slot] = -2;
    d->live--;
    return 1;
}

__attribute__((weak)) unsigned long __sic_dict_len(__sic_dict *d) { return d ? d->live : 0; }

__attribute__((weak)) void __sic_dict_free(__sic_dict *d) {
    if (!d) return;
    for (unsigned long e = 0; e < d->nents; e++)
        if (d->ents[e].live && d->ents[e].kind == 2) free((void *)d->ents[e].a);
    free(d->ents);
    free(d->index);
    free(d);
}
"#;

/// True if `src` uses the `dict` type (so the runtime must be prepended). A crude
/// word-boundary scan for the `dict` keyword, ignoring substrings like `predict`.
pub fn uses_dict(src: &str) -> bool {
    let bytes = src.as_bytes();
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while let Some(pos) = src[i..].find("dict") {
        let start = i + pos;
        let end = start + 4;
        let before_ok = start == 0 || !is_word(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_word(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        i = end;
    }
    false
}
