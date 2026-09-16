extern void *malloc(unsigned long);
extern void *realloc(void *, unsigned long);
extern void free(void *);
extern void *memcpy(void *, const void *, unsigned long);
extern int memcmp(const void *, const void *, unsigned long);
/* Reclaim an owned value box by its `vowned` kind (1 = plain block, 2 = refcounted
   string). Defined in the list runtime, which is prepended whenever dict is used. */
extern void __sic_box_free(unsigned long vslot, int vowned);

typedef struct __sic_dent {
    unsigned long hash;
    unsigned long a;     /* int value / string byte pointer / address */
    unsigned long b;     /* string length (0 otherwise) */
    unsigned long vty;   /* value type-info pointer (0 for a plain scalar) */
    unsigned long vslot; /* value slot (scalar bits or aggregate pointer) */
    int kind;            /* 1 int, 2 string, 3 pointer */
    int live;            /* 0 = tombstone */
    int vowned;          /* 1 = `vslot` is a single owned heap block to free */
} __sic_dent;

typedef struct __sic_dict {
    int *index;          /* open-addressing slots: -1 empty, -2 deleted, else entry # */
    unsigned long cap;   /* index size, power of two */
    __sic_dent *ents;    /* entries in insertion order */
    unsigned long nents; /* entries used (incl. tombstones) */
    unsigned long ecap;  /* entries capacity */
    unsigned long live;  /* live entry count */
    unsigned long rc;    /* strong references (owners), freed at 0 */
    unsigned long wrc;   /* weak references (sic.md "Weak"): don't keep it alive */
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
    d->rc = 1;
    d->wrc = 0;
    return d;
}

/* Share the handle: another owner (a binding, a return, a closure capture). */
__attribute__((weak)) void __sic_dict_retain(__sic_dict *d) {
    if (d) d->rc++;
}

/* sic weak references (sic.md §"Weak"): weak counts don't keep the dict alive;
   `upgrade` returns a fresh strong reference if still live, else NULL. */
__attribute__((weak)) void __sic_dict_weak_retain(__sic_dict *d) {
    if (d) d->wrc++;
}
__attribute__((weak)) void __sic_dict_weak_release(__sic_dict *d) {
    if (d && --d->wrc == 0 && d->rc == 0) free(d);
}
__attribute__((weak)) __sic_dict *__sic_dict_upgrade(__sic_dict *d) {
    if (d && d->rc > 0) { d->rc++; return d; }
    return 0;
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
        __sic_dict *d, int kind, unsigned long a, unsigned long b,
        unsigned long vty, unsigned long vslot, int vowned) {
    unsigned long h = __sic_dict_hash(kind, a, b);
    int ent;
    unsigned long slot = __sic_dict_probe(d, h, kind, a, b, &ent);
    if (ent >= 0) {
        __sic_box_free(d->ents[ent].vslot, d->ents[ent].vowned); /* reclaim old */
        d->ents[ent].vty = vty; d->ents[ent].vslot = vslot; d->ents[ent].vowned = vowned;
        return;
    }
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
    d->ents[e].b = b; d->ents[e].vty = vty; d->ents[e].vslot = vslot;
    d->ents[e].vowned = vowned; d->ents[e].live = 1;
    d->index[slot] = (int)e;
    d->live++;
}

__attribute__((weak)) int __sic_dict_get(
        __sic_dict *d, int kind, unsigned long a, unsigned long b,
        unsigned long *out_ty, unsigned long *out_slot) {
    if (!d) { *out_ty = 0; *out_slot = 0; return 0; }   /* a null (empty) va_dict */
    unsigned long h = __sic_dict_hash(kind, a, b);
    int ent;
    __sic_dict_probe(d, h, kind, a, b, &ent);
    if (ent < 0) { *out_ty = 0; *out_slot = 0; return 0; }
    *out_ty = d->ents[ent].vty;
    *out_slot = d->ents[ent].vslot;
    return 1;
}

__attribute__((weak)) int __sic_dict_del(__sic_dict *d, int kind, unsigned long a, unsigned long b) {
    if (!d) return 0;
    unsigned long h = __sic_dict_hash(kind, a, b);
    int ent;
    unsigned long slot = __sic_dict_probe(d, h, kind, a, b, &ent);
    if (ent < 0) return 0;
    if (d->ents[ent].kind == 2) free((void *)d->ents[ent].a);   /* string key bytes */
    __sic_box_free(d->ents[ent].vslot, d->ents[ent].vowned);    /* owned value */
    d->ents[ent].live = 0;
    d->index[slot] = -2;
    d->live--;
    return 1;
}

__attribute__((weak)) unsigned long __sic_dict_len(__sic_dict *d) { return d ? d->live : 0; }

/* Release one strong reference; at zero free the owned keys/values and arrays.
   The handle struct is kept while weak references remain, freed by the last weak
   release. */
__attribute__((weak)) void __sic_dict_free(__sic_dict *d) {
    if (!d || d->rc == 0 || --d->rc != 0) return;
    for (unsigned long e = 0; e < d->nents; e++) {
        if (!d->ents[e].live) continue;
        if (d->ents[e].kind == 2) free((void *)d->ents[e].a);   /* string key bytes */
        __sic_box_free(d->ents[e].vslot, d->ents[e].vowned);    /* owned value */
    }
    free(d->ents);
    free(d->index);
    d->ents = 0; d->index = 0; d->nents = 0; d->live = 0; d->cap = 0;
    if (d->wrc == 0) free(d);
}

/* ── Enumeration → `list` (sic.md §"Iterators", `.keys`/`.values`) ────────────
   These build a `list` handle from a dict's live entries in insertion order,
   reusing the list runtime (prepended alongside dict). The list value-box is the
   same (vty, vslot, vowned) triple as a dict value, so `values` copies it
   directly (BORROWED, vowned=0 — the dict keeps ownership). Scalar keys box as
   (0, key, 0); string keys are rebuilt as OWNED sic strings so the list can
   outlive the dict's own key bytes. */
struct __sic_list;
extern struct __sic_list *__sic_list_new(void);
extern void __sic_list_push(struct __sic_list *, unsigned long, unsigned long, int);

/* Build a refcounted OWNED sic `string` block from raw bytes, matching the
   frontend's `emit_dict_owned_string` layout: [ rc cell (1 word) | {data,size,rc}
   descriptor (3 words) | bytes | NUL ]. The rc cell sits at the block base, so the
   descriptor's rc field == the block base and one __sic_box_free (vowned 2)
   reclaims the whole thing. Returns the DESCRIPTOR pointer. 64-bit word = 8. */
__attribute__((weak)) void *__sic_str_owned(const char *src, unsigned long n) {
    unsigned long hdr = 24, ps = 8;             /* descriptor size, pointer size */
    char *block = (char *)malloc(n + hdr + ps + 1);
    *(unsigned long *)block = 1;                 /* rc cell at the block base */
    char *desc = block + ps;
    char *bytes = block + ps + hdr;
    if (n) memcpy(bytes, src, n);
    bytes[n] = 0;
    void **dsc = (void **)desc;
    dsc[0] = bytes;                             /* data */
    ((unsigned long *)desc)[1] = n;             /* size */
    dsc[2] = block;                             /* rc = block base */
    return desc;
}

__attribute__((weak)) void *__sic_dict_values(__sic_dict *d) {
    struct __sic_list *l = __sic_list_new();
    if (d) for (unsigned long e = 0; e < d->nents; e++)
        if (d->ents[e].live)
            __sic_list_push(l, d->ents[e].vty, d->ents[e].vslot, 0);
    return l;
}

__attribute__((weak)) void *__sic_dict_keys_scalar(__sic_dict *d) {
    struct __sic_list *l = __sic_list_new();
    if (d) for (unsigned long e = 0; e < d->nents; e++)
        if (d->ents[e].live)
            __sic_list_push(l, 0, d->ents[e].a, 0);
    return l;
}

__attribute__((weak)) void *__sic_dict_keys_string(__sic_dict *d) {
    struct __sic_list *l = __sic_list_new();
    if (d) for (unsigned long e = 0; e < d->nents; e++)
        if (d->ents[e].live)
            __sic_list_push(l, 0, (unsigned long)__sic_str_owned(
                (const char *)d->ents[e].a, d->ents[e].b), 2);
    return l;
}
