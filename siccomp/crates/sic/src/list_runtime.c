extern void *malloc(unsigned long);
extern void *realloc(void *, unsigned long);
extern void free(void *);

/* A growable list: parallel arrays of the same (type-info, slot, owned) element box
   the dict runtime uses, so strings/structs are owned and freed identically. */
typedef struct __sic_list {
    unsigned long *vty;
    unsigned long *vslot;
    int *vowned;
    unsigned long len;
    unsigned long cap;
} __sic_list;

__attribute__((weak)) __sic_list *__sic_list_new(void) {
    __sic_list *l = (__sic_list *)malloc(sizeof(__sic_list));
    l->cap = 8;
    l->len = 0;
    l->vty = (unsigned long *)malloc(sizeof(unsigned long) * l->cap);
    l->vslot = (unsigned long *)malloc(sizeof(unsigned long) * l->cap);
    l->vowned = (int *)malloc(sizeof(int) * l->cap);
    return l;
}

__attribute__((weak)) void __sic_list_push(__sic_list *l, unsigned long vty, unsigned long vslot, int vowned) {
    if (l->len >= l->cap) {
        l->cap = l->cap * 2;
        l->vty = (unsigned long *)realloc(l->vty, sizeof(unsigned long) * l->cap);
        l->vslot = (unsigned long *)realloc(l->vslot, sizeof(unsigned long) * l->cap);
        l->vowned = (int *)realloc(l->vowned, sizeof(int) * l->cap);
    }
    l->vty[l->len] = vty;
    l->vslot[l->len] = vslot;
    l->vowned[l->len] = vowned;
    l->len = l->len + 1;
}

/* Read element i into *oty/*oslot; out-of-range reads back as 0 (returns found). */
__attribute__((weak)) int __sic_list_get(__sic_list *l, unsigned long i, unsigned long *oty, unsigned long *oslot) {
    if (!l || i >= l->len) { *oty = 0; *oslot = 0; return 0; }
    *oty = l->vty[i];
    *oslot = l->vslot[i];
    return 1;
}

__attribute__((weak)) void __sic_list_set(__sic_list *l, unsigned long i, unsigned long vty, unsigned long vslot, int vowned) {
    if (!l || i >= l->len) return;
    if (l->vowned[i]) free((void *)l->vslot[i]);  /* reclaim the replaced element */
    l->vty[i] = vty;
    l->vslot[i] = vslot;
    l->vowned[i] = vowned;
}

__attribute__((weak)) unsigned long __sic_list_len(__sic_list *l) { return l ? l->len : 0; }

/* `.values` (sic.md §"Iterators"): a fresh list with each element BORROWED
   (vowned=0 — the source list keeps ownership). */
__attribute__((weak)) __sic_list *__sic_list_values(__sic_list *l) {
    __sic_list *r = __sic_list_new();
    if (l) for (unsigned long i = 0; i < l->len; i++)
        __sic_list_push(r, l->vty[i], l->vslot[i], 0);
    return r;
}

/* `.keys` (sic.md §"Iterators"): a fresh list of the indices 0..len-1. */
__attribute__((weak)) __sic_list *__sic_list_keys(__sic_list *l) {
    __sic_list *r = __sic_list_new();
    if (l) for (unsigned long i = 0; i < l->len; i++)
        __sic_list_push(r, 0, i, 0);
    return r;
}

__attribute__((weak)) void __sic_list_free(__sic_list *l) {
    if (!l) return;
    for (unsigned long i = 0; i < l->len; i++)
        if (l->vowned[i]) free((void *)l->vslot[i]);
    free(l->vty);
    free(l->vslot);
    free(l->vowned);
    free(l);
}
