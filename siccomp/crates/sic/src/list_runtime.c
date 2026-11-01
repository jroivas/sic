extern void *malloc(unsigned long);
extern void *realloc(void *, unsigned long);
extern void free(void *);
extern void *memcpy(void *, const void *, unsigned long);

/* Forward references for container-element release (a `list`/`dict`/`set` stored
   inside a container is refcounted). `__sic_dict_free` lives in the dict runtime,
   which is co-prepended whenever a dict is used; the weak reference resolves to 0
   in a list-only program (which never stores a dict, so it is never called). */
struct __sic_list;
void __sic_list_free(struct __sic_list *);
void __sic_list_weak_release(struct __sic_list *);
extern __attribute__((weak)) void __sic_dict_free(void *);
extern __attribute__((weak)) void __sic_dict_weak_release(void *);

/* Release a tuple stored as a container element (sic.md §"Tuples"): mirrors the
   compiler's `emit_tuple_release` — a 4-word header `[shape | __dtor | count | rc]`
   with the data pointer past it. Decrement rc; at zero run the per-layout element
   destructor (releasing the tuple's own refcounted elements) and free the block. */
__attribute__((weak)) void __sic_tuple_release(void *data) {
    if (!data) return;
    unsigned long *p = (unsigned long *)data;
    unsigned long *rc = p - 1;                 /* rc at data - 1 word */
    if (--(*rc) != 0) return;
    void (*dtor)(void *) = *(void (**)(void *))(p - 3);  /* __dtor at data - 3 words */
    if (dtor) dtor(data);
    free((void *)(p - 4));                      /* block base = data - 4 words */
}

/* Release one reference to a string block (the frontend's `__sic_str_release`
   does the same): `rc` <= 1 is a non-owning view; otherwise the count is the low
   bits of `*rc`, and its top bit marks a foreign block (`[count | FLAG][finalizer]
   […]`, made by the Rust glue) whose finalizer — not `free` — releases it. */
__attribute__((weak)) void __sic_str_rc_release(unsigned long *rc) {
    if ((unsigned long)rc <= 1) return;
    const unsigned long flag = 1UL << (sizeof(unsigned long) * 8 - 1);
    unsigned long n = --(*rc);
    if ((n & ~flag) != 0) return;
    if (n & flag) ((void (*)(void *))rc[1])((void *)rc);
    else free((void *)rc);
}

/* Reclaim a container element's owned value by its `vowned` kind (shared by the
   list and dict runtimes; sic.md §"Dict"/§"List"):
     1 = a plain owned heap block (a deep-copied struct) — raw free;
     2 = a refcounted `string` block — `vslot` is the descriptor and its rc field
         (word 2) is the block base, so decrement the rc and free only at 0 (a
         reader that copied the descriptor and retained keeps it alive);
     3/4 = a nested list / dict handle, 5/6 = a weak one, 7 = a tuple;
     8 = a deep-copied managed struct: its destructor runs before the free.
   A borrowed value (vowned 0) is left alone. */
__attribute__((weak)) void __sic_box_free(unsigned long vslot, int vowned) {
    if (vowned == 1) {
        free((void *)vslot);
    } else if (vowned == 2) {
        unsigned long *desc = (unsigned long *)vslot;
        __sic_str_rc_release((unsigned long *)desc[2]);
    } else if (vowned == 3) {
        /* a nested `list`/`set-of-list` handle — release one reference */
        __sic_list_free((struct __sic_list *)vslot);
    } else if (vowned == 4) {
        /* a nested `dict`/`set` handle — release one reference */
        if (__sic_dict_free) __sic_dict_free((void *)vslot);
    } else if (vowned == 5) {
        /* a weak `list` element (`list<weak<list>>`) — drop the weak count only */
        __sic_list_weak_release((struct __sic_list *)vslot);
    } else if (vowned == 6) {
        /* a weak `dict`/`set` element — drop the weak count only */
        if (__sic_dict_weak_release) __sic_dict_weak_release((void *)vslot);
    } else if (vowned == 7) {
        /* a `tuple` element — release one reference (runs its element dtor at 0) */
        __sic_tuple_release((void *)vslot);
    } else if (vowned == 8) {
        /* a deep-copied MANAGED struct (one with a destructor): the block is
           [dtor | pad | data…] with `vslot` = data; destroy, then free the block */
        void **hdr = (void **)vslot - 2;
        void (*dtor)(void *) = (void (*)(void *))hdr[0];
        if (dtor) dtor((void *)vslot);
        free(hdr);
    }
}

/* A growable list: parallel arrays of the same (type-info, slot, owned) element box
   the dict runtime uses, so strings/structs are owned and freed identically. `rc`
   is the reference count (sic.md §"List"): the handle is shared by retain and
   released by `__sic_list_free`, freed only when the last owner drops it, so a
   returned/captured list outlives the scope that created it. */
typedef struct __sic_list {
    unsigned long *vty;
    unsigned long *vslot;
    int *vowned;
    unsigned long len;
    unsigned long cap;
    unsigned long rc;    /* strong references (owners) */
    unsigned long wrc;   /* weak references (sic.md §"Weak"): don't keep it alive */
    /* Boxes of `any` elements popped: an `any` only borrows, so what it points at
       stays until the list goes, as for one read with `l[i]`. */
    unsigned long *retired;
    int *retired_owned;
    unsigned long nretired;
} __sic_list;

__attribute__((weak)) __sic_list *__sic_list_new(void) {
    __sic_list *l = (__sic_list *)malloc(sizeof(__sic_list));
    l->cap = 8;
    l->len = 0;
    l->rc = 1;
    l->wrc = 0;
    l->retired = 0;
    l->retired_owned = 0;
    l->nretired = 0;
    l->vty = (unsigned long *)malloc(sizeof(unsigned long) * l->cap);
    l->vslot = (unsigned long *)malloc(sizeof(unsigned long) * l->cap);
    l->vowned = (int *)malloc(sizeof(int) * l->cap);
    return l;
}

/* Share the handle: another owner (a binding, a return, a closure capture). */
__attribute__((weak)) void __sic_list_retain(__sic_list *l) {
    if (l) l->rc++;
}

/* sic weak references (sic.md §"Weak"): a weak ref does not keep the list alive.
   `weak_retain`/`weak_release` count weak owners; `upgrade` returns the handle
   with a fresh STRONG reference if it is still live, else NULL — so a weak ref
   detects a freed container and breaks reference cycles. */
__attribute__((weak)) void __sic_list_weak_retain(__sic_list *l) {
    if (l) l->wrc++;
}
__attribute__((weak)) void __sic_list_weak_release(__sic_list *l) {
    if (l && --l->wrc == 0 && l->rc == 0) free(l);   /* contents already freed at rc==0 */
}
__attribute__((weak)) __sic_list *__sic_list_upgrade(__sic_list *l) {
    if (l && l->rc > 0) { l->rc++; return l; }
    return 0;
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
    __sic_box_free(l->vslot[i], l->vowned[i]);    /* reclaim the replaced element */
    l->vty[i] = vty;
    l->vslot[i] = vslot;
    l->vowned[i] = vowned;
}

__attribute__((weak)) unsigned long __sic_list_len(__sic_list *l) { return l ? l->len : 0; }

/* Drop the last element, if any (the second half of `l.pop()`). */
__attribute__((weak)) void __sic_list_drop_last(__sic_list *l) {
    if (!l || l->len == 0) return;
    l->len--;
    __sic_box_free(l->vslot[l->len], l->vowned[l->len]);
}

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

/* Release one strong reference; at zero free the owned elements and the arrays.
   The handle struct itself is kept while weak references remain (so they can see
   it is dead), and freed by the last weak release. */
__attribute__((weak)) void __sic_list_free(__sic_list *l) {
    if (!l || l->rc == 0 || --l->rc != 0) return;
    for (unsigned long i = 0; i < l->len; i++)
        __sic_box_free(l->vslot[i], l->vowned[i]);
    for (unsigned long i = 0; i < l->nretired; i++)
        __sic_box_free(l->retired[i], l->retired_owned[i]);
    free(l->retired);
    free(l->retired_owned);
    l->retired = 0; l->retired_owned = 0; l->nretired = 0;
    free(l->vty);
    free(l->vslot);
    free(l->vowned);
    l->vty = 0; l->vslot = 0; l->vowned = 0; l->len = 0; l->cap = 0;
    if (l->wrc == 0) free(l);
}

/* ── `clone()` (sic.md §"Copying: clone") ──────────────────────────────────────
   An independent copy of a container: every element is copied by its type, so
   nothing is shared with the original. The type comes from the element's own
   type-info (`vty`, an `any` element) or else the container's element type
   `ti`, which the compiler passes. A type-info is `{ name; id; size; kind;
   clone }`: `clone` makes a byte copy of a value independent (null when the
   bytes are the whole value). */
typedef struct __sic_elem_tinfo {
    const char *name; unsigned long id; unsigned int size; unsigned int kind;
    void (*clone)(void *);
} __sic_elem_tinfo;
struct __sic_dict;
extern __attribute__((weak)) struct __sic_dict *__sic_dict_clone(struct __sic_dict *, const __sic_elem_tinfo *);
extern __attribute__((weak)) void __sic_dict_weak_retain(struct __sic_dict *);
__sic_list *__sic_list_clone(__sic_list *l, const __sic_elem_tinfo *ti);
extern int dprintf(int fd, const char *fmt, ...);
extern void abort(void);

/* A type the runtime cannot copy reached a container clone. */
__attribute__((weak)) void __sic_cannot_clone(const char *what) {
    dprintf(2, "cannot clone %s\n", what);
    abort();
}

/* An owned string box `[rc | {data, size, rc} | bytes | NUL]`; `vslot` is the
   descriptor. */
__attribute__((weak)) unsigned long __sic_str_box_clone(unsigned long vslot) {
    unsigned long *desc = (unsigned long *)vslot;
    unsigned long size = desc[1];
    unsigned long *block = (unsigned long *)malloc(sizeof(unsigned long) * 4 + size + 1);
    unsigned char *bytes = (unsigned char *)(block + 4);
    if (size) memcpy(bytes, (const void *)desc[0], size);
    bytes[size] = 0;
    block[0] = 1;
    block[1] = (unsigned long)bytes;
    block[2] = size;
    block[3] = (unsigned long)block;
    return (unsigned long)(block + 1);
}

/* A copy of one element box, by its `vowned` kind and its type `ti`. */
__attribute__((weak)) unsigned long __sic_box_clone(unsigned long vslot, int vowned, const __sic_elem_tinfo *ti) {
    if (vowned == 2) return __sic_str_box_clone(vslot);
    if (vowned == 5) { __sic_list_weak_retain((__sic_list *)vslot); return vslot; }
    if (vowned == 6) { __sic_dict_weak_retain((struct __sic_dict *)vslot); return vslot; }
    if (vowned == 1 || vowned == 8) {
        /* a struct in its own block (8: after a `[dtor | pad]` header) */
        if (!ti) __sic_cannot_clone("a container element of unknown type");
        unsigned long hdr = vowned == 8 ? 2 * sizeof(unsigned long) : 0;
        char *n = (char *)malloc(hdr + (ti->size ? ti->size : 1));
        memcpy(n, (const char *)vslot - hdr, hdr + ti->size);
        if (ti->clone) ti->clone(n + hdr);
        return (unsigned long)(n + hdr);
    }
    if (vowned == 3 || vowned == 4 || vowned == 7) {
        /* a nested container or a tuple: its handle, copied by its type */
        if (ti && ti->clone) { ti->clone(&vslot); return vslot; }
        if (vowned == 3) return (unsigned long)__sic_list_clone((__sic_list *)vslot, 0);
        if (vowned == 4) return (unsigned long)__sic_dict_clone((struct __sic_dict *)vslot, 0);
        __sic_cannot_clone("a tuple of unknown type");
    }
    return vslot;   /* 0: a scalar or a borrowed value */
}

__attribute__((weak)) __sic_list *__sic_list_clone(__sic_list *l, const __sic_elem_tinfo *ti) {
    __sic_list *r = __sic_list_new();
    if (l) for (unsigned long i = 0; i < l->len; i++) {
        const __sic_elem_tinfo *t = l->vty[i] ? (const __sic_elem_tinfo *)l->vty[i] : ti;
        __sic_list_push(r, l->vty[i], __sic_box_clone(l->vslot[i], l->vowned[i], t), l->vowned[i]);
    }
    return r;
}

/* Remove the last element of a `list<any>`, keeping its box (see `retired`). */
__attribute__((weak)) void __sic_list_retire_last(__sic_list *l) {
    if (!l || l->len == 0) return;
    l->len--;
    l->retired = (unsigned long *)realloc(l->retired, (l->nretired + 1) * sizeof(unsigned long));
    l->retired_owned = (int *)realloc(l->retired_owned, (l->nretired + 1) * sizeof(int));
    l->retired[l->nretired] = l->vslot[l->len];
    l->retired_owned[l->nretired] = l->vowned[l->len];
    l->nretired++;
}

/* Remove the last element, moved out: its bytes have a new owner, so only the box
   goes, with no destructor. */
__attribute__((weak)) void __sic_list_take_last(__sic_list *l) {
    if (!l || l->len == 0) return;
    l->len--;
    if (l->vowned[l->len] == 8) free((void **)l->vslot[l->len] - 2);
    else if (l->vowned[l->len] == 1) free((void *)l->vslot[l->len]);
}

/* `l.pop()`, instantiated with the list's element type: an ordinary copy of the last
   element and an ordinary return, so every element type owns what it should. On an
   empty list the read gives a zero value, as any read past the end does. */
T __sic_list_pop<T>(list<T> *l) {
    T v = (*l)[l.length - 1];
    __sic_list_drop_last((__sic_list *)*l);
    return v;
}

static any __sic_list_pop_any(list<any> *l) {
    any v = (*l)[l.length - 1];
    __sic_list_retire_last((__sic_list *)*l);
    return v;
}
