/* sic's `stringbuilder` (sic.md §"Stringbuilder"): text collected without copying,
   joined once by `.build()`. Prepended only when a unit uses it.

   A builder is one `string` whose block is a foreign block (`[count | FLAG]
   [finalizer] ...`, see `__sic_str_rc_release`): the tail of a chain of blocks of
   pieces. Every copy, return and scope exit of a builder is then a string's. Pieces
   retain the strings they point into. A block with one reference may grow; one
   that is shared is frozen, and the next append starts a block with it as parent,
   so copies branch off a common base and never see each other's appends. */
extern void *malloc(unsigned long);
extern void free(void *);
extern void *memcpy(void *, const void *, unsigned long);

typedef struct __sic_sb_str {
    const char *data;
    unsigned long size;
    unsigned long *rc;
} __sic_sb_str;

typedef struct __sic_sb_block {
    unsigned long count;
    void (*finalize)(void *);
    struct __sic_sb_block *parent;
    unsigned long total;
    int n;
    int cap;
    __sic_sb_str p[];
} __sic_sb_block;

__attribute__((weak)) void __sic_sb_free(void *block) {
    const unsigned long flag = 1UL << (sizeof(unsigned long) * 8 - 1);
    __sic_sb_block *b = (__sic_sb_block *)block;
    while (b) {
        for (int i = 0; i < b->n; i++) {
            unsigned long *rc = b->p[i].rc;
            if ((unsigned long)rc <= 1) continue;
            unsigned long c = --(*rc);
            if ((c & ~flag) != 0) continue;
            if (c & flag) ((void (*)(void *))rc[1])((void *)rc);
            else free((void *)rc);
        }
        __sic_sb_block *parent = b->parent;
        free(b);
        b = parent;
        if (b && ((--b->count) & ~flag) != 0) break;
    }
}

__attribute__((weak)) void __sic_sb_append(void *handle, void *piece) {
    const unsigned long flag = 1UL << (sizeof(unsigned long) * 8 - 1);
    __sic_sb_str *h = (__sic_sb_str *)handle;
    __sic_sb_str *s = (__sic_sb_str *)piece;
    if (s->size == 0) return;
    __sic_sb_block *b = (__sic_sb_block *)h->rc;
    int mine = b && (b->count & ~flag) == 1;
    if (mine && b->n > 0) {
        __sic_sb_str *last = &b->p[b->n - 1];
        if (last->rc == s->rc && last->data + last->size == s->data) {
            last->size += s->size;
            b->total += s->size;
            return;
        }
    }
    if (!mine || b->n == b->cap) {
        int cap = b ? b->cap * 2 : 8;
        if (cap > 1024) cap = 1024;
        __sic_sb_block *nb = (__sic_sb_block *)malloc(sizeof(__sic_sb_block) + cap * sizeof(__sic_sb_str));
        nb->count = 1 | flag;
        nb->finalize = __sic_sb_free;
        nb->parent = b;      /* takes over the handle's reference */
        nb->total = b ? b->total : 0;
        nb->n = 0;
        nb->cap = cap;
        h->rc = (unsigned long *)nb;
        b = nb;
    }
    __sic_sb_str p = *s;
    if ((unsigned long)p.rc == 1) {
        /* A view of a stack buffer: it would not outlive this frame. */
        unsigned long *copy = (unsigned long *)malloc(sizeof(unsigned long) + p.size);
        *copy = 1;
        memcpy(copy + 1, p.data, p.size);
        p.data = (const char *)(copy + 1);
        p.rc = copy;
    } else if ((unsigned long)p.rc > 1) {
        ++*p.rc;
    }
    b->p[b->n++] = p;
    b->total += p.size;
}

__attribute__((weak)) void __sic_sb_build(void *handle, void *out) {
    __sic_sb_str *h = (__sic_sb_str *)handle;
    __sic_sb_str *r = (__sic_sb_str *)out;
    __sic_sb_block *b = (__sic_sb_block *)h->rc;
    if (!b || b->total == 0) { r->data = ""; r->size = 0; r->rc = (unsigned long *)0; return; }
    /* One owned piece is already the result. */
    if (!b->parent && b->n == 1 && (unsigned long)b->p[0].rc > 1) {
        *r = b->p[0];
        ++*r->rc;
        return;
    }
    unsigned long *block = (unsigned long *)malloc(sizeof(unsigned long) + b->total + 1);
    *block = 1;
    char *text = (char *)(block + 1);
    unsigned long end = b->total;
    text[end] = 0;
    r->data = text;
    r->size = end;
    r->rc = block;
    for (; b; b = b->parent) {
        for (int i = b->n - 1; i >= 0; i--) {
            end -= b->p[i].size;
            memcpy(text + end, b->p[i].data, b->p[i].size);
        }
    }
}

__attribute__((weak)) unsigned long __sic_sb_length(void *handle) {
    __sic_sb_block *b = (__sic_sb_block *)((__sic_sb_str *)handle)->rc;
    return b ? b->total : 0;
}

struct stringbuilder {
    string __tail;
    void append(stringbuilder *self, string s) { __sic_sb_append(&self->__tail, &s); }
    string build(stringbuilder *self) { string r; __sic_sb_build(&self->__tail, &r); return r; }
    stringbuilder copy(stringbuilder *self) { stringbuilder c; c.__tail = self->__tail; return c; }
    u64 length(stringbuilder *self) { return __sic_sb_length(&self->__tail); }
}
static stringbuilder __sic_sb_new() { stringbuilder b; return b; }
