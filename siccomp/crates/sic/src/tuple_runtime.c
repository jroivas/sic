/* Dynamically typed tuples (sic.md §"Tuples"). Every tuple block carries its
   shape — `[shape | __dtor | count | rc]` before the data — so a `tuple` whose
   element types are not known at compile time (a struct field, a parameter
   called with several shapes) is read through these checked accessors. A shape
   is `{ count; { typeinfo *ti; offset; } elem[count] }`; a typeinfo is
   `{ name; id; size; kind }` and its `id` (a hash of the canonical type name)
   identifies a type across modules. Prepended (post-preprocess) only when the
   unit mentions `tuple`; weak-linked. */
extern int dprintf(int fd, const char *fmt, ...);
extern void abort(void);

typedef struct __sic_tinfo { const char *name; unsigned long id; unsigned int size; unsigned int kind; } __sic_tinfo;
typedef struct __sic_tshape_elem { const __sic_tinfo *ti; unsigned long off; } __sic_tshape_elem;
typedef struct __sic_tshape { unsigned long count; __sic_tshape_elem e[]; } __sic_tshape;

/* The same type for a dynamic check: equal ids — or both `fixed` (its <I,F>
   is display precision only), or both tuples (a nested tuple's shape is
   checked when it is itself converted to a typed tuple). */
static int __sic_tuple_same(const __sic_tinfo *a, const __sic_tinfo *b) {
    if (a->id == b->id) return 1;
    if (a->kind == b->kind && (a->kind == 10 || a->kind == 15)) return 1;
    return 0;
}

static const __sic_tshape *__sic_tuple_shape_of(void *data) {
    return data ? *((const __sic_tshape **)data - 4) : 0;
}

/* (Written for sic's own SIC-mode compile: no string-literal ternaries — those
   would be `string` values — just plain `const char*` data.) */
static const char __sic_tuple_unknown[2] = { '?', 0 };

__attribute__((weak)) void __sic_tuple_type_fail(unsigned long i, const char *got, const char *want) {
    const char *g = got;
    const char *w = want;
    if (!g) g = __sic_tuple_unknown;
    if (!w) w = __sic_tuple_unknown;
    dprintf(2, "tuple element %lu is `%s`, not `%s`\n", i, g, w);
    abort();
}

/* Address of element `i`, aborting when out of range or (with `want`) when the
   element is not exactly that type. */
__attribute__((weak)) void *__sic_tuple_elem(void *data, unsigned long i, const __sic_tinfo *want) {
    const __sic_tshape *s = __sic_tuple_shape_of(data);
    unsigned long n = s ? s->count : 0;
    if (i >= n) {
        dprintf(2, "tuple index %lu out of range (length %lu)\n", i, n);
        abort();
    }
    const __sic_tinfo *ti = s->e[i].ti;
    if (want && !__sic_tuple_same(ti, want)) __sic_tuple_type_fail(i, ti->name, want->name);
    return (char *)data + s->e[i].off;
}

/* Box element `i` as an `any` (`*oty` = its typeinfo, `*oslot` = the value as
   the compiler boxes it: a scalar's bits — floats as f64 bits — a pointer/handle
   value (a nested tuple too), or an aggregate's address). */
__attribute__((weak)) void __sic_tuple_get_any(void *data, unsigned long i, const void **oty, unsigned long *oslot) {
    char *p = (char *)__sic_tuple_elem(data, i, 0);
    const __sic_tinfo *ti = __sic_tuple_shape_of(data)->e[i].ti;
    unsigned long v = 0;
    unsigned int k = ti->kind, z = ti->size;
    if (k == 1) v = *(unsigned char *)p;                            /* bool */
    else if (k == 2) {                                              /* signed int */
        if (z == 1) v = (unsigned long)(long)*(signed char *)p;
        else if (z == 2) v = (unsigned long)(long)*(short *)p;
        else if (z == 4) v = (unsigned long)(long)*(int *)p;
        else v = *(unsigned long *)p;
    } else if (k == 3) {                                            /* unsigned int */
        if (z == 1) v = *(unsigned char *)p;
        else if (z == 2) v = *(unsigned short *)p;
        else if (z == 4) v = *(unsigned int *)p;
        else v = *(unsigned long *)p;
    } else if (k == 4) {                                            /* f32 → f64 bits */
        double d = *(float *)p;
        v = *(unsigned long *)&d;
    } else if (k == 5 || k == 6 || k == 7 || k == 8 || k == 10 || k == 15 || k == 16) {
        v = *(unsigned long *)p;                         /* f64, ptr, fixed, tuple, bigint */
    } else {
        v = (unsigned long)p;                                       /* by address */
    }
    *oty = ti;
    *oslot = v;
}

/* An `any` read from a dynamically typed tuple converts only to its exact type. */
__attribute__((weak)) void __sic_tuple_expect(const __sic_tinfo *got, const __sic_tinfo *want, unsigned long i) {
    if (got && want && __sic_tuple_same(got, want)) return;
    const char *g = 0;
    const char *w = 0;
    if (got) g = got->name;
    if (want) w = want->name;
    __sic_tuple_type_fail(i, g, w);
}

/* `tuple(a, b, …) = t`: `t` must have exactly `n` elements. */
__attribute__((weak)) void __sic_tuple_arity(void *data, unsigned long n) {
    const __sic_tshape *s = __sic_tuple_shape_of(data);
    unsigned long got = s ? s->count : 0;
    if (got != n) {
        dprintf(2, "tuple has %lu elements, unpacked into %lu\n", got, n);
        abort();
    }
}

/* A dynamically typed tuple converted to a static `tuple<…>` must have exactly
   that shape. */
__attribute__((weak)) void __sic_tuple_check_shape(void *data, const __sic_tshape *want) {
    const __sic_tshape *s = __sic_tuple_shape_of(data);
    if (s == want) return;
    unsigned long got = s ? s->count : 0;
    if (got != want->count) {
        dprintf(2, "tuple has %lu elements, expected %lu\n", got, want->count);
        abort();
    }
    for (unsigned long i = 0; i < got; i++)
        if (!__sic_tuple_same(s->e[i].ti, want->e[i].ti))
            __sic_tuple_type_fail(i, s->e[i].ti->name, want->e[i].ti->name);
}
