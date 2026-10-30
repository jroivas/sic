// Without SSE, no optimization may introduce vector values: a 16-byte struct
// that is only copied went to a vector slot (Linux's efi_guid_t by value), and
// counting and summing loops were vectorized. All are errors under -mno-sse.
typedef struct { unsigned char b[16]; } guid_t;
extern int memcmp(const void *, const void *, unsigned long);

static inline int guidcmp(guid_t l, guid_t r) { return memcmp(&l, &r, sizeof l); }

static long count(const unsigned char *a, long n) {
    long c = 0;
    for (long j = 0; j < n; j++) if (a[j] == 7) c++;
    return c;
}

static unsigned sum(const unsigned *a, int n) {
    unsigned s = 0;
    for (int i = 0; i < n; i++) s += a[i];
    return s;
}

static void clear(char *p, int n) {
    for (int i = 0; i < n; i++) p[i] = 0;
}

struct wide { guid_t a, b; };
static struct wide swap(struct wide w) { struct wide t = { w.b, w.a }; return t; }

int main(void) {
    guid_t g = {{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}};
    guid_t h = g;
    if (guidcmp(h, ((guid_t){{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}}))) return 1;
    if (!guidcmp(h, ((guid_t){{0}}))) return 2;
    if (count(g.b, 16) != 1) return 3;
    unsigned v[32];
    for (int i = 0; i < 32; i++) v[i] = i;
    if (sum(v, 32) != 496) return 4;
    char c[40];
    for (int i = 0; i < 40; i++) c[i] = 1;
    clear(c, 37);
    if (c[36] != 0 || c[37] != 1) return 5;
    struct wide w = { g, ((guid_t){{0}}) };
    w = swap(w);
    if (w.b.b[15] != 16 || w.a.b[0] != 0) return 6;
    return 42;
}
