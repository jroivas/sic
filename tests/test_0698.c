// Static initializers as Linux writes them, once a form the serializer could not
// handle had zeroed the whole object: a `static` naming itself or a neighbour,
// __is_constexpr and the checks built on it, bit-fields of a packed struct, the
// offsetof idiom, &*NULL, &"string", address chains, anonymous members, the address
// inside a compound literal, typeof(local), __func__ and sizeof("literal").
#include <stdio.h>
#include <stddef.h>
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32; typedef unsigned long long u64; typedef short s16;
#define BUILD_BUG_ON_ZERO(e) ((int)sizeof(struct { _Static_assert(!(e), "x"); }))
#define __is_constexpr(x) (sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))
#define __bf_shf __builtin_ctzll
#define GENMASK_U32(h, l) (((~0U) << (l)) & (~0U >> (31 - (h))))
#define BIT_U32(n) ((u32)(BUILD_BUG_ON_ZERO(__builtin_choose_expr(__is_constexpr(n), (n) < 0 || (n) > 31, 0)) + (1U << (n))))
#define IS_POWER_OF_2(n) ((n) != 0 && (((n) & ((n) - 1)) == 0))
#define REG_FIELD_PREP(m, v) ((u32)((((typeof(m))(v) << __bf_shf(m)) & (m)) + BUILD_BUG_ON_ZERO(!__is_constexpr(m)) + BUILD_BUG_ON_ZERO((m) == 0 || (m) > 0xffffffffULL) + BUILD_BUG_ON_ZERO(!IS_POWER_OF_2((m) + (1ULL << __bf_shf(m)))) + BUILD_BUG_ON_ZERO(__builtin_choose_expr(__is_constexpr(v), (~((m) >> __bf_shf(m)) & (v)) != 0, 0))))
#define REG_MASKED_FIELD(mask, value) (BUILD_BUG_ON_ZERO(__builtin_choose_expr(__builtin_constant_p(mask), ((mask) & 0xffff0000), 0)) + BUILD_BUG_ON_ZERO(__builtin_choose_expr(__builtin_constant_p(value), ((value) & ~(mask)), 0)) + ((mask) << 16 | (value)))
#define __BF_CHECK_POW2(n) BUILD_BUG_ON_ZERO(((n) & ((n) - 1)) != 0)
#define FIELD_PREP_CONST(_m, _v) (BUILD_BUG_ON_ZERO((_m) == 0) + BUILD_BUG_ON_ZERO(~((_m) >> __bf_shf(_m)) & (_v)) + __BF_CHECK_POW2((_m) + (1ULL << __bf_shf(_m))) + (((typeof(_m))(_v) << __bf_shf(_m)) & (_m)))
struct cc { int c; u32 v; };
const struct cc audio[] = { { 25175, REG_FIELD_PREP(GENMASK_U32(19, 16), 1) }, { 3, BIT_U32(4) } };
static const u32 lri[] = { REG_MASKED_FIELD(BIT_U32(3), BIT_U32(3)), 2 };
unsigned long pst = FIELD_PREP_CONST(0xff00ULL, 102);
struct orc { s16 sp, bp; unsigned sr:4; unsigned br:4; unsigned ty:3; unsigned sig:1; } __attribute__((packed));
static struct orc ofp = { .ty = 2, .sr = 5, .sp = 16, .br = 7, .bp = -16 };
struct desc { u16 l0; u16 b0; u16 b1:8, ty:4, s:1, dpl:2, p:1; u16 l1:4, avl:1, l:1, d:1, g:1, b2:8; } __attribute__((packed));
#define GI(fl, ba, li) { .l0 = (u16)(li), .l1 = ((li) >> 16) & 0xF, .b0 = (u16)(ba), .b1 = ((ba) >> 16) & 0xFF, .b2 = ((ba) >> 24) & 0xFF, .ty = (fl & 0xf), .s = ((fl) >> 4) & 0x01, .dpl = ((fl) >> 5) & 0x03, .p = ((fl) >> 7) & 0x01, .avl = ((fl) >> 12) & 0x01, .l = ((fl) >> 13) & 0x01, .d = ((fl) >> 14) & 0x01, .g = ((fl) >> 15) & 0x01 }
static const struct desc gdt[] = { [1] = GI(0xc09b, 0, 0xfffff), [2] = GI(0xa09b, 0, 0xfffff) };
static const char x86nops[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
const char *const nops[3] = { [1] = x86nops, [2] = x86nops + 1 + 2 };
struct p { int a; struct { int z; struct list { void *n; } mm; }; int data[4]; };
struct p ip = { .mm = { &ip.mm } };
int *dp = &((struct p *)0)->data[2];
#define showlocks (*(const struct p *)NULL)
const struct p *tbl[3] = { &ip, &showlocks, NULL };
unsigned long cfg = (0 ? 0 : (unsigned long)&"PARPORT");
struct sa { const char *n; unsigned short m; };
struct stra { struct sa attr; const char *str; };
struct sa *fmt[] = { (&((struct stra[]) { { .attr = { "a", 1 }, .str = "cfg" } })[0].attr), NULL };
struct hdr { const char *name; unsigned len; };
#define H(__n) { .name = __n, .len = sizeof(__n) - 1 }
struct hdr hs[] = { H("From") };
static const struct { struct { u32 a, b, c; } h; unsigned char nm[sizeof("Linux")] __attribute__((aligned(4))); int desc __attribute__((aligned(4))); } note __attribute__((used)) = { { sizeof("Linux"), sizeof(1), 1 }, "Linux", 1 };
struct net; struct pidns { int x; struct nsc { unsigned t; unsigned long id; const void *ops; } ns; };
extern const int pidops;
#define nstype(n) _Generic((n), struct net *: 1, struct pidns *: 2)
#define nsops(n) _Generic((n), struct net *: (0 ? &pidops : NULL), struct pidns *: (1 ? &pidops : NULL))
struct pidns pn = { .ns = { .t = nstype(&pn), .id = 5, .ops = nsops(&pn) } };
const int pidops = 3;
struct l { struct l *n, *p; };
struct engine { struct { unsigned a, hb; } props; };
int f(struct engine *engine) {
  static struct l g = { &g, &g };
  static const int states[] = { 3, 4 };
  static const int *const sp = states;
  static const char u10[] = "kB", u2[] = "Ki";
  static const char *const un[2] = { [0] = u10, [1] = u2 };
  static const struct { size_t off; const char *name; } props[] = { { offsetof(typeof(engine->props), hb), "hb" } };
  static const struct { const int *p; unsigned n; } dv[] = { { states, sizeof(states) / sizeof(states[0]) } };
  return g.n == &g && sp == states && un[1][0] == 'K' && props[0].off == 4 && dv[0].n == 2;
}
static const char *where(void) { static const char *const here = __func__; return here; }

#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)
int main(void)
{
	struct engine e;
	CHECK(audio[0].v == 0x10000 && audio[1].v == 0x10 && lri[0] == 0x80008 && pst == 0x6600);
	CHECK(ofp.ty == 2 && ofp.sr == 5 && ofp.sp == 16 && ofp.br == 7 && ofp.bp == -16);
	CHECK(gdt[1].l0 == 0xffff && gdt[1].ty == 0xb && gdt[1].d == 1 && gdt[2].l == 1);
	CHECK(nops[2][0] == 4 && ip.mm.n == &ip.mm && (long)dp == 32 && !tbl[1] && !__builtin_strcmp((char *)cfg, "PARPORT"));
	CHECK(!__builtin_strcmp(fmt[0]->n, "a") && !__builtin_strcmp(((struct stra *)fmt[0])->str, "cfg"));
	CHECK(hs[0].len == 4 && note.h.a == 6 && !__builtin_strcmp((char *)note.nm, "Linux"));
	CHECK(sizeof(note.nm) == 6 && pn.ns.t == 2 && pn.ns.ops == &pidops);
	CHECK(f(&e) == 1 && !__builtin_strcmp(where(), "where"));
	return 42;
}
