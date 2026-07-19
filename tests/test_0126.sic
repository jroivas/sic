// Struct-by-value return (sret ABI). Previously sic loaded/returned a small
// struct as a scalar register and then memcpy'd the caller's slot from that
// scalar treated as a pointer → segfault / cranelift verifier errors. Now
// aggregate returns pass a hidden result pointer.
#include <stdio.h>

typedef struct { unsigned int v; } Small;      // fits in a register
typedef struct { long a, b; int c; } Big;       // > 16 bytes
typedef struct { int x, y; } Pair;

static Small mk_small(unsigned int x){ Small r; r.v = x; return r; }
static Big   mk_big(long a, long b, int c){ Big r; r.a=a; r.b=b; r.c=c; return r; }
static Pair  mk_pair(int x, int y){ Pair r; r.x=x; r.y=y; return r; }

// Returned struct passed straight into another by-value parameter.
static int pair_sum(Pair p){ return p.x + p.y; }

// Function-pointer / function-typed-parameter returning a struct by value
// (testfloat's trueFunction/subjFunction pattern → sret via CallIndirect).
static unsigned int via_fnparam(Small fn(unsigned int), unsigned int a){ Small z = fn(a); return z.v; }

int main(void){
    setvbuf(stdout,0,_IONBF,0);
    int ok = 1;

    // init from call
    Small a = mk_small(42);
    if (a.v != 42) ok=0;
    // assign from call
    Small d; d = mk_small(99);
    if (d.v != 99) ok=0;

    // big struct (sret, > register size)
    Big g = mk_big(10, 20, 30);
    if (g.a!=10 || g.b!=20 || g.c!=30) ok=0;
    Big h; h = mk_big(1, 2, 3);
    if (h.a!=1 || h.b!=2 || h.c!=3) ok=0;

    // field access directly on the returned rvalue
    if (mk_small(7).v != 7) ok=0;
    if (mk_pair(11, 22).x != 11 || mk_pair(3, 4).y != 4) ok=0;

    // returned struct forwarded as a by-value argument
    if (pair_sum(mk_pair(5, 6)) != 11) ok=0;

    // struct returned through a function-typed parameter and a function pointer
    if (via_fnparam(mk_small, 77) != 77) ok=0;
    Small (*fp)(unsigned int) = mk_small;
    if (fp(123).v != 123) ok=0;

    printf("struct-return: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
