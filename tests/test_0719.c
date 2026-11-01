// aligned / _Alignas on variables of every storage, and in _Alignof: values are gcc's.
#include <stdio.h>
#include <string.h>
static char out[4096];
static int outn;
static const char expected[] =
    "64 128 32 64 128 1024 1 2\n"
    "64 64 1 128 64\n"
    "bad=0 10\n"
;
#define printf(...) (outn += sprintf(out + outn, __VA_ARGS__))
#define puts(s) printf("%s\n", s)
#include <stdint.h>
#include <stddef.h>
#define CK(p,n) do { if ((uintptr_t)(p) % (n)) { printf("BAD %s %d\n", #p, n); bad++; } } while (0)
static int bad;
int g __attribute__((aligned(64)));
char pad1 = 1;
_Alignas(128) int h;
char pad2 = 2;
int init __attribute__((aligned(256))) = 5;
static char sarr[3] __attribute__((aligned(4096)));
char pad3;
__attribute__((aligned(32))) int lead1, lead2 __attribute__((aligned(64)));
extern int later __attribute__((aligned(128)));
char pad4;
int later = 3;
__thread int tls __attribute__((aligned(64)));
const int ro __attribute__((aligned(512))) = 1;
int bare __attribute__((aligned));
int sec __attribute__((section(".mydata"), aligned(64))) = 1;
_Static_assert(_Alignof(g) == 64, "g");
_Static_assert(__alignof__(h) == 128, "h");
typedef int a16 __attribute__((aligned(16)));
typedef char c64 __attribute__((aligned(64)));
a16 tv; c64 tc; char pad5;
struct big { char c[100]; } sb __attribute__((aligned(1024)));
_Static_assert(sizeof(sb) == 100, "size");
struct S { char c; char m __attribute__((aligned(64))); };
int noalign __attribute__((aligned(1)));
long lowered __attribute__((aligned(2)));
void leaf(int depth) {
    int a __attribute__((aligned(64)));
    char pad[depth % 37 + 1];
    char b[3] __attribute__((aligned(128)));
    _Alignas(32) long c;
    static int st __attribute__((aligned(512)));
    c64 d; a16 e;
    int f __attribute__((aligned(4096)));
    __attribute__((aligned(256))) char x1, x2;
    a = c = 0; b[0] = 1; d = 1; e = 2; f = 3; x1 = x2 = 0; pad[0] = 0;
    CK(&a,64); CK(b,128); CK(&c,32); CK(&st,512); CK(&d,64); CK(&e,16); CK(&f,4096); CK(&x1,256); CK(&x2,256);
    *(volatile int *)&a = 1; *(volatile char *)b = 2;
    if (a != 1 || b[0] != 2 || f != 3 || d != 1 || e != 2) { puts("BAD value"); bad++; }
    if (depth > 0) leaf(depth - 1);
    if (a != 1 || f != 3) { puts("BAD after call"); bad++; }
}
int main(void) {
    int r[8];
    CK(&g,64);CK(&h,128);CK(&init,256);CK(sarr,4096);CK(&lead1,32);CK(&lead2,64);CK(&later,128);CK(&tls,64);CK(&ro,512);CK(&bare,16);CK(&sec,64);CK(&tv,16);CK(&tc,64);CK(&sb,1024);
    for (int i = 0; i < 60; i++) leaf(i % 9);
    printf("%zu %zu %zu %zu %zu %zu %zu %zu\n", _Alignof(g), _Alignof(h), _Alignof(lead1), _Alignof(lead2), _Alignof(later), _Alignof(sb), _Alignof(noalign), _Alignof(lowered));
    struct S s; struct S *p = &s;
    printf("%zu %zu %zu %zu %zu\n", _Alignof(s.m), _Alignof(p->m), _Alignof(s.c), sizeof(struct S), _Alignof(tc));
    printf("bad=%d %d\n", bad, init + later + ro + sec); (void)r; return strcmp(out, expected) ? 1 : 42; }
