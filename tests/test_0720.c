// aligned on a scalar typedef raises or lowers: in members, unions, _Alignof. Values are gcc's.
#include <stdio.h>
#include <string.h>
static char out[4096];
static int outn;
static const char expected[] =
    "A 32 16 16\n"
    "A 32 16 20\n"
    "B 12 4 4\n"
    "C 24 4 4\n"
    "C 24 4 16\n"
    "D 32 16 16\n"
    "E 28 4 4\n"
    "F 16 8 8\n"
    "H 16 8 8\n"
    "I 5 1 1\n"
    "J 13 1 1\n"
    "J 13 1 5\n"
    "K 14 2 2\n"
    "K 14 2 6\n"
    "L 12 4 8\n"
    "N 48 16 16\n"
    "N 48 16 32\n"
    "U 16 16 V 8 8 W 8 4 M 4 4\n"
    "16 4 4 4 16 4 8\n"
    "16 4 16 4 4 16\n"
    "4 1 1\n"
;
#define printf(...) (outn += sprintf(out + outn, __VA_ARGS__))
#define puts(s) printf("%s\n", s)
#include <stddef.h>
typedef int a16 __attribute__((aligned(16)));
typedef long long l4 __attribute__((aligned(4)));
typedef __attribute__((aligned(4))) long long l4b;
typedef long long __attribute__((aligned(4))) l4c;
typedef a16 a16b;
typedef l4 l4d;
typedef l4 *pl4;
struct A { char c; a16 x; char d; };
struct B { int i; l4 v; };
struct C { int i; l4b v; int j; l4c w; };
struct D { char c; a16b x; };
struct E { char c; l4 a[3]; };
struct F { char c; pl4 p; };
struct H { char c; l4 v __attribute__((aligned(8))); };
struct I { char c; a16 v __attribute__((packed)); };
struct __attribute__((packed)) J { char c; a16 v; l4 w; };
#pragma pack(push,2)
struct K { char c; a16 v; l4 w; };
#pragma pack(pop)
union U { char c; a16 v; };
union V { long long a; l4 b; };
union W { l4 b; };
struct L { l4 v; char c; };
struct N { char c; _Alignas(16) int x; _Alignas(16) char y; };
struct M { char c; l4 v:3; };
a16 g; l4 h;
#define P(T,f) printf("%s %zu %zu %zu\n", #T, sizeof(struct T), _Alignof(struct T), offsetof(struct T, f))
int main(void){ a16 v; l4 w; struct B b;
 P(A,x);P(A,d);P(B,v);P(C,v);P(C,w);P(D,x);P(E,a);P(F,p);P(H,v);P(I,v);P(J,v);P(J,w);P(K,v);P(K,w);P(L,c);P(N,x);P(N,y);
 printf("U %zu %zu V %zu %zu W %zu %zu M %zu %zu\n", sizeof(union U),_Alignof(union U),sizeof(union V),_Alignof(union V),sizeof(union W),_Alignof(union W),sizeof(struct M),_Alignof(struct M));
 printf("%zu %zu %zu %zu %zu %zu %zu\n",_Alignof(a16),_Alignof(l4),_Alignof(l4b),_Alignof(l4c),_Alignof(a16b),_Alignof(l4d),_Alignof(pl4));
 printf("%zu %zu %zu %zu %zu %zu\n",_Alignof(v),_Alignof(w),_Alignof(g),_Alignof(h),_Alignof(b.v),_Alignof(__typeof__(v)));
 printf("%zu %d %d\n",sizeof(a16), ((size_t)&v)%16==0, ((size_t)&g)%16==0);
 return strcmp(out, expected) ? 1 : 42; }