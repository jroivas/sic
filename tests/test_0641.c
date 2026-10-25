// aligned(sizeof(T)) takes T's real size (Linux's atomic_t is
// `int __aligned(sizeof(int)) counter;`, which sic made 8-byte aligned,
// moving struct page's fields); typedef/struct operands are not guessed. An
// alignment after the closing brace applies to the struct (Linux's struct page
// `} _struct_page_alignment;`).
#include <stddef.h>

typedef struct { int __attribute__((aligned(sizeof(int)))) counter; } atomic_t;
struct a2 { char c; short __attribute__((aligned(sizeof(short)))) s; };
struct a8 { char c; int __attribute__((aligned(sizeof(long)))) i; };
struct ap { char c; int __attribute__((aligned(sizeof(void *)))) i; };
struct a16 { char c; int __attribute__((aligned(2 * sizeof(long long)))) i; };
struct page_like { long a; union { unsigned int t; atomic_t m; }; atomic_t ref; long b, c; } __attribute__((__aligned__(2 * sizeof(unsigned long))));

_Static_assert(sizeof(atomic_t) == 4 && _Alignof(atomic_t) == 4, "atomic_t");
_Static_assert(offsetof(struct a2, s) == 2, "a2");
_Static_assert(offsetof(struct a8, i) == 8, "a8");
_Static_assert(offsetof(struct ap, i) == 8, "ap");
_Static_assert(offsetof(struct a16, i) == 16, "a16");
_Static_assert(offsetof(struct page_like, ref) == 12, "page_like");
_Static_assert(sizeof(struct page_like) == 32 && _Alignof(struct page_like) == 16, "trailing aligned");

int main(void) { return (int)(sizeof(struct page_like) + offsetof(struct a16, i) - 6); }
