// Before C23, bool/true/false/nullptr/alignas/thread_local/static_assert are names.
int bool = true + false;
void *p = nullptr;
int alignas, thread_local, static_assert;
_Bool b; _Static_assert(1, "x"); _Alignas(8) int q; _Thread_local int tl;
__auto_type a = 1; __typeof__(a) x; __asm__("nop"); __attribute__((unused)) int y; __extension__ int z;
__int128 big; __float128 f; _Float16 h; __builtin_va_list ap; int __builtin_va_start;
i8 isize; string list; set *s; dict d; Task tk; Fn f2; weak w2; match m; new n; defer df;
