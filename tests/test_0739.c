/* A static assertion in a function sees that function's names: a parameter or
   local hides a global (Linux's `page_offset` parameter and `page_offset()`, in
   i915's castable_to_type check). */
typedef unsigned long pgoff_t;
#define __is_constexpr(x) (sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))
#define is_signed_type(type) (((type)(-1)) < (type)1)
#define is_unsigned_type(type) (!is_signed_type(type))
#define __type_half_max(type) ((type)1 << (8*sizeof(type) - 1 - is_signed_type(type)))
#define __type_max(T) ((T)((__type_half_max(T) - 1) + __type_half_max(T)))
#define type_max(t) __type_max(typeof(t))
#define __type_min(T) ((T)((T)-type_max(T)-(T)1))
#define type_min(t) __type_min(typeof(t))
#define __overflows_type_constexpr(x, T) (is_unsigned_type(typeof(x)) ? (x) > type_max(T) : \
    is_unsigned_type(typeof(T)) ? (x) < 0 || (x) > type_max(T) : (x) < type_min(T) || (x) > type_max(T))
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#define castable_to_type(n, T) __builtin_choose_expr(__is_constexpr(n), \
    !__overflows_type_constexpr(n, T), __same_type(n, T))

long page_offset(void *p);
char v[100];
static long h(long x) { return x + 1; }
static long g(unsigned long page_offset) {
    _Static_assert(castable_to_type(page_offset, pgoff_t), "param");
    _Static_assert(__builtin_types_compatible_p(typeof(page_offset), unsigned long), "hides");
    char v[3];
    _Static_assert(sizeof(v) == 3, "local array");
    enum { K = 3 };
    _Static_assert(K == 3, "local enum");
    _Static_assert(castable_to_type(5, pgoff_t) && !castable_to_type(-1, pgoff_t), "const");
    _Static_assert(!__is_constexpr(page_offset) && __is_constexpr(5), "constexpr");
    v[0] = 1;
    return h(({ _Static_assert(castable_to_type(page_offset, pgoff_t), "stmt expr"); page_offset; })) + v[0];
}
int main(void) { return g(4) != 6; }
