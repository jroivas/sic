// typeof of an earlier parameter, `__builtin_choose_expr` in a file-scope typeof,
// and `__alignof__` of a global's member as an `aligned` value. Values are gcc's.
long g;
struct S { long a; char b; } gs;
typedef __typeof__(__builtin_choose_expr(sizeof(g) <= 4, (int)0, (long)0)) T;
int a6 __attribute__((aligned(__alignof__(gs.a))));
_Static_assert(sizeof(T) == 8 && _Alignof(a6) == 8, "file scope");

static int f(int n, __typeof__(n) m, const __typeof__(n) *p) { return n + m + *p; }

int main(void)
{
    int x = 2;
    return f(30, 10, &x);
}
