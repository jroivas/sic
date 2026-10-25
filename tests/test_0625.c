// Functions returning a large aggregate (through the hidden result pointer)
// are inlined like void ones: results land in the caller's slot, also when
// the result is the argument (`s = step(s)`), with several returns, and for
// GCC vectors (x86 intrinsics are such functions).
typedef struct { long v[6]; } Big;
typedef float v8sf __attribute__((vector_size(32)));

static Big step(Big b)
{
    Big r;
    for (int i = 0; i < 6; i++) r.v[i] = b.v[(i + 1) % 6] + i;
    return r;
}

static Big pick(int k, Big a, Big b)
{
    if (k > 0) return a;
    Big z = { { 0 } };
    if (k < 0) return z;
    return b;
}

static inline __attribute__((always_inline)) v8sf twice(v8sf x) { return x + x; }

int main(void)
{
    Big s = { { 1, 2, 3, 4, 5, 6 } };
    for (int n = 0; n < 3; n++) s = step(s);
    // three rotations by one, adding i, (i+1), (i+2) along the way
    if (s.v[0] != 4 + 0 + 1 + 2 || s.v[5] != 3 + 5 + 0 + 1) return 1;
    Big a = { { 7 } }, b = { { 9 } };
    if (pick(1, a, b).v[0] != 7 || pick(0, a, b).v[0] != 9 || pick(-1, a, b).v[0] != 0) return 2;
    a = pick(0, b, a);
    if (a.v[0] != 7) return 3;
    v8sf x = { 1, 2, 3, 4, 5, 6, 7, 8 };
    v8sf y = twice(twice(x));
    if (y[0] != 4 || y[7] != 32) return 4;
    return 42;
}
