/* GNU `__auto_type` / C23 `auto x = e;` infer the type from the initializer
 * (arrays decay, structs copy), and a declaration with NO type specifier is
 * implicit `int` — it used to become `long long`. Returns 42. */
struct P { int a, b; };
static implicit = 5;
int main(void) {
    __auto_type i = 40;
    __auto_type l = 1L << 40;
    __auto_type d = 1.5;
    int arr[3] = {1, 2, 3};
    __auto_type p = arr;
    struct P s = {1, 7};
    __auto_type t = s;
    t.a = 9;
    auto c = 'x';
    const k = 3;
    if (sizeof(i) != sizeof(int) || sizeof(l) != 8 || sizeof(d) != sizeof(double)) return 1;
    if (sizeof(p) != sizeof(int *) || p[2] != 3) return 2;
    if (t.a != 9 || t.b != 7 || s.a != 1) return 3;
    if (sizeof(implicit) != sizeof(int) || sizeof(k) != sizeof(int)) return 4;
    return i + (int)(l >> 40) + (int)(d * 2) + (c == 'x') - 3 + k - implicit + 2;   /* 40+1+3+1-3+3-5+2 */
}
