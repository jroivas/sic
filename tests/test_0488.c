/* In `_Generic`, a function name decays to a pointer to its function type, so
 * `_Generic(foo, fptr: …)` matches (it was "no matching association": a
 * function was typed `void *`). c-testsuite 00219. Returns 42. */
typedef int (*fptr)(int);
int foo(int i) { return i; }
long bar(int i) { return i; }
int main(void) {
    int a = _Generic(foo, fptr: 10, default: 0);
    int b = _Generic(&foo, int (*)(int): 20, default: 0);
    int c = _Generic(bar, fptr: 0, long (*)(int): 12, default: 1);
    return a + b + c;
}
