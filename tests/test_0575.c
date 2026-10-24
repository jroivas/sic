/* Writing to a const object was accepted silently (C requires a diagnostic).
   Shadowing and casting away const stay legal. */
const int limit = 1;
struct S { int v; };

int main(void)
{
    int limit = 40;
    limit++;
    { const int limit = 2; (void)limit; }
    limit += 1;
    const char *s = "abc";
    s++;
    char buf[2] = { 0, 0 };
    const char *p = buf;
    *(char *)p = 1;
    struct S st = { 0 };
    const struct S *cp = &st;
    ((struct S *)cp)->v = buf[0];
    return limit + st.v + (s[0] == 'b');
}
