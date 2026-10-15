/* An enum defined inside a member of an ANONYMOUS struct/union
 * (`struct { enum { X } x; } s;`) did not define its constants: "undefined
 * name 'X'". c-testsuite 00120. Returns 42. */
struct { enum { X, Y } x; } s;
union { enum { U1 = 30 } u; int i; } un;
int main(void) {
    struct { enum { Z = 10 } z; } loc;
    s.x = Y;
    return X + s.x + U1 + Z + 1;   /* 0 + 1 + 30 + 10 + 1 */
}
