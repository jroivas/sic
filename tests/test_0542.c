/* In C the sic feature words are ordinary identifiers: none of them may pull a
   sic runtime into a C unit (QEMU's qom-test.c `QDict *tuple` dragged in the
   SIC-only tuple runtime, which failed to parse in C as "line 1123:35"). */
struct node { int tuple, list, set, fixed, bigint, dict, va_dict, utf8, async, await; };
static int Task(int x) { return x + 1; }
int main(void) {
    struct node n = {0};
    int tuple = 1, list = 2, set = 3, fixed = 4, bigint = 5, dict = 6;
    n.tuple = tuple + list + set + fixed + bigint + dict;
    n.utf8 = Task(n.tuple);
    return n.utf8 + 20; /* 42 */
}
