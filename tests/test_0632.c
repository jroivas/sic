// Before C23, `bool`, `true`, `false`, `nullptr`, `alignas` and `thread_local`
// are ordinary identifiers (Linux, built -std=gnu11, declares
// `enum { false = 0, true = 1 }` and `typedef _Bool bool;`).
typedef _Bool bool;
enum { false = 0, true = 1 };
static int nullptr = 3, alignas = 4, thread_local = 5;

int main(void)
{
    bool b = true;
    return (b == 1 && false == 0) ? nullptr + alignas + thread_local + 30 : 1;
}
