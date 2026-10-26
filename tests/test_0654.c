// `extern typeof(sym) sym;` re-declares a known function or variable with its
// own type (Linux's EXPORT_SYMBOL). sic took typeof(function) for `int` at
// file scope and declared the function as data: "Incompatible declaration".
long twice(long x) { return 2 * x; }
extern typeof(twice) twice;

long table[5] = { 1, 2, 3, 4, 5 };
extern typeof(table) table;

struct pt { int x, y; } origin = { 3, 4 };
extern typeof(origin) origin;

static void *const exported __attribute__((used)) = (void *)&twice;

int main(void) {
    return (int)(twice(10) + sizeof(table) / sizeof(table[0]) + table[4] + origin.y + sizeof(origin) - 0) - 1;
}
