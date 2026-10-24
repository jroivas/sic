// A builtin called with the wrong number of arguments says so (the extra one
// was ignored).
int main(void) { return __builtin_clz(1, 2); }
