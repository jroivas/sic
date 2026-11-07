/* A failing static assertion on a local's type is reported, not passed over. */
long g(unsigned long v) { _Static_assert(__builtin_types_compatible_p(typeof(v), int), "local"); return v; }
int main(void) { return g(0); }
