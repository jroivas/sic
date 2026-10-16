/* -Wlong-double is opt-in; once enabled, -Werror promotes it like any warning. */
long double half(long double x) { return x / 2; }
int main(void) { return (int)half(84.0); }
