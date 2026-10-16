/* -Werror: `long double` is deprecated (computed as double), so it is an error. */
long double half(long double x) { return x / 2; }
int main(void) { return (int)half(84.0); }
