/* A plain -Werror does not promote -Wlong-double: library headers (glib's
   gtestutils.h, via -I) declare long double and -Werror builds must work. */
typedef struct { unsigned n; long double *nums; } LogMsg;
void report(const char *what, long double a, long double b);
int main(void) { LogMsg m = {0}; return 42 + (int)m.n; }
