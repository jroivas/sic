// -nodefaultlibs leaves out the implicit libraries (libc, libm, the compiler
// runtime) but keeps the start files and any library given explicitly: here
// `-lc`, so the program links and runs.
int puts(const char *s);

int main(void) { return puts("nodefaultlibs") > 0 ? 42 : 1; }
