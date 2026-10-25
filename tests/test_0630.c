// -nostdinc: no system include directories (Linux builds every file with it);
// the flag used to be parsed as an unknown `-n`.
#if __has_include(<stdio.h>) || __has_include(<stdint.h>)
#error system headers are visible under -nostdinc
#endif

int main(void) { return 42; }
