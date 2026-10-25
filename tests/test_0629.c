// Clang's `--target=` naming the host is accepted (Linux's Kconfig passes
// `--target=x86_64-linux-gnu` with every compiler probe); another target is an
// error rather than a silently mis-targeted build.
int main(void) { return 42; }
