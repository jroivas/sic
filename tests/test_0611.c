// An unknown CPU feature name is an error (as in GCC).
int main(void) { return __builtin_cpu_supports("sse9"); }
