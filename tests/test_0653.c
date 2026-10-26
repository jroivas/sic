// With SSE disabled (-mno-sse, as Linux builds its kernel) a floating-point
// value is an error, as with GCC, not SSE code in code that does not save the
// FPU state.
double twice(double x) { return x * 2; }
int main(void) { return (int)twice(21); }
