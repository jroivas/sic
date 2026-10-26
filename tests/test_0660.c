// __attribute__((noinline)) keeps a function out of line (sic ignored it):
// such a function has its own frame, below its caller's.
static __attribute__((noinline)) void *own_frame(void) { return __builtin_frame_address(0); }
__attribute__((noinline)) int twice(int x) { return 2 * x; }

int main(void) {
    char *mine = __builtin_frame_address(0);
    char *callee = own_frame();
    return (callee < mine) + twice(20) + 1;    // 1 + 40 + 1
}
