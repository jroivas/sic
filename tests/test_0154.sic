// Constant-condition ternary must fold to the taken arm only (like gcc/clang).
// QEMU's dup_const/tcg macros nest `__builtin_constant_p(x) ? <fold> : <runtime>`
// where the dead <fold> arm ends in an exhaustiveness `qemu_build_not_reached()`
// (a deliberately-undefined symbol). sic returns 0 for __builtin_constant_p, so
// the fold arm must be dropped — not lowered (which would emit the bad call).
#include <stdio.h>
extern long never_linked_marker(void);       // must never be referenced
static long pick(int vece){
    // mirrors the dup_const shape
    return (__builtin_constant_p(vece)
              ? ((vece)==8 ? 0x11 : (vece)==16 ? 0x22 : (never_linked_marker(), 0))
              : (vece * 10));
}
int main(void){
    setvbuf(stdout,0,2,0);
    int ok = (pick(3) == 30 && pick(5) == 50);
    printf("ternary-dce: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
