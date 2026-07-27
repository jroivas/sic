// `__attribute__((constructor))` functions must run before main (via .init_array).
// QEMU relies on this pervasively: type_init/block_init/module registration,
// clock init, etc. Without it the emulators link but crash on startup asserts
// (mutex->initialized, main_loop_tlg). Priority order: lower runs first, then
// unprioritized.
#include <stdio.h>
static char order[8]; static int n = 0;
static int inited = 0;
__attribute__((constructor(200))) static void c_b(void){ order[n++]='B'; }
__attribute__((constructor(100))) static void c_a(void){ order[n++]='A'; }
__attribute__((constructor)) static void c_c(void){ order[n++]='C'; inited = 42; }
int main(void){
    setvbuf(stdout,0,2,0);
    order[n]=0;
    int ok = (inited==42 && order[0]=='A' && order[1]=='B' && order[2]=='C');
    printf("constructor-init-array: %s (%s)\n", ok?"OK":"FAIL", order);
    return ok?0:1;
}
