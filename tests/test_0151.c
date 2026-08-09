// `__thread` (and `_Thread_local`) must be an ignored specifier that does NOT
// mask the storage class: `extern __thread T x;` stays a pure declaration, not a
// definition. Getting this wrong made QEMU's `current_cpu` (declared `extern
// __thread CPUState *current_cpu;` in a header) emit a strong bss definition in
// every including TU → "multiple definition" at link with -fno-common.
#include <stdio.h>
__thread int counter;              // tentative definition (one strong def)
static __thread long slot = 7;     // internal TLS with initializer
int bump(void){ return ++counter; }
int main(void){
    setvbuf(stdout,0,2,0);
    counter = 0;
    int ok = (bump()==1 && bump()==2 && counter==2 && slot==7);
    slot = 42; if (slot != 42) ok = 0;
    printf("thread-local-storage: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
