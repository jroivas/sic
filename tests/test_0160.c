// C11 6.2.2p5: a function has internal linkage if ANY declaration is `static`,
// even one whose definition omits the keyword. QEMU's decodetree emits
// `static bool decode_insn(...);` then `#include`s a .inc defining
// `bool decode_insn(...)` (no static) into BOTH disas.c and translate.c —
// each must stay local, else the two objects collide ("multiple definition").
#include <stdio.h>
static int decode_insn(int x);      // forward decl WITH static
int decode_insn(int x){ return x + 1; }   // definition WITHOUT static -> still internal
int use_it(int x){ return decode_insn(x); }
int main(void){
    setvbuf(stdout,0,2,0);
    int ok = (use_it(41) == 42);
    printf("static-inherited-linkage: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
