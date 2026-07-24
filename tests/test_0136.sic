// offsetof() must drill through anonymous struct/union members. QEMU CPU state
// (e.g. ARM's env with `sctlr_el` inside an anonymous union) uses this heavily;
// sic's offsetof only looked at direct members → "no field 'sctlr_el' in offsetof".
// Also covers typedef names shadowed by locals in statements/expressions.
#include <stdio.h>
#include <stddef.h>

struct CpuState {
    int id;
    union {
        struct { int sctlr_el[4]; int ttbr; };   // anonymous struct in anon union
        int raw[8];
    };
    int flags;
};

int main(void){
    setvbuf(stdout,0,_IONBF,0);
    int ok = 1;

    if (offsetof(struct CpuState, sctlr_el) != 4) ok=0;
    if (offsetof(struct CpuState, sctlr_el[2]) != 12) ok=0;
    if (offsetof(struct CpuState, ttbr) != 20) ok=0;
    if (offsetof(struct CpuState, flags) != offsetof(struct CpuState, id) + 4 + 32) ok=0;

    printf("offsetof-anon: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
