// Two build-blocking gaps surfaced by linking qemu-system-*:
// (1) constant-condition dead-branch elimination — `if (whpx_enabled())` where
//     the macro is a literal 0 must NOT lower the dead branch (it references
//     whpx_*/hvf_* funcs never compiled on Linux → undefined symbols).
// (2) alloca / __builtin_alloca (sic has no dynamic stack alloc; malloc-backed).
#include <stdio.h>
extern int never_linked(int);          // must never be referenced
#define FEATURE() 0
static int pick(int x){ if (FEATURE()) return never_linked(x); return x + 1; }
static int suma(int n){
    int *a = __builtin_alloca(n * sizeof(int));
    for (int i=0;i<n;i++) a[i]=i+1;
    int s=0; for(int i=0;i<n;i++) s+=a[i]; return s;
}
int main(void){
    setvbuf(stdout,0,2,0);
    int ok = (pick(41)==42 && suma(5)==15);
    printf("dce-alloca: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
