// Short-circuit constant folding of `&&`/`||`: a constant-false `&&` (or
// constant-true `||`) folds even when the other operand is runtime, so the
// branch is dead-code-eliminated. QEMU user-mode has `if (kvm_enabled() && x)`
// where `kvm_enabled()` is `(0)`; without short-circuit folding the guarded call
// to the (unstubbed) kvm_arch_get_supported_cpuid stays -> undefined at link.
#include <stdio.h>
extern int kvm_only(int);          // must never be referenced/linked
#define kvm_enabled() (0)
static int f(int x, int pmu){
    if (kvm_enabled() && pmu && (x > 5)) return kvm_only(x);
    return x + 1;
}
#define always() (1)
static int g(int x){
    if (always() || kvm_only(x)) return x * 2;   // || short-circuits: RHS dead
    return 0;
}
int main(void){
    setvbuf(stdout,0,2,0);
    int ok = (f(10,1)==11 && g(21)==42);
    printf("shortcircuit-dce: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
