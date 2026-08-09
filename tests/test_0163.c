// A `static` function forward-declared, then CALLED (by an earlier function),
// then defined must resolve the call to the real definition — not to an extern
// synthesized from the forward declaration. QEMU's qht.c does this:
//   static void qht_do_resize_reset(...);           // forward decl
//   static inline void qht_do_resize(...) { qht_do_resize_reset(...); }  // caller
//   static void qht_do_resize_reset(...) { ... }     // definition (later)
// If the call binds to a synthesized extern, the real (uncalled) definition is
// dropped as dead and the extern reference is left undefined at link time.
#include <stdio.h>
static int impl(int x);                         // forward decl
static int wrapper(int x){ return impl(x) + 1; } // calls impl before its def
static int impl(int x){ return x * 2; }          // definition
int use_it(int x){ return wrapper(x); }
int main(void){
    setvbuf(stdout,0,2,0);
    int ok = (use_it(20) == 41);
    printf("static-fwd-then-def: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
