// `*arr = scalar` where arr is an array (so it decays to a pointer to its
// element) must be a scalar store, not an aggregate memcpy — sic surfaces the
// deref's type as the array, and the vector/aggregate-assignment path must not
// hijack a scalar RHS. Regression from AES/SIMD aggregate-copy work; hit by
// libdecnumber decNumber.c `*res->lsu = 1;`.
#include <stdio.h>
typedef unsigned short Unit;
struct N { int digits; Unit lsu[8]; };
static void setone(struct N *n){ *n->lsu = 1; }        // *arr = scalar
int main(void){
    setvbuf(stdout,0,2,0);
    struct N n; for (int i=0;i<8;i++) n.lsu[i]=9;
    setone(&n);
    // also a plain local array deref
    Unit a[4] = {5,5,5,5}; *a = 7;
    int ok = (n.lsu[0]==1 && n.lsu[1]==9 && a[0]==7 && a[1]==5);
    printf("deref-array-scalar-store: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
