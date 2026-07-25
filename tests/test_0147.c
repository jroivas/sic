// A parameter/local that shadows a like-named typedef: `(name)` must parse as a
// parenthesized variable, not a cast. QEMU's s390x mmu_helper/mem_helper do
// `VADDR_PAGE_TX(vaddr)` = `((vaddr) & MASK) >> 12` where `vaddr` is both a
// parameter and `typedef uintptr_t vaddr;`. (C-mode only — this is test_0147.c,
// not .sic, since in sic-lang the aliases are reserved keywords.)
#include <stdio.h>
typedef unsigned long vaddr;
typedef unsigned long entry;
#define MASK 0xff000UL
static unsigned long page_tx(vaddr vaddr){
    return ((vaddr) & MASK) >> 12;      // AND, not (vaddr)(&MASK)
}
int main(void){
    setvbuf(stdout,0,2,0);
    vaddr a = 0xABCDEF123UL;
    unsigned long r = page_tx(a);
    unsigned long g = (a) & 0xf;        // parenthesized-var & const
    entry entry = 5;                    // local shadows typedef 'entry'
    unsigned long h = (entry) + 1;      // parenthesized var, not a cast
    int ok = (r == ((0xABCDEF123UL & MASK) >> 12)) && (g == 3) && (h == 6);
    printf("paren-typedef-shadow: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
