// C struct tags and typedef names share sic's type map. A `typedef Fwd Tag;`
// whose name equals an already-completed struct tag must NOT overwrite the real
// definition with the forward alias's empty snapshot. QEMU's QOM does exactly
// this: `typedef struct ArchCPU HexagonCPU;` (forward) ... `struct ArchCPU {..}`
// ... `typedef HexagonCPU ArchCPU;`.
#include <stdio.h>
typedef struct ArchCPU HexCPU;         // forward typedef (struct incomplete)
struct ArchCPU { int env; int adj; };  // completed here
typedef HexCPU ArchCPU;                 // alias whose name == the struct tag
int main(void){
    setvbuf(stdout,0,_IONBF,0);
    HexCPU c; HexCPU *p = &c;
    p->env = 5; p->adj = 9;
    ArchCPU *q = p;                     // use the colliding alias too
    int ok = (p->env==5 && p->adj==9 && q->env==5);
    printf("fwd-typedef-tag-collision: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
