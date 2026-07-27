// A static initializer that takes the address of the object being initialized
// (or one of its fields) must emit a relocation to itself, not NULL. QEMU's
// QTAILQ_HEAD_INITIALIZER(list) sets `list.tqh_circ.tql_prev = &list.tqh_circ`;
// getting it wrong made the first list insert dereference NULL (SIGSEGV in
// register_aiocontext / main-loop init).
#include <stdio.h>
struct Circ { void *next, *prev; };
struct Head { void *first; struct Circ circ; };
static struct Head list = { NULL, { NULL, &list.circ } };   // self-referential
static int *selfp = (int *)&selfp;                          // whole-object self-ref
int main(void){
    setvbuf(stdout,0,2,0);
    int ok = (list.circ.prev == (void*)&list.circ)
          && (list.circ.next == NULL)
          && (selfp == (int *)&selfp);
    printf("self-ref-static-init: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
