// typeof of a GCC statement-expression `({ ...; e; })` — used pervasively by
// QEMU's qobject_ref/QOBJECT macros: `typeof(({ typeof(x) _o = x; _o; }))`.
// The value type is that of the trailing expression; a trailing bare identifier
// declared inside the block must be resolved from that inner declaration.
#include <stdio.h>
typedef struct QDict { int base; int x; } QDict;
#define REF(obj) ({ typeof(obj) _o = (obj); _o; })
int main(void){
    setvbuf(stdout,0,_IONBF,0);
    QDict d = { 42, 7 };
    QDict *p = &d;
    typeof(REF(p)) q = REF(p);          // typeof of a stmt-expr yielding a pointer
    int ok = (q->base == 42);
    // nested: typeof of a stmt-expr whose last expr is itself a stmt-expr
    typeof(({ REF(p); })) q2 = REF(p);
    if (q2->x != 7) ok = 0;
    printf("typeof-stmt-expr: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
