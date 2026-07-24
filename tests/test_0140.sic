// A declaration whose type is a function typedef declares a *function*, not a
// variable: `static Handler foo;` then `static int foo(...) {...}`. QEMU
// target/xtensa/xtensa-semi.c does this (`static IOCanReadHandler
// sim_console_can_read;`). sic used to emit a function-typed global, colliding
// with the definition ("Incompatible declaration").
#include <stdio.h>

typedef int Handler(void *opaque);

static Handler myfn;                       // forward declaration via typedef
static int other(void *p) { (void)p; return 7; }

static int myfn(void *p) { (void)p; return 42; }   // definition

int main(void){
    setvbuf(stdout,0,_IONBF,0);
    int ok = (myfn(0) == 42 && other(0) == 7);
    /* also use it as a function pointer */
    Handler *fp = myfn;
    if (fp(0) != 42) ok = 0;
    printf("func-typedef-decl: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
