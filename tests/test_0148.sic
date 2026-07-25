// A tentative definition — a non-`extern` file-scope variable with no
// initializer — is a real (zero-initialized) definition in C, even when a
// prior `extern` declaration (from a header) was already seen. sic must emit
// it as a defined bss symbol, not leave it undefined. QEMU declares
// `error_abort`, `trace_events_enabled_count`, `qemu_loglevel`, etc. this way,
// so getting it wrong left ~250 objects unlinkable.
#include <stdio.h>
extern int g_count;          // header-style forward declaration
extern long g_table[4];
int g_count;                 // tentative DEFINITION (upgrades the extern)
long g_table[4];             // tentative DEFINITION
int bump(void){ return ++g_count; }
int main(void){
    setvbuf(stdout,0,2,0);
    g_table[2] = 42;
    int ok = (bump()==1 && bump()==2 && g_count==2 && g_table[2]==42 && g_table[0]==0);
    printf("tentative-def: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
