// A file-scope array sized by an enum constant (`T arr[SOME_ENUM_MAX]`) must get
// the right storage. The scope-less global type path didn't resolve enum
// constants, so it came out length 0 — QEMU's `init_type_list[MODULE_INIT_MAX]`
// then had 8 bytes and overlapped the next global, crashing every emulator at
// startup (register_module_init).
#include <stdio.h>
enum { INIT_A, INIT_B, INIT_C, MODULE_INIT_MAX };   // MODULE_INIT_MAX == 3
struct Head { void *first; void *last; };
static struct Head init_type_list[MODULE_INIT_MAX];
static int sentinel = 0x1234;
int main(void){
    setvbuf(stdout,0,2,0);
    for (int i=0;i<MODULE_INIT_MAX;i++){ init_type_list[i].first=(void*)1; init_type_list[i].last=(void*)2; }
    int ok = (sizeof(init_type_list) == (size_t)MODULE_INIT_MAX*sizeof(struct Head))
          && sentinel == 0x1234;   // writes to the array must not clobber the next global
    printf("enum-global-array-size: %s (sizeof=%zu)\n", ok?"OK":"FAIL", sizeof(init_type_list));
    return ok?0:1;
}
