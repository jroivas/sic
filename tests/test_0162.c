// A compound literal in a static initializer must be materialized as a real
// global to point at. QEMU's generated QEnumLookup tables do this:
//   .array = (const char *const[]){ [ENUM_A]="a", ... }, .size = ENUM__MAX
// Without it the whole struct failed to serialize (zero-filled), so .size was 0
// and qapi_enum_lookup asserted `val < lookup->size` at startup (qemu-keymap).
#include <stdio.h>
#include <string.h>
typedef enum { E_NONE, E_A, E_B, E__MAX } E;
typedef struct { const char *const *array; const int size; } EnumLookup;
const EnumLookup lk = {
    .array = (const char *const[]) { [E_NONE]="none", [E_A]="a", [E_B]="b" },
    .size = E__MAX,
};
int main(void){
    setvbuf(stdout,0,2,0);
    int ok = (lk.size == 3)
          && !strcmp(lk.array[E_NONE], "none")
          && !strcmp(lk.array[E_A], "a")
          && !strcmp(lk.array[E_B], "b");
    printf("compound-literal-in-init: %s (size=%d)\n", ok?"OK":"FAIL", lk.size);
    return ok?0:1;
}
