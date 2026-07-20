// `sizeof(global_expr)` inside a static initializer (QEMU s390x gen-features:
// `ARRAY_SIZE(base_##name)` = sizeof(global_array)/sizeof(elem) sets a struct
// field). sic couldn't fold sizeof-of-a-global during constant serialization, so
// the whole aggregate zero-filled → NULL `.name` pointers → strcmp segfault.
#include <stdio.h>
#include <stdint.h>

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

typedef struct { uint16_t *data; uint32_t len; } BitSpec;
typedef struct { const char *name; BitSpec bits; } Spec;

static uint16_t base_A[] = { 1, 2, 3 };
static uint16_t base_B[] = { 7, 8 };

// nested designated init: pointer-to-global fields + sizeof-of-global lengths.
static const Spec defs[] = {
    { .name = "AA", .bits = { .data = base_A, .len = ARRAY_SIZE(base_A) } },
    { .name = "BB", .bits = { .data = base_B, .len = ARRAY_SIZE(base_B) } },
};

int main(void){
    setvbuf(stdout,0,_IONBF,0);
    int ok = 1;
    if ((int)ARRAY_SIZE(defs) != 2) ok=0;
    if (!defs[0].name || !defs[1].name) ok=0;          // not zero-filled
    if (defs[0].name[0] != 'A' || defs[1].name[0] != 'B') ok=0;
    if (defs[0].bits.len != 3 || defs[1].bits.len != 2) ok=0;
    if (defs[0].bits.data[0] != 1 || defs[1].bits.data[1] != 8) ok=0;
    printf("sizeof-global-init: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
