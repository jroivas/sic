// An anonymous enum defined inline as a struct field type contributes its
// constants to the enclosing scope (QEMU util/error-report.c:
// `typedef struct Location { enum { LOC_NONE, LOC_CMDLINE, LOC_FILE } kind; ... }`).
// sic didn't register enum constants nested inside struct field types → the
// constant `LOC_NONE` used in a function body was "undefined name".
#include <stdio.h>

typedef struct Location {
    enum { LOC_NONE, LOC_CMDLINE, LOC_FILE } kind;
    int num;
} Location;

// nested inside a union field too
typedef struct {
    union { enum { U_A = 5, U_B, U_C } tag; int raw; } u;
} Wrap;

static Location cur = { .kind = LOC_NONE };
static void reset(Location *l){ l->kind = LOC_NONE; }

int main(void){
    setvbuf(stdout,0,_IONBF,0);
    int ok = 1;
    if (LOC_NONE != 0 || LOC_CMDLINE != 1 || LOC_FILE != 2) ok=0;
    if (U_A != 5 || U_B != 6 || U_C != 7) ok=0;
    if (cur.kind != LOC_NONE) ok=0;
    Location a; a.kind = LOC_FILE; reset(&a);
    if (a.kind != LOC_NONE) ok=0;
    printf("nested-enum: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
