// QEMU-driven fixes: __builtin_clrsb, GNU `?:` (elvis), GNU range array
// designators `[lo ... hi]`, and enum constants referenced across a following
// `typedef enum` (QEMU's FIELD() macro in softfloat-types.h).
#include <stdio.h>

// FIELD()-style: anonymous enums whose constants feed a later typedef enum.
enum { R_1ST_SHIFT = (0) };
enum { R_2ND_SHIFT = (2) };
enum { R_3RD_SHIFT = (4) };
#define RULE(X, Y, Z) (((X) << R_1ST_SHIFT) | ((Y) << R_2ND_SHIFT) | ((Z) << R_3RD_SHIFT))
typedef enum __attribute__((__packed__)) {
    rule_none = 0,
    rule_abc = RULE(0, 1, 2),   // 0 | 4 | 32 = 36
    rule_cba = RULE(2, 1, 0),   // 2 | 4 | 0  = 6
} Rule;

// GNU range array designators (global).
int g[10] = { [2 ... 5] = 7, [8] = 9 };

int main(void){
    setvbuf(stdout,0,_IONBF,0);
    int ok = 1;

    // __builtin_clrsb: leading redundant sign bits.
    if (__builtin_clrsb(0) != 31) ok=0;
    if (__builtin_clrsb(1) != 30) ok=0;
    if (__builtin_clrsb(-1) != 31) ok=0;
    if (__builtin_clrsbll(0) != 63) ok=0;

    // enum-across-typedef-enum values.
    if (rule_abc != 36 || rule_cba != 6) ok=0;

    // GNU `?:` — evaluated once, value is the condition when truthy.
    char *p = 0;
    const char *q = p ?: "def";
    if (q[0] != 'd') ok=0;
    int a = 5; if ((a ?: 9) != 5) ok=0;
    int z = 0; if ((z ?: 42) != 42) ok=0;
    // side effect happens exactly once.
    int calls = 0, arr[4] = {0,0,7,0};
    int idx = 2;
    int v = arr[idx++] ?: 99;   // arr[2]==7 truthy; idx incremented once
    if (v != 7 || idx != 3) ok=0;

    // range designators (global + local).
    if (g[1]!=0||g[2]!=7||g[5]!=7||g[6]!=0||g[8]!=9) ok=0;
    int local[8] = { [1 ... 3] = 4, [6] = 1 };
    if (local[0]!=0||local[1]!=4||local[3]!=4||local[4]!=0||local[6]!=1) ok=0;

    printf("qemu-fixes: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
