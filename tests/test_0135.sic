// GCC case-ranges must be lowered as bounds checks, NOT enumerated. QEMU's
// target/arm/ptw.c has `case 0xF0000000 ... 0xFFFFFFFF:` (268M values); sic used
// to expand each value into a switch arm → hundreds of millions of arms → the
// backend hung for tens of minutes. Now ranges compile in O(1).
#include <stdio.h>

static int classify(int x){
    switch (x) {
    case 0 ... 9:                    return 1;
    case 20 ... 29:                  return 2;
    case 100:                        return 3;   // single value mixed with ranges
    case 0x7FFFFFF0 ... 0x7FFFFFFF:  return 4;   // huge range near INT_MAX
    default:                         return 0;
    }
}

// Range + fallthrough sharing a body (multiple range labels → one block).
static int band(int x){
    switch (x) {
    case 0 ... 3:
    case 8 ... 11:
        return 1;
    default:
        return 0;
    }
}

int main(void){
    setvbuf(stdout,0,_IONBF,0);
    int ok = 1;
    if (classify(5) != 1 || classify(9) != 1) ok=0;
    if (classify(10) != 0) ok=0;                 // gap between ranges
    if (classify(25) != 2 || classify(100) != 3) ok=0;
    if (classify(50) != 0) ok=0;
    if (classify(0x7FFFFFF5) != 4 || classify(0x7FFFFFFF) != 4) ok=0;
    if (classify(0x7FFFFFEF) != 0) ok=0;         // just below the big range

    if (band(2) != 1 || band(9) != 1) ok=0;
    if (band(5) != 0) ok=0;                      // gap between the two ranges

    printf("case-range: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
