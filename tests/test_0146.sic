// Pointer-to-array parameter `T (*e)[N]` (and the 2D-array param `T e[][N]` that
// decays to it): `e[i]` must yield the whole `T[N]` row, then `e[i][j]` the
// element — not collapse a level. QEMU's xtensa reset_tlb_mmu_all_ways takes
// `xtensa_tlb_entry entry[][MAX_TLB_WAY_SIZE]` and writes `entry[wi][ei].asid`.
#include <stdio.h>
typedef struct { int asid; int variable; } entry_t;
static void reset(entry_t e[][4], int nways){
    for (int wi=0; wi<nways; wi++)
        for (int ei=0; ei<4; ei++){ e[wi][ei].asid = wi*10+ei; e[wi][ei].variable = 1; }
}
int main(void){
    setvbuf(stdout,0,_IONBF,0);
    entry_t grid[3][4];
    reset(grid, 3);
    int ok = (grid[0][0].asid==0 && grid[2][3].asid==23 && grid[1][2].variable==1);
    // explicit pointer-to-array too
    entry_t (*p)[4] = grid;
    if (p[2][3].asid != 23) ok = 0;
    printf("ptr-to-array-param: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
