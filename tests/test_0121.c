#include <stdio.h>
typedef struct { int x, y, z; } P3;
typedef struct { int req; union { unsigned long u64; struct { int a; int b; } area; } payload; } Msg;
int garr[8] = { [2] = 20, [5] = 50, [0] = 5 };   // global sparse array
P3 gp = { .z = 3, .x = 1 };                        // global reordered struct
Msg gm = { .req = 7, .payload.area = { .b = 2, .a = 1 } };  // global nested
int main(void){
    setvbuf(stdout,0,_IONBF,0);
    int ok = 1;
    if (garr[0]!=5||garr[2]!=20||garr[5]!=50||garr[1]!=0||garr[7]!=0) ok=0;
    if (gp.x!=1||gp.y!=0||gp.z!=3) ok=0;
    if (gm.req!=7||gm.payload.area.a!=1||gm.payload.area.b!=2) ok=0;

    // local versions
    P3 p = { .y = 20, .x = 10 };
    if (p.x!=10||p.y!=20||p.z!=0) ok=0;
    int a[6] = { [3] = 30, [1] = 10 };
    if (a[0]!=0||a[1]!=10||a[3]!=30||a[5]!=0) ok=0;
    Msg m = { .req = 9, .payload.area.a = 100, .payload.area.b = 200 };
    if (m.req!=9||m.payload.area.a!=100||m.payload.area.b!=200) ok=0;
    // mixed positional + designated (cursor resume)
    P3 q = { 1, .z = 9, 5 };  // x=1, then .z=9, then next positional after z => none; y stays 0
    if (q.x!=1||q.z!=9) ok=0;
    // designated array of structs
    P3 arr[3] = { [1].x = 7, [1].y = 8, [2] = { .z = 9 } };
    if (arr[0].x!=0||arr[1].x!=7||arr[1].y!=8||arr[2].z!=9) ok=0;

    printf("designated: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
