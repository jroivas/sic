// `sizeof(global_array)` in a *scalar* file-scope initializer must fold to a
// real value (build_global_init must use the sizeof-aware evaluator), and a
// header's incomplete `extern T a[];` seen before the sized definition must not
// mask the real length. QEMU's keymap does exactly this:
//   extern const guint16 map[];                       // in a header
//   const guint16 map[525] = { ... };                 // in a generated .inc
//   const guint map_len = sizeof(map)/sizeof(map[0]); // must be 525, not 0
// A zero length made qemu-keymap assert `lnx < ..._len`.
#include <stdio.h>
extern const unsigned short map[];
const unsigned short map[525] = { [524] = 9, [0] = 1 };
const unsigned map_len = sizeof(map) / sizeof(map[0]);
const unsigned map_bytes = sizeof(map);
int main(void){
    setvbuf(stdout,0,2,0);
    int ok = (map_len == 525) && (map_bytes == 1050) && (map[524] == 9) && (map[0] == 1);
    printf("sizeof-global-in-init: %s (len=%u)\n", ok?"OK":"FAIL", map_len);
    return ok?0:1;
}
