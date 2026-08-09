// A definition must upgrade a prior `extern`/tentative declaration of the same
// global. QEMU's hexagon opcodes.h declares `extern const T opcode_encodings[];`
// then the .c file defines it; sic's duplicate-declaration guard used to drop
// the definition, leaving the symbol undefined at link time.
#include <stdio.h>

// extern declarations first (as a header would provide)
extern const char * const g_names[];
extern const int g_vals[];
extern int g_tentative;          // tentative (no initializer)

// real definitions afterwards
const char * const g_names[] = { "a", "b", "c" };
const int g_vals[] = { 10, 20, 30 };
int g_tentative = 7;

// Incomplete-size array with sparse designated initializers: length must be the
// highest index reached (max+1), not the number of entries (QEMU hexagon's
// `const OpcodeEncoding opcode_encodings[] = { [TAG] = ... }`).
enum { E_A = 0, E_B = 5, E_C = 10, E_NN };
typedef struct { const char *enc; } Enc;
const Enc g_enc[] = { [E_A] = {"aa"}, [E_B] = {"bb"}, [E_C] = {"cc"} };

static const char *name_of(int i){ return g_names[i]; }
static int val_of(int i){ return g_vals[i]; }

int main(void){
    setvbuf(stdout,0,_IONBF,0);
    int ok = 1;
    if (name_of(1)[0] != 'b') ok=0;
    if (val_of(2) != 30) ok=0;
    if (g_tentative != 7) ok=0;
    // sparse designated array: sized to max index + 1 = 11, entries at their index
    if (sizeof(g_enc)/sizeof(g_enc[0]) != 11) ok=0;
    if (g_enc[E_A].enc[0]!='a' || g_enc[E_B].enc[0]!='b' || g_enc[E_C].enc[0]!='c') ok=0;
    if (g_enc[1].enc != 0) ok=0;   // gap entries are zero
    printf("extern-then-define: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
