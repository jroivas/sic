// enum values built from sizeof of a *global* array — `enum { N = ARRAY_SIZE(g) }`
// (QEMU e1000e/igb `NREADOPS`, smbios `..._LEN`). Enums are registered before
// globals are lowered, so sic pre-records global variable types (with array
// lengths inferred from initializers) to fold sizeof(global) at that point.
#include <stdio.h>
#include <stddef.h>

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

typedef void (*op_t)(int);
static void o0(int x){(void)x;} static void o1(int x){(void)x;}
static void o2(int x){(void)x;} static void o3(int x){(void)x;}

static op_t const readops[] = { o0, o1, o2, o3 };     // sized by initializer
static const int table[] = { 10, 20, 30 };

enum { NREADOPS = ARRAY_SIZE(readops) };              // = 4
enum { NTABLE = ARRAY_SIZE(table), NHALF = NTABLE / 2 + 1 };

// offsetofend = offsetof(type,m) + sizeof(member) — QEMU smbios `..._LEN_V28`.
// Needs the const evaluator to fold offsetof AND sizeof-of-member together.
#define offsetofend(t, m) (offsetof(t, m) + sizeof(((t *)0)->m))
struct Rec { int a; char name[12]; long tail; };
enum { REC_HDR_LEN = offsetofend(struct Rec, name) };   // 4 + 12 = 16

int main(void){
    setvbuf(stdout,0,_IONBF,0);
    int ok = 1;
    if (NREADOPS != 4) ok=0;
    if (NTABLE != 3 || NHALF != 2) ok=0;
    if (REC_HDR_LEN != 16) ok=0;
    printf("enum-arraysize: %s\n", ok?"OK":"FAIL");
    return ok?0:1;
}
