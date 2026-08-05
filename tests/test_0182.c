/* `char a[] = { "str" }` — a brace list wrapping a single string literal —
 * initializes the char array from the string (C11 6.7.9p14), exactly like
 * `char a[] = "str"`. sic treated it as a 1-element list, so the array came out
 * size 1 and empty. QEMU's target/i386 does
 *   static const char eip_name[] = { "rip" };
 * for the cpu_eip TCG global's name. An array of char* with a single string,
 * `const char *p[] = { "str" }`, must stay one pointer element (not a char
 * array). */
#include <string.h>

static const char g_brace[] = { "rip" };
static const char g_plain[] = "rip";
static const char *g_ptrs[] = { "aa", "bb" };
static const char *g_one[]  = { "hello" };

int main(void)
{
    if (sizeof(g_brace) != 4 || strcmp(g_brace, "rip") != 0) return 1;
    if (sizeof(g_brace) != sizeof(g_plain)) return 2;

    char l_brace[] = { "hello" };
    if (sizeof(l_brace) != 6 || strcmp(l_brace, "hello") != 0) return 3;

    static const char l_static[] = { "xyz" };
    if (sizeof(l_static) != 4 || strcmp(l_static, "xyz") != 0) return 4;

    /* array-of-pointers must be unaffected */
    if (sizeof(g_ptrs) / sizeof(g_ptrs[0]) != 2) return 5;
    if (sizeof(g_one) / sizeof(g_one[0]) != 1) return 6;
    if (strcmp(g_ptrs[1], "bb") != 0 || strcmp(g_one[0], "hello") != 0) return 7;

    return 0;
}
