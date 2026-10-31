// File-scope `asm("…");` reaches the assembler (it was dropped, and with it every
// EXPORT_SYMBOL in Linux's C files). Variables of one named section share one ELF
// section, relocations included (modpost reads one `.modinfo`).
#include <stdio.h>
#include <string.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)
#define __stringify_1(x...) #x
#define __stringify(x...) __stringify_1(x)
#define ASM_NL ;

// A function written in assembler, called from C.
asm(".text\n"
    ".globl asm_add\n"
    ".type asm_add,@function\n"
    "asm_add:\n"
    "\tleaq (%rdi,%rsi), %rax\n"
    "\tret\n"
    ".size asm_add, .-asm_add\n");
long asm_add(long a, long b);

// Linux's ___EXPORT_SYMBOL: one line, `;` separated, stringified.
int exported_fn(void) { return 7; }
int exported_var = 8;
#define EXPORT_ENTRY(sym, lic)					\
	.section "exports","aw"			ASM_NL	\
	__export_symbol_##sym:				ASM_NL	\
	.asciz lic				ASM_NL	\
	.balign 8				ASM_NL	\
	.quad sym				ASM_NL	\
	.previous
#define EXPORT(sym, lic) asm(__stringify(EXPORT_ENTRY(sym, lic)))
EXPORT(exported_fn, "GPL");
EXPORT(exported_var, "GPL");

struct exp { char lic[8]; void *sym; };
extern struct exp __start_exports[], __stop_exports[];

// Assembler referring to a `static` of this unit, data the C code reads.
static int local_value __attribute__((used)) = 11;
__asm__(".pushsection .data\n"
        "asm_ptr:\n"
        "\t.quad local_value\n"
        ".popsection\n"
        ".globl asm_ptr_addr\n"
        ".set asm_ptr_addr, asm_ptr\n");
extern int *const asm_ptr_addr;

// The section after a file-scope asm is still what C expects.
static int after_asm(void) { return 3; }

// Many variables of one named section, with pointers.
struct item { const char *name; int (*fn)(void); };
static int f1(void) { return 1; }
static int f2(void) { return 2; }
#define ITEM(n, f) static const struct item item_##n __attribute__((used, section("items"), aligned(8))) = { #n, f }
ITEM(one, f1);
ITEM(two, f2);
ITEM(three, f1);
extern const struct item __start_items[], __stop_items[];

static const char info1[] __attribute__((used, section("infos"), aligned(1))) = "license=GPL";
static const char info2[] __attribute__((used, section("infos"), aligned(1))) = "author=me";
static const char info3[] __attribute__((used, section("infos"), aligned(1))) = "alias=x";
extern const char __start_infos[], __stop_infos[];

int main(void)
{
	CHECK(asm_add(2, 3) == 5);
	CHECK(__stop_exports - __start_exports == 2);
	CHECK(!strcmp(__start_exports[0].lic, "GPL"));
	CHECK(__start_exports[0].sym == (void *)exported_fn);
	CHECK(__start_exports[1].sym == (void *)&exported_var);
	CHECK(*asm_ptr_addr == 11);
	CHECK(after_asm() == 3);

	CHECK(__stop_items - __start_items == 3);
	int sum = 0, found = 0;
	for (const struct item *i = __start_items; i < __stop_items; i++) {
		sum += i->fn();
		found += !strcmp(i->name, "two");
	}
	CHECK(sum == 4 && found == 1);

	// no gaps and all there: a reader walks the strings
	int count = 0;
	for (const char *p = __start_infos; p < __stop_infos; p += strlen(p) + 1)
		count += *p != 0;
	CHECK(count == 3 && __stop_infos - __start_infos == 12 + 10 + 8);
	return 42;
}
