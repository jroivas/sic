// `__attribute__((alias("x")))` names the same object or function. It was ignored:
// a variable got a zero-filled copy (every MODULE_DEVICE_TABLE of Linux, seen by
// modpost as "Invalid WMI device id 'wmi:'"), a function stayed undefined.
#include <stdio.h>
#include <string.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)
#define __stringify_1(x...) #x
#define __stringify(x...) __stringify_1(x)

struct id { char guid[8]; const void *ctx; };
static const struct id table[] = { { .guid = "abc" }, { .guid = "de" }, { } };
#define DEVICE_TABLE(name) \
	static typeof(name) devtab_##name __attribute__((used, alias(__stringify(name))))
DEVICE_TABLE(table);

int target_var = 5;
extern int alias_var __attribute__((alias("target_var")));
static int static_target = 6;
static int alias_static __attribute__((alias("static_target")));

int tgt(int x) { return x + 1; }
int alias_fn(int) __attribute__((alias("tgt")));
extern int ext_alias(int) __attribute__((__alias__("tgt")));
int weak_alias(int) __attribute__((weak, alias("tgt")));
int concat_alias(int) __attribute__((alias("t" "gt")));

// The target is used by nothing but the alias.
static int only_via_alias(int x) { return x * 2; }
int doubled(int) __attribute__((alias("only_via_alias")));

static int static_alias(int) __attribute__((alias("tgt")));

int main(void)
{
	CHECK(!strcmp(devtab_table[1].guid, "de"));
	CHECK(sizeof(devtab_table) == sizeof(table));
	CHECK(&devtab_table[0] == &table[0]);

	alias_var = 9;
	CHECK(target_var == 9 && &alias_var == &target_var);
	alias_static = 7;
	CHECK(static_target == 7);

	CHECK(alias_fn(1) == 2 && ext_alias(2) == 3 && weak_alias(3) == 4 && concat_alias(4) == 5);
	CHECK(doubled(4) == 8 && static_alias(1) == 2);
	CHECK(alias_fn == tgt);
	return 42;
}
