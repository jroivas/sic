// `__attribute__((weak))` on a function was dropped (it only worked on variables):
// Linux's __weak defaults collided with their arch overrides at link time. A weak
// reference nothing defines is null.
#include <stdio.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)
#define __weak __attribute__((__weak__))
#define __init __attribute__((__section__(".init.text")))

void __weak w_after_type(void) {}
__weak int w_before_type(int x) { return x + 1; }
int __init __weak w_with_section(void) { return 5; }
int __weak __init w_section_after(void) { return 6; }
int w_proto(void) __weak;
int w_proto(void) { return 7; }
extern int w_extern(void) __weak;
int w_extern(void) { return 8; }
const char *__weak w_ptr(void) { return "p"; }

// Nothing defines these.
extern void undefined_fn(void) __weak;
extern int undefined_fn2(int) __attribute__((weak));
extern int undefined_var __weak;
int undef_proto(void) __weak, undef_proto2(void) __weak;

extern int w_var_decl __weak;
int w_var_decl = 9;

static int (*const fp)(int) = undefined_fn2;

int main(void)
{
	w_after_type();
	CHECK(w_before_type(1) == 2);
	CHECK(w_with_section() == 5 && w_section_after() == 6);
	CHECK(w_proto() == 7 && w_extern() == 8);
	CHECK(w_ptr()[0] == 'p');
	CHECK(w_var_decl == 9);

	CHECK(!undefined_fn && !undefined_fn2 && !fp);
	CHECK(!&undefined_var);
	CHECK(!undef_proto && !undef_proto2);
	if (undefined_fn)
		undefined_fn();
	return 42;
}
