// __BASE_FILE__ is the main input file even inside a header, __FILE_NAME__ the
// current file without its directories. Linux's snd_use_lock_sync passes
// __BASE_FILE__ to its wait helper.
#include <stdio.h>
#include <string.h>
#define CHECK(c) do { if (!(c)) { printf("fail line %d\n", __LINE__); return 1; } } while (0)

#ifndef __BASE_FILE__
#error __BASE_FILE__ is not defined
#endif
#if !defined(__FILE_NAME__)
#error __FILE_NAME__ is not defined
#endif

#include "test_0684.h"

#define STR2(x) #x
#define STR(x) STR2(x)

static int ends(const char *s, const char *tail)
{
	size_t a = strlen(s), b = strlen(tail);
	return a >= b && !strcmp(s + a - b, tail);
}

int main(void)
{
	CHECK(ends(__BASE_FILE__, "test_0684.c"));
	CHECK(!strcmp(__BASE_FILE__, __FILE__));
	CHECK(!strcmp(__FILE_NAME__, "test_0684.c"));
	CHECK(sizeof(__FILE_NAME__) == sizeof("test_0684.c"));

	CHECK(ends(hdr_file, "test_0684.h"));
	CHECK(!strcmp(hdr_base, __FILE__));
	CHECK(!strcmp(hdr_name, "test_0684.h"));
	CHECK(!strcmp(BASE_IN_MACRO, __FILE__));
	CHECK(ends(STR(__BASE_FILE__), "test_0684.c\""));
	return 42;
}
