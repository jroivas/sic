// SIC's built-in type names are ordinary names in C: a typedef wins (Linux's
// `typedef struct { unsigned int len; const char *data; } string;`).

#define CHECK(c) do { if (!(c)) return __LINE__ & 0x7f; } while (0)

typedef struct { unsigned len; const char *data; } string;
typedef int any;
typedef long fixed;
typedef short bigint;
typedef char u8char;
typedef int list;
typedef int dict;
typedef int set;
typedef int va_array;
typedef int va_dict;
typedef short i8;
typedef int u8;
typedef char u32;
typedef long f32;
typedef int f64;
typedef char usize;
typedef short isize;

static unsigned f(string s)
{
	return s.len + (s.data[0] == 'a');
}

int main(void)
{
	string s = { 3, "abc" };
	u8 neg = -1;

	CHECK(f(s) == 4);
	CHECK(sizeof(s) == 16);
	CHECK(sizeof(any) == 4 && sizeof(fixed) == 8 && sizeof(bigint) == 2);
	CHECK(sizeof(u8char) == 1 && sizeof(list) == 4 && sizeof(dict) == 4);
	CHECK(sizeof(set) == 4 && sizeof(va_array) == 4 && sizeof(va_dict) == 4);
	CHECK(sizeof(i8) == 2 && sizeof(u8) == 4 && sizeof(u32) == 1);
	CHECK(sizeof(f32) == 8 && sizeof(f64) == 4);
	CHECK(sizeof(usize) == 1 && sizeof(isize) == 2);
	CHECK(neg < 0);

	// A block-scope typedef, and names that are no type at all.
	{
		typedef struct { char c[3]; } string;
		typedef short set;
		string t;

		CHECK(sizeof(t) == 3 && sizeof(set) == 2);
	}
	CHECK(sizeof(string) == 16 && sizeof(set) == 4);
	CHECK(sizeof(s) == 16);

	// Nested, and in a loop body that is lowered once per use.
	{
		typedef char set;

		{
			typedef short set;

			CHECK(sizeof(set) == 2);
		}
		CHECK(sizeof(set) == 1);
	}
	CHECK(sizeof(set) == 4);
	for (int i = 0; i < 2; i++) {
		typedef long set;

		CHECK(sizeof(set) == 8);
	}
	CHECK(sizeof(set) == 4);
	return 42;
}

// Variables and members of these names.
int names(void)
{
	int bigint2 = 1;
	struct { int string, set, any; } m = { 1, 2, 3 };

	return bigint2 + m.string + m.set + m.any;
}
