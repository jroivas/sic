// A packed enum is as small as its values need, whether the attribute comes
// before the body or after it (Linux: `enum _cache_table_type { … } __packed;`
// with a static_assert that it is one byte).
#define __packed __attribute__((__packed__))

enum small { S1 = 1, S2, S3 } __packed;
enum __packed neg { N1 = -1, N2 = 100 };
enum wide { W1 = 1, W2 = 300 } __packed;
enum big { B1 = 0, B2 = 70000 } __packed;
enum plain { P1, P2 };

_Static_assert(sizeof(enum small) == 1, "small");
_Static_assert(sizeof(enum neg) == 1, "neg");
_Static_assert(sizeof(enum wide) == 2, "wide");
_Static_assert(sizeof(enum big) == 4, "big");
_Static_assert(sizeof(enum plain) == 4, "plain");

struct holder { enum small a; enum small b; char c; };

int main(void)
{
    enum neg n = N1;
    return sizeof(struct holder) == 3 && n < 0 ? 42 : 1;
}
