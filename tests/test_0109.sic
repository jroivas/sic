// Regression: `sizeof(p->aCol[0])` where `aCol` is a pointer to a struct must
// use the struct's full size, not 0. sic keeps a pointer's pointee aggregate
// *opaque* (fields stripped) and resolves it on demand; the `Deref` (`*p`) path
// resolved it but the `Index` (`p[i]`) path did not, so `sizeof(ptr[0])` came
// out 0. In SQLite this made `sqlite3AddColumn` request a 0-byte aCol array,
// which `sqlite3DbMallocRawNN` served from lookaside even when lookaside was
// disabled (because `0 > 0` is false) — a lookaside pointer stored in a
// committed schema object, later crashing sqlite3_close with "invalid free".

struct Column { char *zName; int flags; long extra; };   // 24 bytes
struct Table  { struct Column *aCol; int nCol; };

int main(void)
{
    struct Table *p = 0;
    struct Column *c = 0;

    // Element of a pointer-to-struct via [] and via *.
    if (sizeof(p->aCol[0]) != sizeof(struct Column)) return 1;
    if (sizeof(*p->aCol)   != sizeof(struct Column)) return 2;
    if (sizeof(c[0])       != sizeof(struct Column)) return 3;
    if (sizeof(*c)         != sizeof(struct Column)) return 4;

    // The exact expression shape from the bug: (nCol+1) * sizeof(aCol[0]).
    if ((0 + 1) * sizeof(p->aCol[0]) != sizeof(struct Column)) return 5;
    if ((3 + 1) * sizeof(c[0])       != 4 * sizeof(struct Column)) return 6;

    // And that a real allocation-sized computation is non-zero and usable.
    long n = 2 * (long)sizeof(c[0]);
    if (n != 48) return 7;

    return 0;
}
