// Regression: C11 anonymous struct/union members. A field declared inside an
// unnamed struct/union member is accessed as if it belonged to the enclosing
// aggregate (`h.reg` where `reg` lives in an anonymous union). sic's field
// resolver only looked at direct members, so `h.reg` errored "no field 'reg'".
// This blocked QEMU's idef-parser (its HexValue has an anonymous union of
// reg/tmp/imm/... members). The resolver must drill through anonymous members
// and compute the cumulative byte offset.

typedef struct { int rtype; int id; } Reg;
typedef struct { long v; } Tmp;

typedef struct HexValue {
    union {
        Reg reg;
        Tmp tmp;
    };
    int type;
    unsigned bit_width;
} HexValue;

// Anonymous member that is NOT at offset 0 (verifies cumulative offset).
struct Outer {
    long header;
    struct {          // anonymous struct at offset 8
        int a;
        int b;
    };
    long trailer;
};

// Nested anonymous members.
struct Nest {
    union {
        struct {
            int x;
            int y;
        };
        long combined;
    };
};

int main(void)
{
    HexValue h;
    h.reg.rtype = 5;
    h.reg.id = 7;
    h.type = 1;
    h.bit_width = 32;
    if (h.reg.rtype != 5 || h.reg.id != 7) return 1;
    if (h.type != 1 || h.bit_width != 32) return 2;
    // Writing through a different union arm aliases the same storage.
    h.tmp.v = 0;
    if (h.reg.rtype != 0) return 3;

    struct Outer o;
    o.header = 100;
    o.a = 11;
    o.b = 22;
    o.trailer = 200;
    if (o.a != 11 || o.b != 22) return 4;
    if (o.header != 100 || o.trailer != 200) return 5;
    // The anonymous struct really is at offset 8 (right after `header`).
    if ((char *)&o.a - (char *)&o != 8) return 6;

    struct Nest n;
    n.x = 0x11111111;
    n.y = 0x22222222;
    // x/y overlap `combined` (little-endian: low word = x).
    if ((n.combined & 0xffffffff) != 0x11111111) return 7;

    return 0;
}
