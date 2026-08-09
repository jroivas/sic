// Regression: identifiers that collide with sic's built-in type aliases
// (u32, u64, i32, ...) must still work as ordinary C identifiers — as field
// names, struct members, and variables. Previously `uint32_t u32;` parsed `u32`
// as a second type specifier, dropping the field name and breaking union/struct
// member access (as in tser's `obj->val.u32`).

struct obj {
    int type;
    union {
        unsigned int u32;
        unsigned long u64;
        struct {
            int len;
            void *data;
        } data;
    } val;
};

int main(void)
{
    // Alias-like names used as plain local variables.
    int u32 = 10;
    int i32 = 20;
    if (u32 + i32 != 30)
        return 1;

    struct obj o;
    o.type = 1;

    // Union members named after type aliases.
    o.val.u32 = 0xABCD;
    if (o.val.u32 != 0xABCD)
        return 2;

    o.val.u64 = 0x1122334455UL;
    if (o.val.u64 != 0x1122334455UL)
        return 3;

    // Nested struct inside the anonymous union.
    o.val.data.len = 7;
    if (o.val.data.len != 7)
        return 4;

    // Pointer + arrow access, mirroring tser's `obj->val.u32`.
    struct obj *p = &o;
    p->val.u32 = 99;
    if (p->val.u32 != 99)
        return 5;

    return 0;
}
