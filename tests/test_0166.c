/* `__alignof__(T)` / `_Alignof(T)` in a static initializer must fold. sic's
 * eval_const_int handled sizeof(T) and __alignof__(expr) but NOT __alignof__(T),
 * so the field failed to evaluate — and a single unfoldable scalar field made
 * sic zero-fill the WHOLE aggregate. QEMU's OBJECT_DEFINE_TYPE emits
 *   static const TypeInfo T_info = { .parent=..., .instance_align=__alignof__(T), ... };
 * so every QOM type ended up as a zeroed struct → type_register_static() saw a
 * NULL .parent and aborted at startup. */
typedef struct InterfaceInfo { const char *typ; } InterfaceInfo;
typedef struct TypeInfo {
    const char *name;
    const char *parent;
    unsigned long instance_size;
    unsigned long instance_align;
    unsigned long class_size;
    int abstract;
    const InterfaceInfo *interfaces;
} TypeInfo;

struct Big { long a, b, c; };

static const TypeInfo my_info = {
    .parent = "parent-type",
    .name = "my-type",
    .instance_size = sizeof(struct Big),
    .instance_align = __alignof__(struct Big),
    .class_size = _Alignof(long),
    .abstract = 0,
    .interfaces = (const InterfaceInfo[]) { { 0 } },
};

int main(void)
{
    if (my_info.parent == 0) return 1;              /* whole struct was zeroed */
    if (my_info.name == 0) return 2;
    if (my_info.instance_size != sizeof(struct Big)) return 3;
    if (my_info.instance_align != __alignof__(struct Big)) return 4;
    if (my_info.class_size != _Alignof(long)) return 5;
    return 0;
}
