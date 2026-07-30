/* An implicit-length compound-literal array `(T[]){ a, b, c }` used as a struct
 * field must reserve storage for all its elements. sic lowered it to a `[T; 0]`
 * alloca (1 byte), so the element stores overflowed into neighboring stack slots
 * — which a later variadic call (g_strdup_printf) then reused, clobbering the
 * array. Mirrors QEMU's virtio_pci_types_register:
 *   .interfaces = (const InterfaceInfo[]){ {INTERFACE_PCIE_DEVICE}, {..}, {} }
 * followed by g_strdup_printf("%s-base-type", ...) → the 2nd interface pointer
 * was overwritten and type_new() dereferenced garbage. */
extern int snprintf(char *, unsigned long, const char *, ...);

struct InterfaceInfo { const char *type; };
struct TypeInfo { const char *name; const char *parent; const struct InterfaceInfo *interfaces; };

static int count_and_check(const struct TypeInfo *t)
{
    int n = 0;
    const char *want[3] = { "pcie", "conventional", 0 };
    for (int i = 0; t->interfaces && t->interfaces[i].type; i++) {
        const char *a = t->interfaces[i].type, *b = want[i];
        while (*a && *a == *b) { a++; b++; }
        if (*a != *b) return -1;                  /* content clobbered */
        n++;
    }
    return n;
}

static int build(const char *gname)
{
    struct TypeInfo base = { .name = 0 };
    struct TypeInfo generic = {
        .name = gname,
        .parent = base.name,
        .interfaces = (const struct InterfaceInfo[]) {
            { "pcie" }, { "conventional" }, { }
        },
    };
    char buf[64];
    if (!base.name) {
        /* variadic call between the array's init and its use — this is what
         * reused the overflowed stack in the real bug. */
        snprintf(buf, sizeof buf, "%s-base-type", gname);
        generic.parent = buf;
    }
    return count_and_check(&generic);
}

int main(void)
{
    if (build("virtio-sound-pci") != 2) return 1;   /* clobbered → wrong count/content */
    return 0;
}
