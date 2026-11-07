/* Linker-defined bounds of an empty table are one address: the loop must not run
   (Linux's __start_builtin_fw / __end_builtin_fw with no built-in firmware). */
struct b { const char *name; void *data; unsigned long size; };
extern struct b __start_tbl[];
extern struct b __end_tbl[];
extern int known;
__asm__(".data\n.globl __start_tbl\n.globl __end_tbl\n.globl known\n"
        ".p2align 3\n__start_tbl:\n__end_tbl:\nknown:\n.long 7\n.long 9\n.text\n");
static int count(void) {
    int n = 0;
    for (struct b *p = __start_tbl; p != __end_tbl; p++) n += p->name[0];
    return n;
}
int main(void) {
    if (count() != 0) return 1;
    if (__start_tbl != __end_tbl) return 2;
    if (known != 7 || (&known)[1] != 9) return 3;
    return 0;
}
