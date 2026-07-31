/* Dereferencing a pointer-to-array in rvalue position must decay to the array's
 * address, not load a scalar from its first element. sic's Deref lowering only
 * skipped the load for function pointers, so `*(T(*)[N])p` read garbage. QEMU's
 * coroutine trampoline does `siglongjmp(*(sigjmp_buf *)co->entry_arg, 1)` where
 * sigjmp_buf is `struct __jmp_buf_tag[1]`; the stray load handed the saved rbx
 * to __longjmp as the jmp_buf and crashed qemu-system-* during monitor init. */
typedef long arr_t[4];

static long first;
static long sum_via_ptr(void *p)
{
    /* *(arr_t *)p must decay to p (an array read), giving access to all 4
     * elements — not load a single scalar. */
    long *a = *(arr_t *)p;
    first = a[0];
    return a[0] + a[1] + a[2] + a[3];
}

int main(void)
{
    arr_t g = { 11, 22, 33, 44 };
    long s = sum_via_ptr(&g);
    if (first != 11) return 1;           /* would be garbage before the fix */
    if (s != 11 + 22 + 33 + 44) return 2;
    return 0;
}
