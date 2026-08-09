/* va_list forwarding to glibc with many stack-spilled varargs.
 *
 * A sic-compiled variadic function that forwards its va_list to libc (exactly
 * what QEMU's qemu_fprintf -> vfprintf does) must build a System V va_list whose
 * overflow_arg_area covers ALL stack-passed varargs, not just the first few.
 * This reproduces x86_cpu_dump_state's dump line: 8 int + 7 char + 5 int = 20
 * varargs, 15 of which spill past the 6 GP registers onto the stack. A too-small
 * overflow capture made everything past the ~8th stack arg print garbage. */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static void myfmt(char *buf, size_t n, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, n, fmt, ap);
    va_end(ap);
}

int main(void)
{
    char buf[256];
    myfmt(buf, sizeof buf,
          "R=%08x %08x %08x %08x %08x %08x %08x %08x "
          "[%c%c%c%c%c%c%c] CPL=%d II=%d A20=%d SMM=%d HLT=%d",
          0u, 0u, 0x02000000u, 0x02000628u, 0x0000000bu, 0x02000000u,
          0x00fab010u, 0x00006d5cu,
          '-', '-', '-', 'Z', '-', 'P', '-',
          0, 1, 1, 1, 0);

    const char *want =
        "R=00000000 00000000 02000000 02000628 0000000b 02000000 "
        "00fab010 00006d5c [---Z-P-] CPL=0 II=1 A20=1 SMM=1 HLT=0";

    if (strcmp(buf, want) != 0) {
        /* Show what we actually got, to aid debugging on failure. */
        printf("got : %s\n", buf);
        printf("want: %s\n", want);
        return 1;
    }
    return 0;
}
