/* Arguments in the `...` part of a variadic call undergo the default argument
 * promotions: integer types narrower than int widen to int, float widens to
 * double. sic skipped this, so a small integer (e.g. a uint8_t) passed on the
 * stack left its 8-byte slot's high bits uninitialized — libc printf's `%02x`
 * of a uint8_t MAC byte then read garbage, malforming QEMU's default NIC MAC
 * (`52:54:00:12:34:56` came out `52:54:00:12:34:256`), aborting device init. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main(void)
{
    char buf[64];

    /* 6 uint8_t values passed directly — the 4th+ land on the stack (SysV) */
    uint8_t mac[6] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
    snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    if (strcmp(buf, "52:54:00:12:34:56") != 0) return 1;

    /* small ints passed directly past the register args */
    uint16_t u = 0xABCD;
    signed char sc = -2;
    short sh = -300;
    snprintf(buf, sizeof buf, "%d %d %d %d %u %d %d",
             1, 2, 3, 4, u, sc, sh);
    if (strcmp(buf, "1 2 3 4 43981 -2 -300") != 0) return 2;

    /* (float→double promotion is also applied, but libc printf of a variadic
     * float additionally needs the SysV AL register set, which cranelift can't
     * do — a separate known limitation — so it isn't checked here.) */
    return 0;
}
