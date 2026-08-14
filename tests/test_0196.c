/* __builtin_return_address(0) must return the real return address, not NULL.
 *
 * sic used to lower it to a null constant ("degrades gracefully for backtraces").
 * But QEMU's GETPC() == __builtin_extract_return_addr(__builtin_return_address(0))
 * is load-bearing: a faulting TCG helper passes it to cpu_restore_state() to find
 * the guest PC to restart at. With GETPC()==0 the wrong guest instruction was
 * restarted, derailing the emulated CPU (FreeDOS/JemmEx wild-jumped to a #UD). */

static void *g_ra;
static int   g_x;

static void __attribute__((noinline)) capture(void)
{
    g_ra = __builtin_return_address(0);
    g_x++;                       /* keep the call non-trivial / non-tail */
}

int main(void)
{
    capture();

    /* Inside capture(), __builtin_return_address(0) is the address in main just
       after the call — must be non-null. */
    if (g_ra == (void *)0) return 1;

    /* extract_return_addr is the identity on x86; GETPC() stays non-null. */
    void *pc = __builtin_extract_return_addr(g_ra);
    if (pc == (void *)0) return 2;

    if (g_x != 1) return 3;
    return 0;
}
