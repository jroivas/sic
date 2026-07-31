/* `__attribute__((cleanup(fn)))`: call `fn(&var)` when the variable leaves
 * scope — on normal fall-through, `return`, `break`, and `continue`, in reverse
 * order of declaration. sic ignored the attribute entirely, so QEMU's
 * QEMU_LOCK_GUARD / WITH_QEMU_LOCK_GUARD (glib g_autoptr) never unlocked their
 * mutex → the main thread self-deadlocked on aio_context_list_lock at boot. */

static int log[32];
static int n;

static void rec(int *p) { log[n++] = *p; }   /* record cleanup order */

static void fallthrough(void)
{
    int a __attribute__((cleanup(rec))) = 1;
    int b __attribute__((cleanup(rec))) = 2;   /* b cleaned before a */
}

static int with_return(int x)
{
    int a __attribute__((cleanup(rec))) = 10;
    {
        int b __attribute__((cleanup(rec))) = 20;
        if (x) return 0;                        /* cleans b then a */
    }
    int c __attribute__((cleanup(rec))) = 30;   /* reached only when !x */
    return 1;
}

static void with_loop(void)
{
    for (int i = 0; i < 3; i++) {
        int g __attribute__((cleanup(rec))) = 100 + i;
        if (i == 0) continue;                   /* cleans 100 */
        if (i == 1) break;                      /* cleans 101 */
    }
}

int main(void)
{
    n = 0; fallthrough();
    if (n != 2 || log[0] != 2 || log[1] != 1) return 1;      /* reverse order */

    n = 0; with_return(1);
    if (n != 2 || log[0] != 20 || log[1] != 10) return 2;     /* b then a */

    n = 0; with_return(0);
    if (n != 3 || log[0] != 20 || log[1] != 30 || log[2] != 10) return 3;

    n = 0; with_loop();
    if (n != 2 || log[0] != 100 || log[1] != 101) return 4;   /* continue then break */

    return 0;
}
