/* `__attribute__((weak))` on a file-scope variable: it must parse, emit a weak
 * symbol, and link+run. QEMU's libqtest-single.h declares
 *   QTestState *global_qtest __attribute__((common, weak));
 * in a header included by every qtest translation unit, so without weak linkage
 * the duplicate strong definitions collide with "multiple definition of ...". */
int weak_counter __attribute__((weak)) = 41;

int weak_ptr_flag __attribute__((common, weak));

static int bump(void) { return weak_counter + 1; }

int main(void)
{
    if (bump() != 42) return 1;
    if (weak_ptr_flag != 0) return 2;
    return 0;
}
