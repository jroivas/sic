/* sic `assert(cond)` / `assert(cond, msg)` failure (sic.md §"Macros"): the
   prelude macro passes the condition's source text and the call site. Prepended
   (post-preprocess) only when a SIC unit mentions `assert`; weak-linked. */
extern int dprintf(int fd, const char *fmt, ...);
extern void abort(void);

__attribute__((weak)) void __sic_assert_fail(const char *expr, const char *file, int line, string msg) {
    if (msg.size > 0) {
        dprintf(2, "%s:%d: assertion failed: %s: %.*s\n", file, line, expr, (int)msg.size, msg.ptr);
    } else {
        dprintf(2, "%s:%d: assertion failed: %s\n", file, line, expr);
    }
    abort();
}
