/* Comments are removed before directives are split into lines (C11 5.1.1.2):
 * a block comment spanning lines inside a #define does not end it (glib's
 * G_C_STD_CHECK_VERSION — the rest of the body leaked out as code), and a
 * `//` comment ending in a backslash continues onto the next line. 42. */
#define CHK(v) ( \
  ((v) == 11) || \
  /* a comment that spans \
   * two lines (see https://x.y/z) */ \
  ((v) == 23) || \
  0)
#define TWO 2 /* trailing
 multi-line */ + 1
// this line comment continues \
int main(void) { return 1; }
#if 1 /* multi
   line in #if */ && 1
#define OK 1
#endif
int main(void) {
    if (!CHK(23) || CHK(5)) return 1;
    if (TWO != 3) return 2;
    if (OK != 1) return 3;
    return 42;
}
