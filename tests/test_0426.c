/* An inline-asm template sic does not recognise compiles (with a warning) and
 * traps only if executed — never silently does nothing. Here it is not
 * executed (like <sys/io.h>'s unused inb/outb inlines). Returns 42. */
static inline unsigned char inb(unsigned short port) {
    unsigned char v;
    __asm__ __volatile__ ("inb %w1,%0" : "=a" (v) : "Nd" (port));
    return v;
}
int main(int argc, char **argv) {
    (void)argv;
    if (argc > 100) return inb(0x80);
    return 42;
}
