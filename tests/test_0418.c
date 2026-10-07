/* -O2 dead-branch must not unwrap `do { … } while (0)` whose body leaves THAT
 * loop: `break`/`continue` lost their target ("break outside loop/switch", QEMU
 * hw/9pfs/9p.c) or — inside an outer loop — silently broke the OUTER loop
 * (this returned 11 instead of 34). Returns 42. */
static int g(int r) { return r == 2; }
int main(void) {
    int out = 0, r = 0, x = 3;
    for (int i = 0; i < 4; i++) {
        do { if (i == 1) break; out += 10; } while (0);
        out += 1;
    }
    if (out != 34) return 1;
    do { { if (x) { r = 1; break; } r = 2; }; } while (0);
    if (r != 1) return 2;
    int c = 0;
    do { c++; if (c < 5) continue; c += 100; } while (0);
    if (c != 1) return 3;
    int s = 0;
    do { switch (x) { case 3: s = 7; break; default: s = 9; } s += 1; } while (0);
    if (s != 8) return 4;
    int w = 0;
    do { while (1) { w++; break; } w += 5; } while (0);
    if (w != 6) return 5;
    int q = 0;
    do { for (q = 0; q < x; q++) { if (g(q)) break; } if (q) { break; } q = -1; } while (0);
    if (q != 2) return 6;
    return 42;
}
