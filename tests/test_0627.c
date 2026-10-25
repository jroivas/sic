// Full unrolling of short constant-count loops (-O2): each copy sees the
// counter's value; steps, `!=`, downward loops, nested loops, break/continue
// in an inner loop, return from the body and side-effect order are kept, and
// loops that write or shadow their counter run as loops.
static int trace[64], nt;
static int note(int x) { trace[nt++] = x; return x; }

static int find(const int *a, int key)
{
    for (int j = 0; j < 4; j++)
        if (a[j] == key) return j;
    return -1;
}

static inline __attribute__((always_inline)) int big(int x)
{
    int s = 0;
    for (int k = 0; k < 40; k++) s += (x ^ k) * (k + 1);
    return s;
}

int main(void)
{
    int m[3][4];
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 4; j++)
            m[i][j] = 10 * i + j;
    if (m[2][3] != 23 || m[1][0] != 10) return 1;
    int s = 0;
    for (int j = 10; j > 0; j -= 3) s += j;          // 10 7 4 1
    if (s != 22) return 2;
    s = 0;
    for (int j = 0; j != 8; j += 2) s += j;          // 0 2 4 6
    if (s != 12) return 3;
    for (int j = 0; j < 3; j++) note(j * j);
    if (nt != 3 || trace[0] != 0 || trace[2] != 4) return 4;
    int a[4] = { 5, 6, 7, 8 };
    if (find(a, 7) != 2 || find(a, 9) != -1) return 5;
    s = 0;
    for (int j = 0; j < 4; j++) {
        for (int k = 0; k < 100; k++) {
            if (k == j) continue;
            if (k > j + 1) break;
            s += k;
        }
    }
    // j=0: k=1; j=1: k=0,2; j=2: k=0,1,3; j=3: k=0,1,2,4
    if (s != 1 + 2 + 4 + 7) return 6;
    s = 0;
    for (int j = 0; j < 6; j++) { s += j; j++; }      // writes j: a real loop
    if (s != 0 + 2 + 4) return 7;
    s = 0;
    for (int j = 0; j < 3; j++) { int j2 = j * 2; { int j = 100; s += j; } s += j2; }
    if (s != 300 + 6) return 8;
    if (big(3) != big(3) || big(1) == big(2)) return 9;
    return 42;
}
