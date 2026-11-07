// Variable-length arrays and alloca: storage of the run-time size, its
// `sizeof`, released at the end of each scope (a VLA in a loop does not pile up),
// on early exits too.
#include <string.h>
#include <alloca.h>

static long sum(int n)
{
    long a[n];
    for (int i = 0; i < n; i++) a[i] = i;
    long s = 0;
    for (int i = 0; i < n; i++) s += a[i];
    return s + (long)sizeof a;
}

static int early(int n)
{
    for (int k = 0; k < 3; k++) {
        char b[n];
        memset(b, k, n);
        if (k == 1) continue;
        if (b[n - 1] == 2) return b[0] + n;
    }
    return -1;
}

static int rec(int d) { int v[d + 1]; v[d] = d; return d ? v[d] + rec(d - 1) : 0; }

static int nested(int n)
{
    int t = 0;
    for (int i = 1; i <= n; i++) {
        int a[i];
        for (int j = 0; j < i; j++) a[j] = j;
        { int b[i * 2]; b[i] = a[i - 1]; t += b[i]; }
    }
    return t;
}

static int sum_alloca(int n)
{
    char *p = alloca(n);
    memset(p, 1, n);
    int s = 0;
    for (int i = 0; i < n; i++) s += p[i];
    return s;
}

int main(void)
{
    long t = 0;
    for (int i = 0; i < 300000; i++) t += sum(i % 300 + 1);
    if (t != 4861150000L) return 1;
    if (sum(10) != 125 || sum(100000) != 5000750000L) return 2;
    if (early(5) != 7 || early(4000) != 4002) return 3;
    if (rec(100) != 5050 || nested(50) != 1225) return 4;
    if (sum_alloca(10) != 10 || sum_alloca(5000) != 5000) return 5;
    int z = 7;
    int zz[z];
    if (sizeof zz != 28) return 6;
    return 0;
}
