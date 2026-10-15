/* fasta (n = 2500000) — the Computer Language Benchmarks Game.
   Source: https://benchmarksgame-team.pages.debian.net/benchmarksgame/description/fasta.html
   (algorithm as in the single-threaded C programs there; revised BSD licence).
   Adapted: single-threaded; instead of writing ~25 MB of FASTA text, every output
   byte (including the 60-column line breaks, without the '>' headers) is folded
   into an FNV-1a hash, printed as the checksum. Stresses an LCG, cumulative-table
   lookups and byte output. */
#include <stdio.h>
#include <string.h>

#define IM 139968
#define IA 3877
#define IC 29573
#define LINE 60

static const char ALU[] =
    "GGCCGGGCGCGGTGGCTCACGCCTGTAATCCCAGCACTTTGG"
    "GAGGCCGAGGCGGGCGGATCACCTGAGGTCAGGAGTTCGAGA"
    "CCAGCCTGGCCAACATGGTGAAACCCCGTCTCTACTAAAAAT"
    "ACAAAAATTAGCCGGGCGTGGTGGCGCGCGCCTGTAATCCCA"
    "GCTACTCGGGAGGCTGAGGCAGGAGAATCGCTTGAACCCGGG"
    "AGGCGGAGGTTGCAGTGAGCCGAGATCGCGCCACTGCACTCC"
    "AGCCTGGGCGACAGAGCGAGACTCCGTCTCAAAAA";

typedef struct { char c; double p; } Acid;

static Acid iub[] = {
    {'a', 0.27}, {'c', 0.12}, {'g', 0.12}, {'t', 0.27},
    {'B', 0.02}, {'D', 0.02}, {'H', 0.02}, {'K', 0.02}, {'M', 0.02},
    {'N', 0.02}, {'R', 0.02}, {'S', 0.02}, {'V', 0.02}, {'W', 0.02}, {'Y', 0.02},
};
static Acid homosapiens[] = {
    {'a', 0.3029549426680}, {'c', 0.1979883004921},
    {'g', 0.1975473066391}, {'t', 0.3015094502008},
};

static unsigned hash = 2166136261u;
static void put(char c) { hash ^= (unsigned char)c; hash *= 16777619u; }

static unsigned last = 42;
static double gen_random(double max) {
    last = (last * IA + IC) % IM;
    return max * last / IM;
}

static void make_cumulative(Acid *t, int n) {
    double p = 0.0;
    for (int i = 0; i < n; i++) { p += t[i].p; t[i].p = p; }
}

static void repeat_fasta(const char *s, int n) {
    int len = (int)strlen(s), pos = 0;
    for (int done = 0; done < n; ) {
        int line = n - done < LINE ? n - done : LINE;
        for (int i = 0; i < line; i++) {
            put(s[pos]);
            if (++pos == len) pos = 0;
        }
        put('\n');
        done += line;
    }
}

static void random_fasta(const Acid *t, int ntab, int n) {
    for (int done = 0; done < n; ) {
        int line = n - done < LINE ? n - done : LINE;
        for (int i = 0; i < line; i++) {
            double r = gen_random(1.0);
            int k = 0;
            while (k < ntab - 1 && r >= t[k].p) k++;
            put(t[k].c);
        }
        put('\n');
        done += line;
    }
}

int main(void) {
    const int n = 2500000;
    make_cumulative(iub, 15);
    make_cumulative(homosapiens, 4);
    repeat_fasta(ALU, 2 * n);
    random_fasta(iub, 15, 3 * n);
    random_fasta(homosapiens, 4, 5 * n);
    printf("%u\n", hash);
    return 0;
}
