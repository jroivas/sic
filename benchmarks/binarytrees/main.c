/* binary-trees (max depth 16) — the Computer Language Benchmarks Game.
   Source: https://benchmarksgame-team.pages.debian.net/benchmarksgame/description/binarytrees.html
   (algorithm as in the single-threaded C programs there; revised BSD licence).
   Adapted: single-threaded, plain malloc/free (no memory pool), fixed depth; prints
   the sum of every tree check instead of the per-depth report. Stresses allocation
   and recursion. */
#include <stdio.h>
#include <stdlib.h>

typedef struct Node { struct Node *left, *right; } Node;

static Node *bottom_up(int depth) {
    Node *n = malloc(sizeof(Node));
    if (depth > 0) { n->left = bottom_up(depth - 1); n->right = bottom_up(depth - 1); }
    else { n->left = n->right = NULL; }
    return n;
}

static long check(const Node *n) { return n->left ? 1 + check(n->left) + check(n->right) : 1; }

static void release(Node *n) {
    if (n->left) { release(n->left); release(n->right); }
    free(n);
}

int main(void) {
    const int min_depth = 4, max_depth = 16;
    long total = 0;
    Node *stretch = bottom_up(max_depth + 1);
    total += check(stretch);
    release(stretch);
    Node *long_lived = bottom_up(max_depth);
    for (int d = min_depth; d <= max_depth; d += 2) {
        int iterations = 1 << (max_depth - d + min_depth);
        long c = 0;
        for (int i = 0; i < iterations; i++) {
            Node *t = bottom_up(d);
            c += check(t);
            release(t);
        }
        total += c;
    }
    total += check(long_lived);
    release(long_lived);
    printf("%ld\n", total);
    return 0;
}
