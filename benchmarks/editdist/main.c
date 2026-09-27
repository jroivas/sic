// Levenshtein edit distance (two 16K-symbol strings, two-row DP). Two u8 symbol
// arrays, two int DP rows, prev/cur swap per row. Prints checksum of final prev[LB].

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static int edit_min3(int a, int b, int c) {
    int m = a < b ? a : b;
    return m < c ? m : c;
}

int main(void) {
    const int LA = 16000, LB = 16000;
    uint8_t *A = malloc(LA), *B = malloc(LB);
    uint32_t x = 66661;
    for (int i = 0; i < LA; i++) { x = x * 1664525u + 1013904223u; A[i] = (uint8_t)((x / 65536u) % 4u); }
    for (int i = 0; i < LB; i++) { x = x * 1664525u + 1013904223u; B[i] = (uint8_t)((x / 65536u) % 4u); }
    int *prev = malloc((LB + 1) * sizeof(int));
    int *cur = malloc((LB + 1) * sizeof(int));
    for (int j = 0; j <= LB; j++) prev[j] = j;
    for (int i = 1; i <= LA; i++) {
        cur[0] = i;
        for (int j = 1; j <= LB; j++) {
            int cost = A[i - 1] == B[j - 1] ? 0 : 1;
            cur[j] = edit_min3(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
        }
        int *tmp = prev; prev = cur; cur = tmp;
    }
    printf("checksum %u\n", (uint32_t)prev[LB]);
    free(A); free(B); free(prev); free(cur);
    return 0;
}