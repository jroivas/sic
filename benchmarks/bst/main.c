/* Binary search tree benchmark — 1M inserts then 1M lookups.
   Uses malloc'd bst_node struct with iterative insertion. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct bst_node {
    uint32_t key;
    struct bst_node *left;
    struct bst_node *right;
} bst_node;

int main(void) {
    const size_t M = 1000000;
    const size_t Q = 1000000;
    bst_node *root = NULL;
    uint32_t x = 22222;
    for (size_t n = 0; n < M; n++) {
        x = x * 1664525u + 1013904223u;
        uint32_t key = x & 0x7FFFFFFFu;
        bst_node *nn = malloc(sizeof(bst_node));
        *nn = (bst_node){key, NULL, NULL};
        if (root == NULL) { root = nn; continue; }
        bst_node *cur = root;
        for (;;) {
            if (key < cur->key) {
                if (cur->left == NULL) { cur->left = nn; break; }
                cur = cur->left;
            } else {
                if (cur->right == NULL) { cur->right = nn; break; }
                cur = cur->right;
            }
        }
    }
    uint32_t y = 99991;
    uint32_t cs = 0;
    for (size_t q = 0; q < Q; q++) {
        y = y * 1664525u + 1013904223u;
        uint32_t key = y & 0x7FFFFFFFu;
        uint32_t steps = 0;
        bst_node *cur = root;
        while (cur != NULL) {
            steps += 1;
            if (key == cur->key) break;
            cur = key < cur->key ? cur->left : cur->right;
        }
        cs = cs * 1000003u + steps;
    }
    printf("checksum %u\n", cs);
    return 0;
}