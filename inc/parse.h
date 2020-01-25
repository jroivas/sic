#ifndef __PARSE_H
#define __PARSE_H

#include "sic.h"
#include "scan.h"

enum nodetype {
    A_ADD, A_MINUS, A_MUL, A_DIV, A_MOD,
    A_NEGATE,
    A_INT_LIT, A_DEC_LIT
};

struct node {
    enum nodetype node;
    enum var_type type;
    int bits;

    char *value_string;
    literalnum value;
    literalnum fraction;

    struct node *left;
    struct node *right;
};

struct node *parse(struct scanfile *f, struct token *token);
extern void node_walk(struct node *node);

#endif
