#ifndef __PARSE_H
#define __PARSE_H

#include "sic.h"
#include "scan.h"

enum nodetype {
    A_ADD, A_MINUS, A_MUL, A_DIV, A_MOD,
    A_IDENTIFIER,
    A_NEGATE,
    A_INT_LIT, A_DEC_LIT,
    A_ASSIGN, A_GLUE, A_TYPE, A_TYPESPEC,
    A_DECLARATION,
    A_PARAMS,
    A_LIST
};

struct node {
    enum nodetype node;
    enum var_type type;
    int bits;
    int sign;

    const char *value_string;
    literalnum value;
    literalnum fraction;

    struct node *left;
    struct node *right;
};

struct node *parse(struct scanfile *f);
extern void node_walk(struct node *node);
const char *node_str(struct node *n);

#endif
