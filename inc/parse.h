#ifndef __PARSE_H
#define __PARSE_H

#include "sic.h"

enum nodetype {
    A_ADD
};

struct node {
    enum nodetype node;
    int type;

    struct node *left;
    struct node *right;
};

#endif
