#ifndef __CG_H
#define __CG_H

#include <stdio.h>
#include "parse.h"

enum type_sign {
    TYPE_UNSIGNED = 0,
    TYPE_SIGNED = 1
};

struct codegen_config {
    int no_link;
};

int codegen(FILE *outfile, struct node *node, const struct codegen_config *conf);

#endif
