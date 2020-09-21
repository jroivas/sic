#ifndef __CG_H
#define __CG_H

#include <stdio.h>
#include "parse.h"

enum type_sign {
    TYPE_UNSIGNED = 0,
    TYPE_SIGNED = 1
};

int codegen(FILE *outfile, struct node *node);

#endif
