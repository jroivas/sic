#ifndef __CG_H
#define __CG_H

#include <stdio.h>
#include "parse.h"

int codegen(FILE *outfile, struct node *node);

#endif
