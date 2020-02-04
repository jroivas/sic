#ifndef __TEST_H
#define __TEST_H

#include <stdio.h>

#define ASSERT(X) if (!X) {\
    fprintf(stderr, "FAILED on line %d: %s\n", __LINE__, #X);\
    return 1;}
#define TEST(X) if (X()) return 1;

#endif
