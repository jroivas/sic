#ifndef __SIC_H
#define __SIC_H

#include <stdio.h>
#include <stdlib.h>

typedef unsigned long long literalnum;
#define DEBUG 0

#define ERR(...) { \
    fprintf(stderr, "ERROR: ");\
    fprintf(stderr, __VA_ARGS__);\
    fprintf(stderr, "\n");\
    exit(1); \
}

#define FATAL(check, ...) if (check) { \
    fprintf(stderr, "FATAL Compiler error: ");\
    fprintf(stderr,  __VA_ARGS__);\
    fprintf(stderr, "\n");\
    exit(1); \
}

#endif
