#ifndef __SIC_H
#define __SIC_H

#include <stdio.h>
#include <stdlib.h>

typedef unsigned long long literalnum;
typedef unsigned long hashtype;

static const int MAX_STR_LEN = 512;
#define DEBUG 0
#define REF_CTX(X) (-(X))

enum var_type {
    V_VOID, V_INT, V_FLOAT, V_FIXED
};


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

const char *type_str(enum var_type t);
int determine_size(literalnum value);
hashtype hash(const char *str);

#endif
