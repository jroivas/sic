#ifndef __SIC_H
#define __SIC_H

#include <stdio.h>
#include <stdlib.h>

typedef unsigned long long literalnum;
typedef unsigned long hashtype;

static const int MAX_STR_LEN = 512;
#define STACK_TRACE_SIZE 25
#define DEBUG 0
#define REF_CTX(X) (-(X))

enum var_type {
    V_VOID, V_NULL, V_INT, V_FLOAT, V_FIXED, V_STR
};

#define WARN(...) { \
    fprintf(stderr, "WARNING: ");\
    fprintf(stderr, __VA_ARGS__);\
    fprintf(stderr, "\n");\
}

#define ERR_FULL(trace, ...) { \
    fprintf(stderr, "ERROR in %s at %d: ", __FILE__, __LINE__);\
    fprintf(stderr, __VA_ARGS__);\
    fprintf(stderr, "\n");\
    if (trace) stack_trace();\
    exit(1); \
}

#define ERR(...) ERR_FULL(0, __VA_ARGS__)
#define ERR_TRACE(...) ERR_FULL(1, __VA_ARGS__)

#define FATAL(check, ...) if (check) { \
    fprintf(stderr, "FATAL Compiler error in %s at %d: ", __FILE__, __LINE__);\
    fprintf(stderr,  __VA_ARGS__);\
    fprintf(stderr, "\n");\
    stack_trace();\
    exit(1); \
}

const char *type_str(enum var_type t);
int determine_size(literalnum value);
hashtype hash(const char *str);
char *get_stars(int cnt);
void stack_trace(void);
char *int_to_str(literalnum val);

#endif
