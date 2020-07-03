#ifndef __SIC_H
#define __SIC_H

#include <stdio.h>
#include <stdlib.h>
#include <execinfo.h>

typedef unsigned long long literalnum;
typedef unsigned long hashtype;

#define MAX_STR_LEN 512
#define STACK_TRACE_SIZE 64
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
    exit(EXIT_FAILURE); \
}

#define ERR(...) ERR_FULL(0, __VA_ARGS__)
#define ERR_TRACE(...) ERR_FULL(1, __VA_ARGS__)

void stack_trace(void);
#include "parse.h"
#define FATALN(check, _node, ...) if (check) { \
    if (_node) \
        fprintf(stderr, "FATAL Compiler error in %s at %d, %s:%d,%d: ", __FILE__, __LINE__, \
        ((struct node*)_node)->filename, ((struct node*)_node)->line, ((struct node*)_node)->linepos);\
    else fprintf(stderr, "FATAL Compiler error in %s at %d: ", __FILE__, __LINE__);\
    fprintf(stderr,  __VA_ARGS__);\
    fprintf(stderr, "\n");\
    stack_trace();\
    exit(EXIT_FAILURE); \
}

#define FATAL(check, ...) FATALN(check, NULL, __VA_ARGS__)

#define PTR_TO(x, v) do {\
    if (x != NULL) {\
    if (v > 0xf) ERR("Invalid pointer");\
    FATAL(((unsigned long)x & 0xf) != 0, "Invalid align");\
    x = (void*)((unsigned long)x | v);\
    }\
} while(0);
#define PTR_VAL(x) (void *)((unsigned long)x & ~0xf)
#define PTR_GET(x) ((unsigned long)x & 0xf)

const char *type_str(enum var_type t);
int determine_size(literalnum value);
hashtype hash(const char *str);
char *get_stars(int cnt);
char *int_to_str(literalnum val);
char *double_to_str(literalnum val);

#endif
