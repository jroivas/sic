#ifndef __SIC_H
#define __SIC_H

#include <stdio.h>
#include <stdlib.h>
#include <execinfo.h>

typedef unsigned long long literalnum;
typedef unsigned long hashtype;

#define MAX_STR_LEN 512
#define TEXT_BUFFER_SIZE 4096
#define STACK_TRACE_SIZE 64
#define DEBUG 0
#define REF_CTX(X) (-(X))

enum var_type {
    V_VOID, V_NULL, V_INT, V_FLOAT, V_FIXED, V_STR, V_STRUCT, V_UNION, V_ENUM, V_CUSTOM, V_FUNCPTR, V_BUILTIN
};

#define WARN(...) { \
    fprintf(stderr, "WARNING: ");\
    fprintf(stderr, __VA_ARGS__);\
    fprintf(stderr, "\n");\
}

void stack_trace(void);
#define ERR_FULL(trace, fail, ...) { \
    fprintf(stderr, "ERROR in %s at %d: ", __FILE__, __LINE__);\
    fprintf(stderr, __VA_ARGS__);\
    fprintf(stderr, "\n");\
    if (trace) stack_trace();\
    if (fail) exit(EXIT_FAILURE); \
}

#define ERR_NOFAIL(...) ERR_FULL(0, 0, __VA_ARGS__)
#define ERR(...) ERR_FULL(0, 1, __VA_ARGS__)
#define ERR_TRACE(...) ERR_FULL(1, 1, __VA_ARGS__)

const char *type_str(enum var_type t);
int determine_size(literalnum value);
hashtype hash(const char *str);
char *get_stars(int cnt);
char *int_to_str(literalnum val);
char *double_to_str(literalnum val, literalnum frac);
int solve_escape(const char *v);
int solve_escape_str(char *ptr, int v);
char *convert_escape(const char *src, int *len);
FILE *preprocess(const char *fname, char **incs, int inc_cnt);
char *strcopy(const char *src);

#endif
