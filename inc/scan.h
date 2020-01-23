#ifndef __SCAN_C
#define __SCAN_C

#include <stdio.h>

struct token {
    int token;
    union {
        char *value_string;
        unsigned long value_int;
        unsigned long long value_ll;
        double value_float;
    };
};

enum {
    T_PLUS, T_MINUS, T_INTLIT
};

struct scanfile {
    FILE *infile;
    int line;
    int putback;
};

#endif
