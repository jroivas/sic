#ifndef __SCAN_H
#define __SCAN_H

#include <stdio.h>

typedef unsigned long long literalnum;

enum tokentype {
    T_PLUS, T_MINUS, T_STAR, T_DIV, T_MOD,
    T_INT_LIT, T_DEC_LIT
};

struct token {
    enum tokentype token;
    char *value_string;
    literalnum value;
    literalnum fraction;
};

struct scanfile {
    FILE *infile;
    int line;
    int putback;
};

int scan(struct scanfile *f, struct token *t);
const char *token_str(struct token *t);
char *token_dump(struct token *t);

#endif
