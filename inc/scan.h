#ifndef __SCAN_H
#define __SCAN_H

#include <stdio.h>

enum tokentype {
    T_INVALID,
    T_PLUS, T_MINUS, T_STAR, T_SLASH, T_MOD,
    T_EQ,
    T_IDENTIFIER,
    T_INT_LIT, T_DEC_LIT,
    T_SEMI, T_EOF
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
    struct token peek;
};

int scan(struct scanfile *f, struct token *t);
int accept(struct scanfile *f, struct token *t, enum tokentype token);
int expect(struct scanfile *f, struct token *t, enum tokentype token, const char *expect);
void semi(struct scanfile *f, struct token *t);
int peek(struct scanfile *f, struct token **t);

const char *token_val_str(enum tokentype t);
const char *token_str(struct token *t);
char *token_dump(struct token *t);

#endif
