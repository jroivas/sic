#ifndef __SCAN_H
#define __SCAN_H

#include <stdio.h>

enum tokentype {
    T_INVALID,
    T_PLUS, T_MINUS, T_STAR, T_SLASH, T_MOD,
    T_EQ,
    T_IDENTIFIER,
    T_INT_LIT, T_DEC_LIT,
    T_ROUND_OPEN, T_ROUND_CLOSE,
    T_CURLY_OPEN, T_CURLY_CLOSE,
    T_COMMA, T_SEMI, T_EOF
};

struct token {
    enum tokentype token;
    char *value_string;
    literalnum value;
    literalnum fraction;
};

// Max 10 save points
#define SCANFILE_SAVE_MAX 10
struct scanfile {
    FILE *infile;
    int line;
    int putback;
    int savecnt;
    long save_point[SCANFILE_SAVE_MAX];
    struct token save_token[SCANFILE_SAVE_MAX];
};

void open_input_file(struct scanfile *f, const char *name);
void close_input_file(struct scanfile *f);
int scan(struct scanfile *f, struct token *t);
int accept(struct scanfile *f, struct token *t, enum tokentype token);
int expect(struct scanfile *f, struct token *t, enum tokentype token, const char *expect);
void semi(struct scanfile *f, struct token *t);
void save_point(struct scanfile *f, struct token *t);
void load_point(struct scanfile *f, struct token *t);

const char *token_val_str(enum tokentype t);
const char *token_str(struct token *t);
char *token_dump(struct token *t);

#endif
