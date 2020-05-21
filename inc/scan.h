#ifndef __SCAN_H
#define __SCAN_H

#include <stdio.h>
#include "sic.h"

enum tokentype {
    T_INVALID,
    T_PLUS, T_MINUS, T_STAR, T_SLASH, T_MOD,
    T_EQ,
    T_KEYWORD,
    T_IDENTIFIER,
    T_INT_LIT, T_DEC_LIT,
    T_STR_LIT,
    T_ROUND_OPEN, T_ROUND_CLOSE,
    T_CURLY_OPEN, T_CURLY_CLOSE,
    T_COMMA, T_SEMI,
    T_AMP,
    T_EOF
};

enum keyword_type {
    K_NONE,
    K_RETURN,
    K_IF,
    K_ELSE
};

struct token {
    enum tokentype token;
    enum keyword_type keyword;
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
int accept_keyword(struct scanfile *f, struct token *t, enum keyword_type keyword);
void semi(struct scanfile *f, struct token *t);
void save_point(struct scanfile *f, struct token *t);
void remove_save_point(struct scanfile *f, struct token *t);
void load_point(struct scanfile *f, struct token *t);

const char *token_val_str(enum tokentype t);
const char *token_str(struct token *t);
char *token_dump(struct token *t);

static inline int expect_err(struct scanfile *f,
    struct token *t, const char *e, const char *file, int line)
{
    ERR("Expected %s on line %d, got %s instead at %s:%d",
        e, f->line, token_dump(t),
        file, line);
    return 1;
}

#define expect(f, t, token, e)\
    accept(f, t, token) ? 1 : \
        expect_err(f, t, e, __FILE__, __LINE__)

#endif
