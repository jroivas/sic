#ifndef __SCAN_H
#define __SCAN_H

#include <stdio.h>
#include "sic.h"

enum tokentype {
    T_INVALID,
    T_PLUS, T_MINUS, T_STAR, T_SLASH, T_MOD,
    T_LEFT, T_RIGHT, T_OR, T_XOR,
    T_PLUSPLUS, T_MINUSMINUS,
    T_LOG_AND, T_LOG_OR,
    T_LT, T_GT,
    T_EQ,
    T_EQ_EQ,
    T_EXCLAM,
    T_EQ_NE,
    T_KEYWORD,
    T_IDENTIFIER,
    T_INT_LIT, T_DEC_LIT,
    T_STR_LIT,
    T_ROUND_OPEN, T_ROUND_CLOSE,
    T_CURLY_OPEN, T_CURLY_CLOSE,
    T_SQUARE_OPEN, T_SQUARE_CLOSE,
    T_COMMA, T_SEMI,
    T_AMP,
    T_NULL,
    T_TILDE,
    T_QUESTION,
    T_COLON,
    T_DOT,
    T_PTR_OP,
    T_EOF
};

enum keyword_type {
    K_NONE,
    K_RETURN,
    K_IF,
    K_ELSE,
    K_WHILE,
    K_DO,
    K_FOR,
    K_STRUCT,
    K_UNION,
    K_ENUM,
    K_EXTERN,
    K_SIZEOF
};

struct token {
    enum tokentype token;
    enum keyword_type keyword;
    char *value_string;
    literalnum value;
    literalnum fraction;

    const char *filename;
    int line;
    int linepos;
};

// Max 32 save points, adjust when compiler comes more compilicated
#define SCANFILE_SAVE_MAX 64
struct scanfile {
    FILE *infile;
    const char *filename;
    int line;
    int linepos;
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
void save_point(struct scanfile *f, struct token *t);
void remove_save_point(struct scanfile *f, struct token *t);
void load_point(struct scanfile *f, struct token *t);

const char *token_val_str(enum tokentype t);
const char *token_str(struct token *t);
char *token_dump(struct token *t);

static inline int expect_err(struct scanfile *f,
    struct token *t, const char *e, const char *file, int line)
{
    ERR("Expected %s on %s:%d,%d, got %s instead at %s:%d",
        e, t->filename, t->line, t->linepos, token_dump(t), file, line);
}

#define expect(f, t, token, e)\
    accept(f, t, token) ? 1 : \
        expect_err(f, t, e, __FILE__, __LINE__)

#define semi(f, t) expect(f, t, T_SEMI, ";")
#endif
