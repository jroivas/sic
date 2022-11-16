#ifndef __SCAN_H
#define __SCAN_H

#include <stdio.h>
#include "sic.h"
#include "buffer.h"

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
    T_ELLIPSIS,
    T_EOF
};

enum keyword_type {
    K_NONE,
    K_ASM,
    //K_AUTO,
    K_ATTRIBUTE,
    K_BREAK,
    //K_CASE,
    K_CONTINUE,
    //K_CONST,
    K_DO,
    //K_DEFAULT,
    K_ELSE,
    K_ENUM,
    K_EXTENSION,
    K_EXTERN,
    K_FOR,
    K_GOTO,
    K_IF,
    K_INLINE,
    //K_REGISTER,
    K_RETURN,
    K_SIZEOF,
    K_STATIC,
    K_STRUCT,
    //K_SWITCH,
    K_TYPEDEF,
    K_UNION,
    //K_VOLATILE,
    K_WHILE,
};

#define SCANFILE_LINEBUF 1024
struct token {
    enum tokentype token;
    enum keyword_type keyword;
    char *value_string;
    literalnum value;
    double fraction;

    const char *filename;
    size_t pos;
    int line;
    int linepos;
    char c;
    char linebuf[SCANFILE_LINEBUF + 1];
};

// Max 256 save points, adjust when compiler comes more compilicated
#define SCANFILE_SAVE_MAX 256
struct scanfile {
    FILE *infile;
    struct buffer *buf;
    const char *filename;

    size_t pos;

    struct token curr;
    struct token next;

    int step;

    int pipe;
    int line;
    int linepos;
    int putback;
    int savecnt;
    long save_point[SCANFILE_SAVE_MAX];
    struct token save_token[SCANFILE_SAVE_MAX];

    char linebuf[SCANFILE_LINEBUF + 1];

    // Parser defined data
    void *parsedata;
};

void scanfile_open(struct scanfile *f, const char *name);
void scanfile_pipe(struct scanfile *f, FILE *pipe, const char *name);
void scanfile_close(struct scanfile *f);

int scan(struct scanfile *f, struct token *t);
int peek(struct scanfile *f, struct token *t);
int accept(struct scanfile *f, struct token *t, enum tokentype token);
int accept_keyword(struct scanfile *f, struct token *t, enum keyword_type keyword);
int is_next(struct scanfile *f, struct token *t, enum tokentype token);
void save_point(struct scanfile *f, struct token *t);
void remove_save_point(struct scanfile *f, struct token *t);
void __load_point(struct scanfile *f, struct token *t, const char *file, int line);

#define load_point(f, t) __load_point(f, t, __FILE__, __LINE__)

const char *token_val_str(enum tokentype t);
const char *token_str(const struct token *t);
char *token_dump(struct token *t);

static inline int expect_err(struct scanfile *f,
    struct token *t, const char *e, const char *file, int line)
{
    ERR("Expected %s on %s:%d,%d, got %s instead at %s:%d\nLine: %s",
        e, t->filename, t->line, t->linepos, token_dump(t), file, line, f->linebuf);
}

#define expect(f, t, token, e)\
    accept(f, t, token) ? 1 : \
        expect_err(f, t, e, __FILE__, __LINE__)

#define semi(f, t) expect(f, t, T_SEMI, ";")
#endif
