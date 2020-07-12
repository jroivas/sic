#ifndef __PARSE_H
#define __PARSE_H

#include "sic.h"
#include "scan.h"

enum nodetype {
    A_ADD, A_MINUS, A_MUL, A_DIV, A_MOD,
    A_LEFT, A_RIGHT, A_AND, A_OR, A_XOR,
    A_LOG_AND, A_LOG_OR,
    A_IDENTIFIER,
    A_NEGATE,
    A_NOT,
    A_INT_LIT, A_DEC_LIT,
    A_STR_LIT,
    A_ASSIGN,
    A_ADD_ASSIGN,
    A_SUB_ASSIGN,
    A_MUL_ASSIGN,
    A_DIV_ASSIGN,
    A_MOD_ASSIGN,
    A_LEFT_ASSIGN,
    A_RIGHT_ASSIGN,
    A_AND_ASSIGN,
    A_OR_ASSIGN,
    A_XOR_ASSIGN,
    A_GLUE,
    A_TYPE, A_TYPESPEC, A_TYPE_QUAL,
    A_DECLARATION,
    A_PARAMS,
    A_FUNCTION,
    A_RETURN,
    A_POINTER,
    A_ADDR,
    A_DEREFERENCE,
    A_IF,
    A_TERNARY,
    A_EQ_OP,
    A_NE_OP,
    A_LT,
    A_GT,
    A_LT_EQ,
    A_GT_EQ,
    A_NULL,
    A_FUNC_CALL,
    A_POSTINC,
    A_PREINC,
    A_POSTDEC,
    A_PREDEC,
    A_TILDE,
    A_CAST,
    A_WHILE,
    A_DO,
    A_FOR,
    A_INDEX,
    A_SIZEOF,
    A_STRUCT,
    A_UNION,
    A_LIST
};

struct node {
    enum nodetype node;
    enum var_type type;
    int bits;
    int sign;
    int reg;
    int is_const;
    int ptr;
    int addr;
    int strnum;

    const char *value_string;
    literalnum value;
    literalnum fraction;
    struct token *token;

    const char *filename;
    int line;
    int linepos;

    struct node *left;
    struct node *mid;
    struct node *right;
};


struct node *parse(struct scanfile *f);
extern void node_walk(struct node *node);
extern void node_free(struct node *node);
const char *node_type_str(enum nodetype t);
const char *node_str(struct node *n);

enum comma_type {
    COMMA_NONE,
    COMMA_OPT,
    COMMA_MANDATORY
};

typedef struct node *(*list_iter_handler)(struct scanfile *f, struct token *token);
struct node *iter_list(struct scanfile *f, struct token *token, list_iter_handler handler, enum comma_type comma, int force_list);

#endif
