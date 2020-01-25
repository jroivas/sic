#include "parse.h"
#include <string.h>

struct node *additive_expression(struct scanfile *f, struct token *token);

static const char *nodestr[] = {
    "+", "-", "*", "/", "%",
    "IDENTIFIER",
    "-",
    "INT_LIT", "DEC_LIT",
    "ASSIGN", "GLUE", "TYPE"
};

const char *node_str(struct node *n)
{
    FATAL(n->node >= sizeof(nodestr) / sizeof (char*),
            "Node string table overflow with %d", n->node);
    return nodestr[n->node];
}

enum nodetype oper(enum tokentype t)
{
    switch (t) {
        case T_PLUS:
            return A_ADD;
        case T_MINUS:
            return A_MINUS;
        case T_STAR:
            return A_MUL;
        case T_SLASH:
            return A_DIV;
        case T_MOD:
            return A_MOD;
        default:
            ERR("Unexpected arithmetic: %s", token_val_str(t));
    }
}

enum var_type resolve_var_type(struct node *n)
{
    enum var_type v1 = V_VOID;
    enum var_type v2 = V_VOID;
    int s1 = 0;
    int s2 = 0;

    if (n->left) {
        if (n->left->type == V_VOID)
            v1 = resolve_var_type(n->left);
        else
            v1 = n->left->type;
        s1 = n->left->bits;
    }
    if (n->right) {
        if (n->right->type == V_VOID)
            v2 = resolve_var_type(n->right);
        else
            v2 = n->right->type;
        s2 = n->right->bits;
    }

    if (v1 == V_VOID && v2 != V_VOID)
        v1 = v2;
    if (v1 == V_INT && v2 == V_FLOAT)
        v1 = v2;

    if (s1 < s2)
        s1 = s2;

    n->type = v1;
    n->bits = s1;
    return v1;
}

struct node *make_node(enum nodetype node, struct node *left,
        struct node *right)
{
    struct node *res = calloc(1, sizeof(struct node));
    if (res == NULL)
        ERR("Can't create new node, out of memory?");

    res->node = node;
    res->left = left;
    res->right = right;
    if (left != NULL || right != NULL)
        res->type = resolve_var_type(res);
    else
        res->type = V_VOID;
#if DEBUG
    printf("MAKE: %d, %s\n", node, node_str(res));
#endif

    return res;
}

struct node *make_leaf(enum nodetype node, struct token *t)
{
    struct node *n = make_node(node, NULL, NULL);

    if (t->token == T_INT_LIT) {
#if DEBUG
        printf("  INT: %llu\n", t->value);
#endif
        n->value = t->value;
        n->type = V_INT;
        n->bits = determine_size(t->value);
        /* Minimum 32 bits on literals */
        if (n->bits < 32)
            n->bits = 32;
    } else if (t->token == T_DEC_LIT) {
#if DEBUG
        printf("  DEC: %llu.%llu\n", t->value, t->fraction);
#endif
        n->value = t->value;
        n->fraction = t->fraction;
        n->bits = 8;
        n->type = V_FLOAT;
    } else
        ERR("Invalid leaf: %s", node_str(n));
    return n;
}

struct node *make_type(enum nodetype node, struct token *t, enum var_type type, int bits)
{
    struct node *n = make_node(node, NULL, NULL);
    n->type = type;
    n->bits = bits;
    return n;
}

struct node *primary_expression(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;

    switch (token->token) {
        case T_INT_LIT:
            res = make_leaf(A_INT_LIT, token);
            break;
        case T_DEC_LIT:
            res = make_leaf(A_DEC_LIT, token);
            break;
        case T_IDENTIFIER:
            res = make_node(A_IDENTIFIER, NULL, NULL);
            res->value_string = token->value_string;
            scan(f, token);
            break;
        default:
            ERR("Unexpected token: %s", token_str(token));
    }

    scan(f, token);
    return res;
}

struct node *type_specifier(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    if (token->token != T_IDENTIFIER)
        return res;

    if (strcmp(token->value_string, "void") == 0)
        res = make_type(A_TYPE, token, V_VOID, 0);
    else if (strcmp(token->value_string, "int") == 0)
        res = make_type(A_TYPE, token, V_INT, 32);
    else if (strcmp(token->value_string, "char") == 0)
        res = make_type(A_TYPE, token, V_INT, 8);
    // FIXME More types

    if (res)
        scan(f, token);

    return res;
}

struct node *declaration_specifiers(struct scanfile *f, struct token *token)
{
    struct node *type = type_specifier(f, token);
    //TODO type_qualifier, storage_class_specifier
    if (type == NULL)
        return type;
    printf("type? %p == %d, bits %d\n", (void*)type, type->type, type->bits);

    struct node *res = NULL;
    while (1) {
        res = declaration_specifiers(f, token);
        printf("res? %p\n", (void*)res);
        if (res == NULL)
            break;
        res = make_node(A_GLUE, type, res);
    }
    if (!res)
        res = type;
    printf("fres? %p\n", (void*)res);
    return res;
}

struct node *direct_declarator(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    printf("token? %s\n", token_str(token));
    if (token->token == T_IDENTIFIER) {
        res = make_node(A_IDENTIFIER, NULL, NULL);
        res->value_string = token->value_string;
        scan(f, token);
    }
    // TODO other cases
    return res;
}

struct node *declarator(struct scanfile *f, struct token *token)
{
    // TODO pointer
    struct node *res = direct_declarator(f, token);
    return res;
}

struct node *conditional_expression(struct scanfile *f, struct token *token)
{
    struct node *res = additive_expression(f, token);

    // TODO ternary
    return res;
}

struct node *assignment_expression(struct scanfile *f, struct token *token)
{
    // FIXME unary_expression assignment_operator
    return conditional_expression(f, token);
}

struct node *initializer(struct scanfile *f, struct token *token)
{
    struct node *res = assignment_expression(f, token);
    if (res)
        return res;
    return NULL;
}

struct node *init_declarator(struct scanfile *f, struct token *token)
{
    struct node *res = declarator(f, token);
    printf("DECLr %p\n", (void*)res);
    if (!res)
        return NULL;
    if (token->token == T_EQ) {
        scan(f, token);
        struct node *tmp = initializer(f, token);
        printf("INITs %p\n", (void*)tmp);
        res = make_node(A_ASSIGN, res, tmp);
    }

    return res;
}

struct node *init_declarator_list(struct scanfile *f, struct token *token)
{
    struct node *res = init_declarator(f, token);
    //TODO
    return res;
}

struct node *declaration(struct scanfile *f, struct token *token)
{
    struct node *res = declaration_specifiers(f, token);
    printf("DECPEC %p\n", (void*)res);
    if (!res)
        return NULL;

    struct node *decl = init_declarator_list(f, token);
    printf("DECL2 %p %s\n", (void*)decl, token_str(token));
    if (decl)
        res = make_node(A_GLUE, res, decl);

    semi(f, token);
    return res;
}

struct node *postfix_expression(struct scanfile *f, struct token *token)
{
    // TODO
    return primary_expression(f, token);
}
struct node *cast_expression(struct scanfile *f, struct token *token);

struct node *unary_expression(struct scanfile *f, struct token *token)
{
    struct node *left;
    enum tokentype type;

    type = token->token;
    switch (type) {
            case T_PLUS:
                scan(f, token);
                return cast_expression(f, token);
            case T_MINUS:
                scan(f, token);
                left = cast_expression(f, token);
                return make_node(A_NEGATE, left, NULL);
            default:
                break;
    }

    left = postfix_expression(f, token);
    if (token->token == T_EOF)
        return left;


    return left;
}

struct node *cast_expression(struct scanfile *f, struct token *token)
{
    // TODO
    return unary_expression(f, token);
}

struct node *multiplicative_expression(struct scanfile *f, struct token *token)
{
    struct node *left, *right;
    enum tokentype type;

    left = cast_expression(f, token);
    if (token->token == T_EOF)
        return left;

    type = token->token;
    while (type == T_STAR || type == T_SLASH || type == T_MOD) {
        scan(f, token);

        right = cast_expression(f, token);
        printf("MULr: %p\n", (void *)right);
        left = make_node(oper(type), left, right);
        printf("MULl: %p\n", (void *)left);

        if (token->token == EOF)
            break;
        type = token->token;
    }

    return left;
}

struct node *additive_expression(struct scanfile *f, struct token *token)
{
    struct node *left, *right;
    enum tokentype type;

    left = multiplicative_expression(f, token);
    if (token->token == T_EOF)
        return left;

    type = token->token;
    while (1) {
        if (type == T_SEMI)
            break;
        if (!scan(f, token))
            break;

        struct token *tmp;
        peek(f, &tmp);
        if (tmp->token == T_SEMI || tmp->token == T_EOF)
            break;
        scan(f, token);

        printf("ADD0: p: %s n: %s\n", token_val_str(type), token_str(token));

        right = multiplicative_expression(f, token);
        printf("ADDr: %p n: %s\n", (void *)right, token_str(token));
        /*
        if (token->token != T_PLUS && token->token != T_SLASH)
            break;
            */
        left = make_node(oper(type), left, right);
        printf("ADDl: %p\n", (void *)left);

        if (token->token == T_EOF)
            break;
        type = token->token;
    }
    return left;
}

struct node *expression(struct scanfile *f, struct token *token)
{
    if (token->token == T_EOF)
        return NULL;

    return additive_expression(f, token);
    //assignment_expression(f);
}

struct node *expression_statement(struct scanfile *f, struct token *token)
{
    struct node *res = expression(f, token);
    printf("ex1\n");
    if (res)
        semi(f, token);
    return res;
}

struct node *statement(struct scanfile *f, struct token *token)
{
    return expression_statement(f, token);
}

struct node *statement_list(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    struct node *prev = NULL;
    while (1) {
        struct node *tmp = statement(f, token);
        if (!tmp)
            break;
        tmp = make_node(A_GLUE, tmp, NULL);
        if (res == NULL)
            res = tmp;
        else
            prev->right = tmp;
        prev = tmp;
    }
    return res;
}

struct node *external_declaration(struct scanfile *f, struct token *token)
{
    struct node *res = declaration(f, token);
    if (res)
        return res;
    res = statement_list(f, token);
    if (res)
        return res;
    //TODO function_declaration
    return NULL;
}


struct node *translation_unit(struct scanfile *f, struct token *token)
{
    struct node *res = external_declaration(f, token);
    if (!res)
        return NULL;

    printf("TU\n");
    while (1) {
        struct node *tmp = translation_unit(f, token);
        printf("TU1: %p\n", (void*)tmp);
        if (!tmp)
            break;
        res = make_node(A_GLUE, res, tmp);
    }
    return res;
}

struct node *parse(struct scanfile *f, struct token *token)
{
    //return statement_list(f, token);
    return translation_unit(f, token);
}
