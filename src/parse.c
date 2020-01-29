#include "parse.h"
#include <string.h>

struct node *additive_expression(struct scanfile *f, struct token *token);

static const char *nodestr[] = {
    "+", "-", "*", "/", "%",
    "IDENTIFIER",
    "-",
    "INT_LIT", "DEC_LIT",
    "ASSIGN", "GLUE", "TYPE", "TYPESPEC",
    "DECLARATION",
    "LIST"
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
    int b1 = 0;
    int b2 = 0;
    int s1 = 0;
    int s2 = 0;

    if (n->left) {
        if (n->left->type == V_VOID)
            v1 = resolve_var_type(n->left);
        else
            v1 = n->left->type;
        b1 = n->left->bits;
        s1 = n->left->sign;
    }
    if (n->right) {
        if (n->right->type == V_VOID)
            v2 = resolve_var_type(n->right);
        else
            v2 = n->right->type;
        b2 = n->right->bits;
        s2 = n->right->sign;
    }

    if (v1 == V_VOID && v2 != V_VOID)
        v1 = v2;
    if (v1 == V_INT && v2 == V_FLOAT)
        v1 = v2;

    if (b1 < b2)
        b1 = b2;
    if (s1 < s2)
        s1 = s2;

    n->type = v1;
    n->bits = b1;
    n->sign = s1;
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
        // Width be determined later on
        n->bits = 0;
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

struct node *make_type(enum nodetype node, struct token *t, enum var_type type, int bits, int sign, const char *name)
{
    struct node *n = make_node(node, NULL, NULL);
    n->type = type;
    n->bits = bits;
    n->sign = sign;
    n->value_string = name;
    return n;
}

struct node *make_type_spec(struct token *t, enum var_type type, int bits, int sign, const char *name)
{
    struct node *n = make_node(A_TYPESPEC, NULL, NULL);
    n->type = type;
    n->bits = bits;
    n->sign = sign;
    n->value_string = name;
    return n;
}

struct node *type_resolve(struct node *node, int d)
{
    struct node *res = make_node(A_TYPE, NULL, NULL);
    enum var_type type = node->type;
    int bits = node->bits;
    int sign = node->sign;

    if (type == V_INT && bits == 0) {
        // Default for 32 bits
        bits = 32;
    }
    res->bits = bits;
    // Typesign marks unsigned, and default is signed
    // so reverse it
    res->sign = !sign;
    res->type = type;
    return res;
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

#if 0
    if (strcmp(token->value_string, "void") == 0)
        res = make_type(A_TYPE, token, V_VOID, 0, 0, token->value_string);
    else if (strcmp(token->value_string, "char") == 0)
        res = make_type(A_TYPE, token, V_INT, 8, 1, token->value_string);
    else if (strcmp(token->value_string, "int") == 0)
        res = make_type(A_TYPE, token, V_INT, 32, 1, token->value_string);
    else if (strcmp(token->value_string, "unsigned") == 0)
        res = make_type(A_TYPE, token, V_INT, 32, 0, token->value_string);
    else if (strcmp(token->value_string, "short") == 0)
        res = make_type(A_TYPE, token, V_INT, 16, 1, token->value_string);
    else if (strcmp(token->value_string, "long") == 0)
        res = make_type(A_TYPE, token, V_INT, 64, 1, token->value_string);
#else
    if (strcmp(token->value_string, "void") == 0)
        res = make_type_spec(token, V_VOID, 0, 0, token->value_string);
    else if (strcmp(token->value_string, "char") == 0)
        res = make_type_spec(token, V_INT, 8, 0, token->value_string);
    else if (strcmp(token->value_string, "int") == 0)
        res = make_type_spec(token, V_INT, 0, 0, token->value_string);
    else if (strcmp(token->value_string, "unsigned") == 0)
        res = make_type_spec( token, V_INT, 0, 1, token->value_string);
    else if (strcmp(token->value_string, "signed") == 0)
        res = make_type_spec( token, V_INT, 0, 0, token->value_string);
    else if (strcmp(token->value_string, "short") == 0)
        res = make_type_spec(token, V_INT, 16, 0, token->value_string);
    else if (strcmp(token->value_string, "long") == 0)
        res = make_type_spec(token, V_INT, 64, 0, token->value_string);
#endif
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

    struct node *res = NULL;
    while (1) {
        struct node *tmp =declaration_specifiers(f, token);
        if (tmp == NULL)
            break;
        res = make_node(A_GLUE, type, tmp);
    }
    if (!res)
        res = type;
    return res;
}

struct node *direct_declarator(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
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
    if (!res)
        return NULL;
    if (token->token == T_EQ) {
        scan(f, token);
        struct node *tmp = initializer(f, token);
        res = make_node(A_ASSIGN, res, tmp);
    }

    return res;
}

struct node *init_declarator_list(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    struct node *prev = NULL;
    while (1) {
        struct node *tmp = init_declarator(f, token);
        if (!tmp)
            break;
        tmp = make_node(A_LIST, tmp, NULL);
        if (res == NULL)
            res = tmp;
        else {
            FATAL(prev->right, "Compiler error!")
            prev->right = tmp;
        }
        prev = tmp;
        if (token->token != T_COMMA)
            break;
        scan(f, token);
    }
    return res;
}

struct node *declaration(struct scanfile *f, struct token *token)
{
    struct node *res = declaration_specifiers(f, token);
    if (!res)
        return NULL;
    res = type_resolve(res, 0);

    struct node *decl = init_declarator_list(f, token);
    if (decl)
        res = make_node(A_DECLARATION, res, decl);
#if 0
    else {
        match(f, token, T_IDENTIFIER, "identifier");

        struct node *tmp = make_node(A_IDENTIFIER, NULL, NULL);
        tmp->value_string = token->value_string;
        res = make_node(A_DECLARATION, res, tmp);

        scan(f, token);
    }
#endif

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

    if (accept(f, token, T_PLUS)) {
        return cast_expression(f, token);
    } else if (accept(f, token, T_MINUS)) {
        left = cast_expression(f, token);
        return make_node(A_NEGATE, left, NULL);
    }

    left = postfix_expression(f, token);
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
        if (!scan(f, token))
            ERR("Couldn't scan next in multiplicative_expression");
        right = cast_expression(f, token);
        left = make_node(oper(type), left, right);
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
    while (type == T_PLUS || type == T_MINUS) {
        if (!scan(f, token))
            ERR("Couldn't scan next in additive_expression");
        right = multiplicative_expression(f, token);
        left = make_node(oper(type), left, right);
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
        tmp = make_node(A_LIST, tmp, NULL);
        if (res == NULL)
            res = tmp;
        else {
            FATAL(prev->right, "Compiler error!")
            prev->right = tmp;
        }
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
    struct node *decl = external_declaration(f, token);
    if (!decl)
        return NULL;
    struct node *res = decl;

    while (1) {
        struct node *tmp = translation_unit(f, token);
        if (!tmp)
            break;
        /*
         * GLUE and LIST work alike, however LIST is always a list,
         * GLUE can be anything
         */
        res = make_node(A_GLUE, res, tmp);
    }
    return res;
}

struct node *parse(struct scanfile *f, struct token *token)
{
    //return statement_list(f, token);
    return translation_unit(f, token);
}
