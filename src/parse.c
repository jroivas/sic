#include "parse.h"

static const char *nodestr[] = {
    "+", "-", "*", "/", "%",
    "INT_LIT", "DEC_LIT", "EOF"
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

struct node *make_node(enum nodetype node, struct node *left,
        struct node *right)
{
    struct node *res = calloc(1, sizeof(struct node));
    if (res == NULL)
        ERR("Can't create new node, out of memory?");

    res->node = node;
    res->left = left;
    res->right = right;
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
        printf("  INT: %lld\n", t->value);
#endif
        n->value = t->value;
    } else if (t->token == T_DEC_LIT) {
#if DEBUG
        printf("  DEC: %lld\n", t->value);
#endif
        n->value = t->value;
        n->fraction = t->fraction;
    } else
        ERR("Invalid leaf: %s", node_str(n));
    return n;
}

struct node *primary_expression(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;

    switch (token->token) {
        case T_INT_LIT:
        case T_DEC_LIT:
            res = make_leaf(A_INT_LIT, token);
            break;
        default:
            ERR("Invalid token: %s", token_str(token));
    }

    scan(f, token);
    return res;
}

struct node *multiplicative_expression(struct scanfile *f, struct token *token)
{
    struct node *left, *right;
    enum tokentype type;

    // FIXME shortcut here
    left = primary_expression(f, token);
    if (token->token == T_EOF)
        return left;

    type = token->token;
    while (type == T_STAR || type == T_SLASH || type == T_MOD) {
        scan(f, token);

        right = primary_expression(f, token);
        left = make_node(oper(type), left, right);

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
    //while (type == T_PLUS || type == T_SLASH) {
    while (1) {
        if (!scan(f, token))
            break;

        right = multiplicative_expression(f, token);
        left = make_node(oper(type), left, right);

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
