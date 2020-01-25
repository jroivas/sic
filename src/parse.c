#include "parse.h"

static const char *nodestr[] = {
    "+", "-", "*", "/", "%",
    "-",
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
        default:
            ERR("Unexpected token: %s", token_str(token));
    }

    scan(f, token);
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

void __node_walk(struct node *node, int depth)
{
    if (node == NULL)
        return;

    if (node->left)
        __node_walk(node->left, depth + 1);
    if (node->right)
        __node_walk(node->right, depth + 1);

    printf("%*s", depth * 2, "");
    switch (node->node) {
        case A_ADD:
            printf("+");
            break;
        case A_MINUS:
            printf("-");
            break;
        case A_NEGATE:
            printf("NEGATE");
            break;
        case A_MUL:
            printf("*");
            break;
        case A_DIV:
            printf("/");
            break;
        case A_MOD:
            printf("%%");
            break;
        case A_INT_LIT:
            printf("%llu", node->value);
            break;
        case A_DEC_LIT:
            printf("%llu.%llu", node->value, node->fraction);
            break;
    }
    printf("\n");
}

void node_walk(struct node *node)
{
    __node_walk(node, 0);
}
