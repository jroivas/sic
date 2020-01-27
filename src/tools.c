#include "sic.h"
#include "parse.h"

static const char *typestr[] = {
    "void", "int", "float", "fixed"
};

const char *type_str(enum var_type t)
{
    FATAL(t >= sizeof(typestr) / sizeof (char*),
            "Node string table overflow with %d", t);
    return typestr[t];
}

int determine_size_bytes(literalnum value)
{
    if (value < 0x100)
        return 1;
    else if (value < 0x10000)
        return 2;
    else if (value < 0x100000000UL)
        return 4;
    // FIXME 128
    return 8;
}

int determine_size(literalnum value)
{
    return determine_size_bytes(value) * 8;
}

void __node_walk(struct node *node, int depth, char arm)
{
    if (node == NULL)
        return;

    printf("%c %*s", arm, depth * 2, "");
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
        case A_GLUE:
            printf("GLUE");
            break;
        case A_LIST:
            printf("LIST");
            break;
        case A_TYPE:
            printf("TYPE %s", type_str(node->type));
            break;
        case A_IDENTIFIER:
            printf("IDENTIFIER %s", node->value_string);
            break;
        case A_ASSIGN:
            printf("ASSIGN");
            break;
        case A_DECLARATION:
            printf("DECLARATION");
            break;
        default:
            ERR("Unknown node while walking: %s", node_str(node));
    }
    printf("\n");

    if (node->left)
        __node_walk(node->left, depth + 1, 'L');
    if (node->right)
        __node_walk(node->right, depth + 1, 'R');
}

void node_walk(struct node *node)
{
    __node_walk(node, 0, '>');
}
