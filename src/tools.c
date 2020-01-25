#include "sic.h"
#include "parse.h"

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
        case A_GLUE:
            printf("GLUE");
            break;
        case A_TYPE:
            printf("TYPE");
            break;
        case A_IDENTIFIER:
            printf("IDENTIFIER");
            break;
        case A_ASSIGN:
            printf("ASSIGN");
            break;
        default:
            ERR("Unknown node: %s", node_str(node));
    }
    printf("\n");
}

void node_walk(struct node *node)
{
    __node_walk(node, 0);
}
