#include "sic.h"
#include "parse.h"
#include <execinfo.h>

static const char *typestr[] = {
    "void", "NULL", "int", "float", "fixed", "str"
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

char *get_stars(int cnt)
{
        char *tmp = NULL;
        if (cnt <= 0)
            return tmp;

        tmp = calloc(cnt + 1, 1);
        for (int i = 0; i < cnt; i++)
            tmp[i] = '*';
        return tmp;
}

int determine_size(literalnum value)
{
    return determine_size_bytes(value) * 8;
}

unsigned long djb2(const unsigned char *str)
{
    unsigned long hash = 5381;
    unsigned long c;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }

    return hash;
}

hashtype hash(const char *str)
{
    if (!str)
        return 0;
    return djb2((const unsigned char*)str);
}

void __node_walk(struct node *node, int depth, char arm)
{
    if (node == NULL)
        return;

    printf("%c %*s", arm, depth * 2, "");
    switch (node->node) {
        case A_ADD:
        case A_MINUS:
        case A_IF:
        case A_TERNARY:
        case A_NEGATE:
        case A_NOT:
        case A_MUL:
        case A_DIV:
        case A_MOD:
        case A_GLUE:
        case A_LIST:
        case A_ASSIGN:
        case A_ADD_ASSIGN:
        case A_SUB_ASSIGN:
        case A_MUL_ASSIGN:
        case A_DIV_ASSIGN:
        case A_MOD_ASSIGN:
        case A_LEFT_ASSIGN:
        case A_RIGHT_ASSIGN:
        case A_AND_ASSIGN:
        case A_OR_ASSIGN:
        case A_XOR_ASSIGN:
        case A_AND:
        case A_OR:
        case A_LOG_AND:
        case A_LOG_OR:
        case A_XOR:
        case A_FUNCTION:
        case A_RETURN:
        case A_EQ_OP:
        case A_NE_OP:
        case A_LT:
        case A_GT:
        case A_LT_EQ:
        case A_GT_EQ:
        case A_DECLARATION:
        case A_FUNC_CALL:
        case A_NULL:
        case A_POSTINC:
        case A_POSTDEC:
        case A_PREINC:
        case A_PREDEC:
        case A_LEFT:
        case A_RIGHT:
        case A_TILDE:
        case A_CAST:
        case A_WHILE:
        case A_DO:
        case A_FOR:
        case A_INDEX:
        case A_PARAMS:
            printf("%s", node_str(node));
            break;
        case A_INT_LIT:
            printf("INT: %llu, %d bits %s", node->value, node->bits, node->sign ? "signed" : "unsigned");
            break;
        case A_DEC_LIT:
            printf("DECIMAL: %llu.%llu", node->value, node->fraction);
            break;
        case A_STR_LIT:
            printf("STRING: %s", node->value_string);
            break;
        case A_TYPE:
            printf("TYPE %s%*s (%d) %d %s, %s%s", type_str(node->type),
                node->ptr ? node->ptr : 0,
                node->ptr ? "*" : "",
                node->ptr,
                node->bits, node->sign ? "signed" : "unsigned",
                node->is_const ? "const " : "",
                node->value_string);
            break;
        case A_IDENTIFIER:
            printf("IDENTIFIER %s", node->value_string);
            break;
        case A_POINTER:
            printf("POINTER: %d", node->ptr);
            break;
        case A_ADDR:
            printf("ADDR: %d", node->addr);
            break;
        case A_TYPESPEC:
            printf("TYPESPEC %s %d %s, %s", type_str(node->type),
                node->bits, node->sign ? "signed" : "unsigned",
                node->value_string);
            break;
        case A_TYPE_QUAL:
            printf("TYPEQUAL %s", node->value_string);
            break;
        default:
            ERR("Unknown node while walking: %s", node_str(node));
    }
    printf("\n");

    if (node->left)
        __node_walk(node->left, depth + 1, 'L');
    if (node->mid)
        __node_walk(node->mid, depth + 1, 'M');
    if (node->right)
        __node_walk(node->right, depth + 1, 'R');
}

void node_walk(struct node *node)
{
    __node_walk(node, 0, '>');
}

void stack_trace(void)
{
    void *array[STACK_TRACE_SIZE];
    char **strings;
    size_t size;

    size = backtrace(array, STACK_TRACE_SIZE);
    strings = backtrace_symbols(array, size);

    printf("Call trace:\n");
    for (size_t i = 0; i < size; i++)
        printf("  %s\n", strings[i]);

    free(strings);
}
