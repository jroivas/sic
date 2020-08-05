#define _DEFAULT_SOURCE
#include <stdio.h>
#include <execinfo.h>
#include <string.h>

#include "sic.h"
#include "parse.h"

static const char *typestr[] = {
    "void", "NULL", "int", "float", "fixed", "str", "struct", "union", "enum", "custom", "builtin"
};

const char *type_str(enum var_type t)
{
    FATAL(t >= sizeof(typestr) / sizeof (char*),
            "Node string table overflow with %d", t);
    return typestr[t];
}

int solve_escape(const char *v)
{
    if (!v || v[0] == 0)
        return -1;
    if (v[0] != '\\')
        return v[0];
    if (v[1] == 0)
        return -2;

    if (v[1] == 'n')
        return '\n';
    if (v[1] == 'r')
        return '\r';
    if (v[1] == 't')
        return '\t';
    if (v[1] == '0')
        return 0;
    if (v[1] == '\\')
        return '\\';
    if (v[1] == 'a')
        return '\a';
    if (v[1] == 'b')
        return '\b';
    if (v[1] == 'f')
        return '\f';
    if (v[1] == 'v')
        return '\v';
    if (v[1] == '\'')
        return '\'';
    if (v[1] == '"')
        return '"';

    return -3;
}

int solve_escape_str(char *ptr, int v)
{
    if (v == '0') {
        *ptr++ = 0;
        return 1;
    }
    if (v == '\\') {
        *ptr = '\\';
        return 1;
    }
    if (v == '\'') {
        *ptr = '\'';
        return 1;
    }
    if (v == '"') {
        *ptr = '"';
        return 1;
    }
    if (v == 'a') {
        *ptr++ = '\\';
        *ptr++ = '0';
        *ptr++ = '7';
        return 3;
    }
    if (v == 'b') {
        *ptr++ = '\\';
        *ptr++ = '0';
        *ptr++ = '8';
        return 3;
    }
    if (v == 't') {
        *ptr++ = '\\';
        *ptr++ = '0';
        *ptr++ = '9';
        return 3;
    }
    if (v == 'n') {
        *ptr++ = '\\';
        *ptr++ = '0';
        *ptr++ = 'A';
        return 3;
    }
    if (v == 'v') {
        *ptr++ = '\\';
        *ptr++ = '0';
        *ptr++ = 'B';
        return 3;
    }
    if (v == 'f') {
        *ptr++ = '\\';
        *ptr++ = '0';
        *ptr++ = 'C';
        return 3;
    }
    if (v == 'r') {
        *ptr++ = '\\';
        *ptr++ = '0';
        *ptr++ = 'D';
        return 3;
    }

    return 0;
}

char *convert_escape(const char *src, int *len)
{
    int srclen = strlen(src);
    int reslen = srclen * 3;
    char *resptr = calloc(1, reslen);
    char *res = resptr;
    int escape = 0;

    while (*src != 0) {
        if (escape) {
            int cnt = solve_escape_str(res, *src);
            src++;
            res += cnt;
            (*len)++;
            escape = 0;
        } else if (*src == '\\'){
            escape = 1;
            src++;
        } else {
            *res = *src;
            res++;
            src++;
            (*len)++;
        }
    }

    return resptr;
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
    char *tmp = NULL;;
    if (cnt <= 0)
        return calloc(1, 1);

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
        case A_DEREFERENCE:
        case A_STRUCT:
        case A_UNION:
        case A_ENUM:
        case A_ACCESS:
        case A_TYPE_LIST:
        case A_ELLIPSIS:
        case A_BREAK:
        case A_CONTINUE:
        case A_ATTRIBUTE:
        case A_SIZEOF:
            printf("%s", node_str(node));
            break;
        case A_TYPEDEF:
            printf("TYPEDEF: %s", node->value_string);
            break;
        case A_GOTO:
            printf("GOTO: %s", node->value_string);
            break;
        case A_LABEL:
            printf("LABEL: %s", node->value_string);
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
            printf("TYPE %s%*s (%d) %d %s, %s%s%s %s", type_str(node->type),
                node->ptr ? node->ptr : 0,
                node->ptr ? "*" : "",
                node->ptr,
                node->bits, node->sign ? "signed" : "unsigned",
                node->is_const ? "const " : "",
                node->is_extern ? "extern " : "",
                node->value_string,
                node->type_name ? node->type_name : "");
            break;
        case A_IDENTIFIER:
            printf("IDENTIFIER %s (intvalue %lld)", node->value_string, node->value);
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
            printf("TYPE_QUAL %s", node->value_string);
            break;
        case A_STORAGE_CLASS:
            printf("STORAGE_CLASS %s", node->value_string);
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

void node_free(struct node *node)
{
    if (!node)
        return;

    node_free(node->left);
    node_free(node->mid);
    node_free(node->right);

    free(node);
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

char *int_to_str(literalnum val)
{
    // FIXME
    int max_size = 64;
    char *res = calloc(1, max_size);

    snprintf(res, max_size - 1, "%lld", val);

    return res;
}

char *double_to_str(literalnum val, literalnum frac)
{
    // FIXME
    int max_size = 64;
    char *res = calloc(1, max_size);

    snprintf(res, max_size - 1, "%llu.%llu", val, frac);

    return res;
}

const char *resolve_cpp()
{
    // FIXME
    //return "cpp -nostdinc -isystem inc/sys";
    //return "cpp -nostdinc";
    //return "cpp -ansi -pedantic -D__extension__=";
    return "cpp -D__extension__=";
}

char *gen_incs(char **incs, int inc_cnt)
{
    if (!incs)
        return "";

    int cnt = TEXT_BUFFER_SIZE - 1;
    char *res = calloc(1, TEXT_BUFFER_SIZE);

    for (int i = 0; i < inc_cnt; i++) {
        res = strncat(res, "-I", cnt);
        cnt -= 2;
        res = strncat(res, incs[i], cnt);
        cnt -= strlen(incs[i]);
        res = strncat(res, " ", cnt);
        cnt--;
        FATAL(cnt <= 0, "Too many incs")
    }
    return res;
}

FILE *preprocess(const char *fname, char **incs, int inc_cnt)
{
    char cmd[2 * TEXT_BUFFER_SIZE + 1];

    snprintf(cmd, TEXT_BUFFER_SIZE, "%s %s %s", resolve_cpp(), gen_incs(incs, inc_cnt), fname);

#if DEBUG
    printf("Running: %s\n", cmd);
#endif
    return popen(cmd, "r");
}

