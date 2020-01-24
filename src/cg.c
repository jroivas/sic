#include "gc.h"
#include "parse.h"

struct value {
    int reg;
    int bits;
    int direct;
    literalnum value;
    struct value *next;
};

struct gen_context {
    FILE *f;
    int regnum;
    struct value *values;
};

struct gen_context *init(FILE *outfile)
{
    struct gen_context *res = calloc(1, sizeof(struct gen_context));
    res->f = outfile;
    res->regnum = 1;
    res->values = NULL;
    return res;
}

int determine_size_bytes(literalnum value)
{
    if (value < 0x100)
        return 1;
    else if (value < 0x10000)
        return 2;
    else if (value < 0x100000000)
        return 4;
    // FIXME 128
    return 8;
}

int determine_size(literalnum value)
{
    return determine_size_bytes(value) * 8;
}

struct value *find_value(struct gen_context *ctx, int reg)
{
    struct value *val = ctx->values;
    while (val != NULL) {
        if (val->reg == reg)
            return val;
        val = val->next;
    }
    return NULL;
}

struct value *new_value(struct gen_context *ctx, literalnum value)
{
    struct value *val = calloc(1, sizeof(struct value));
    val->bits = determine_size(value);
    val->reg = ctx->regnum++;
    val->value = value;
    val->next = ctx->values;
    val->direct = 0;
    ctx->values = val;
    return val;
}

int gen_allocate_int(struct gen_context *ctx, int reg, int bits)
{
    // TODO Fix align
    fprintf(ctx->f, "%%%d = alloca i%d, align 4\n",
        reg, bits);
    return reg;
}

int gen_store_int(struct gen_context *ctx, literalnum value)
{
    struct value *val = new_value(ctx, value);
    gen_allocate_int(ctx, val->reg, val->bits);

    fprintf(ctx->f, "store i%d %llu, i%d* %%%d, align 4\n",
            val->bits, value, val->bits, val->reg);
    return val->reg;
}

int gen_load_int(struct gen_context *ctx, int reg)
{
    struct value *v = find_value(ctx, reg);
    if (v->direct)
        return v->reg;
    struct value *res = new_value(ctx, v->value);

    fprintf(ctx->f, "%%%d = load i%d, i%d* %%%d, align 4\n",
            res->reg, res->bits, res->bits, v->reg);
    return res->reg;
}

int gen_add(struct gen_context *ctx, int a, int b)
{
    struct value *v1 = find_value(ctx, a);
    struct value *v2 = find_value(ctx, b);

    a = gen_load_int(ctx, a);
    b = gen_load_int(ctx, b);

    struct value *res = new_value(ctx, a > b ? a : b);
    res->direct = 1;

    if (v1 == NULL)
        ERR("Error generaing code, can't get reg %d value", a);
    if (v2 == NULL)
        ERR("Error generaing code, can't get reg %d value", b);
    int bits = v1->bits;
    if (bits < v2->bits)
        bits = v2->bits;
    fprintf(ctx->f, "%%%d = add i%d %%%d, %%%d\n",
        res->reg, bits, a, b);
    return res->reg;
}

int gen_sub(struct gen_context *ctx, int a, int b)
{
    struct value *v1 = find_value(ctx, a);
    struct value *v2 = find_value(ctx, b);

    a = gen_load_int(ctx, a);
    b = gen_load_int(ctx, b);

    struct value *res = new_value(ctx, a > b ? a : b);
    res->direct = 1;

    if (v1 == NULL)
        ERR("Error generaing code, can't get reg %d value", a);
    if (v2 == NULL)
        ERR("Error generaing code, can't get reg %d value", b);
    int bits = v1->bits;
    if (bits < v2->bits)
        bits = v2->bits;
    fprintf(ctx->f, "%%%d = sub i%d %%%d, %%%d\n",
        res->reg, bits, a, b);
    return res->reg;
}

int gen_recursive(struct gen_context *ctx, struct node *node)
{
    int resleft = 0, resright = 0;
    if (node == NULL)
        return 1;

    if (node->left)
        resleft = gen_recursive(ctx, node->left);
    if (node->right)
        resright = gen_recursive(ctx, node->right);

    switch (node->node) {
        case A_ADD:
            return gen_add(ctx, resleft, resright);
        case A_MINUS:
            return gen_sub(ctx, resleft, resright);
        case A_NEGATE:
            fprintf(ctx->f, "gen negate\n");
            break;
        case A_MUL:
            fprintf(ctx->f, "gen mul\n");
            break;
        case A_DIV:
            fprintf(ctx->f, "gen div\n");
            break;
        case A_MOD:
            fprintf(ctx->f, "gen mod\n");
            break;
        case A_INT_LIT:
            return gen_store_int(ctx, node->value);
            //fprintf(ctx->f, "gen intlit\n");
            //printf("%llu", node->value);
        case A_DEC_LIT:
            fprintf(ctx->f, "gen declit\n");
            //printf("%llu.%llu", node->value, node->fraction);
            break;
    }
    return 0;
}

int codegen(FILE *outfile, struct node *node)
{
    struct gen_context *ctx = init(outfile);
    return gen_recursive(ctx, node);
}
