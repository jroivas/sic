#include "gc.h"
#include "parse.h"

struct value {
    int reg;
    int bits;
    int direct;
    int sign;

    enum var_type type;
    literalnum value;
    literalnum frac;
    struct value *next;
};

struct gen_context {
    FILE *f;
    int regnum;
    struct value *values;
    int type;
    int safe;
    char *name;
};

static const char *varstr[] = {
    "void", "i32", "double", "invalid"
};

const char *var_str(enum var_type v, int size, char **r)
{
    FATAL(v >= sizeof(varstr) / sizeof (char*),
            "Variable type string table overflow with %d", v);
    if (v == V_INT && size != 32) {
        char *tmp = calloc(1, 8);
        snprintf(tmp, 8, "i%d", size);
        *r = tmp;
        return tmp;
    }
    *r = NULL;

    return varstr[v];
}

struct gen_context *init(FILE *outfile)
{
    struct gen_context *res = calloc(1, sizeof(struct gen_context));
    res->f = outfile;
    res->regnum = 1;
    res->values = NULL;
    res->type = V_VOID;
    res->safe = 1;
    res->name = "__global_context";
    return res;
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

struct value *new_value_frac(struct gen_context *ctx, literalnum value, literalnum frac, int bits, enum var_type type)
{
    struct value *val = calloc(1, sizeof(struct value));
    val->bits = bits;
    val->reg = ctx->regnum++;
    val->value = value;
    val->frac = frac;
    val->type = type;
    val->next = ctx->values;
    val->direct = 0;
    val->sign = 0;
    ctx->values = val;
    return val;
}

struct value *new_value(struct gen_context *ctx, literalnum value,
        int bits, enum var_type type)
{
    return new_value_frac(ctx, value, 0, bits, type);
}

struct value *new_inst_value(struct gen_context *ctx,
        literalnum value, int bits, enum var_type type)
{
    struct value *res = new_value(ctx, value, bits, type);
    res->direct = 1;
    return res;
}

enum var_type resolve_type(enum var_type a, enum var_type b)
{
    if (a == b)
        return a;
    if (a == V_FLOAT && b == V_INT)
        return V_FLOAT;
    if (b == V_FLOAT && a == V_INT)
        return V_FLOAT;
    ERR("Unsupported cast: %d <-> %d", a, b);
}

struct value *gen_cast(struct gen_context *ctx, struct value *v, enum var_type target)
{
    if (v == NULL)
        ERR("Invalid cast!");
    if (v->type == target)
        return v;

    struct value *val;
    if (target == V_FLOAT && v->type == V_INT) {
        val = new_value_frac(ctx, v->value, 0, v->bits, V_FLOAT);
        fprintf(ctx->f, "%%%d = sitofp i%d %%%d to double\n",
                val->reg, v->bits, v->reg);
        val->direct = 1;
        //    sitofp i32 %6 to float
    } else
        ERR("Invalid cast for %d, %d -> %d",
            v->reg, v->type, target);

    return val;
}

int gen_allocate_int(struct gen_context *ctx, int reg, int bits)
{
    // TODO Fix align
    fprintf(ctx->f, "%%%d = alloca i%d, align 4\n",
        reg, bits);
    return reg;
}

int gen_allocate_double(struct gen_context *ctx, int reg)
{
    fprintf(ctx->f, "%%%d = alloca double, align 8\n", reg);
    return reg;
}

int gen_store_int(struct gen_context *ctx, struct node *n)
{
    struct value *val = new_value(ctx, n->value, n->bits, V_INT);
    gen_allocate_int(ctx, val->reg, val->bits);

    fprintf(ctx->f, "store i%d %llu, i%d* %%%d, align 4\n",
            val->bits, n->value, val->bits, val->reg);
    return val->reg;
}

char *double_str(struct value *val)
{
    char *tmp = calloc(1, 256);
    snprintf(tmp, 255, "%llu.%llue+00", val->value, val->frac);
    return tmp;
}

int gen_store_double(struct gen_context *ctx, struct node *n)
{
    struct value *val = new_value_frac(ctx, n->value, n->fraction, n->bits, V_FLOAT);
    gen_allocate_double(ctx, val->reg);

    char *tmp = double_str(val);

    fprintf(ctx->f, "store double %s, double* %%%d, align 8\n",
            tmp, val->reg);
    return val->reg;
}

struct value *gen_load_int(struct gen_context *ctx, struct value *v)
{
    if (v->direct)
        return v;
    struct value *res = new_value(ctx, v->value, v->bits, V_INT);

    fprintf(ctx->f, "%%%d = load i%d, i%d* %%%d, align 4\n",
            res->reg, res->bits, res->bits, v->reg);
    return res;
}

struct value *gen_load_float(struct gen_context *ctx, struct value *v)
{
    if (v->direct)
        return v;
    struct value *res = new_value(ctx, v->value, v->bits, V_FLOAT);

    fprintf(ctx->f, "%%%d = load double, double* %%%d, align 8\n",
            res->reg, v->reg);
    return res;
}

struct value *gen_load(struct gen_context *ctx, struct value *v, int reg)
{
    if (v == NULL)
        ERR("Value not found for: %d", reg);
    if (v->type == V_INT)
        return gen_load_int(ctx, v);
    else if (v->type == V_FLOAT)
        return gen_load_float(ctx, v);

    ERR("Invalid type: %d", v->type);
}

struct value *gen_bits(struct gen_context *ctx, struct value *v1, struct value *v2)
{
    int bits1 = v1->bits;
    int bits2 = v2->bits;
    if (bits1 == bits2)
        return v1;
    if (bits1 > bits2)
        return v1;

    struct value *res = new_inst_value(ctx, 0, bits2, V_INT);
    if (v2->sign) {
        fprintf(ctx->f, "%%%d = sext i%d %%%d to i%d\n",
            res->reg, bits1, v1->reg, bits2);
    } else {
        fprintf(ctx->f, "%%%d = zext i%d %%%d to i%d\n",
            res->reg, bits1, v1->reg, bits2);
    }
    return res;
}

int gen_add(struct gen_context *ctx, int a, int b)
{
    struct value *v1 = find_value(ctx, a);
    struct value *v2 = find_value(ctx, b);
    v1 = gen_load(ctx, v1, a);
    v2 = gen_load(ctx, v2, b);

    enum var_type restype = resolve_type(v1->type, v2->type);
    v1 = gen_cast(ctx, v1, restype);
    v2 = gen_cast(ctx, v2, restype);

    struct value *res;

    if (restype == V_INT) {
        v1 = gen_bits(ctx, v1, v2);
        v2 = gen_bits(ctx, v2, v1);
        res = new_inst_value(ctx, 0, v1->bits, restype);
        fprintf(ctx->f, "%%%d = add i%d %%%d, %%%d\n",
            res->reg, v1->bits, v1->reg, v2->reg);
    } else if (restype == V_FLOAT) {
        res = new_inst_value(ctx, 0, v1->bits, restype);
        fprintf(ctx->f, "%%%d = fadd double %%%d, %%%d\n",
            res->reg, v1->reg, v2->reg);
    } else
        ERR("Invalid type: %d", restype);
    return res->reg;
}

int gen_sub(struct gen_context *ctx, int a, int b)
{
    struct value *v1 = find_value(ctx, a);
    struct value *v2 = find_value(ctx, b);
    v1 = gen_load(ctx, v1, a);
    v2 = gen_load(ctx, v2, b);

    enum var_type restype = resolve_type(v1->type, v2->type);
    v1 = gen_cast(ctx, v1, restype);
    v2 = gen_cast(ctx, v2, restype);

    struct value *res;

    if (restype == V_INT) {
        v1 = gen_bits(ctx, v1, v2);
        v2 = gen_bits(ctx, v2, v1);
        res = new_inst_value(ctx, 0, v1->bits, restype);
        fprintf(ctx->f, "%%%d = sub i%d %%%d, %%%d\n",
            res->reg, v1->bits, v1->reg, v2->reg);
    } else if (restype == V_FLOAT) {
        res = new_inst_value(ctx, 0, v1->bits, restype);
        fprintf(ctx->f, "%%%d = fsub double %%%d, %%%d\n",
            res->reg, v1->reg, v2->reg);
    } else
        ERR("Invalid type: %d", restype);
    return res->reg;
}

int gen_mul(struct gen_context *ctx, int a, int b)
{
    struct value *v1 = find_value(ctx, a);
    struct value *v2 = find_value(ctx, b);
    v1 = gen_load(ctx, v1, a);
    v2 = gen_load(ctx, v2, b);

    enum var_type restype = resolve_type(v1->type, v2->type);
    v1 = gen_cast(ctx, v1, restype);
    v2 = gen_cast(ctx, v2, restype);

    struct value *res;

    if (restype == V_INT) {
        v1 = gen_bits(ctx, v1, v2);
        v2 = gen_bits(ctx, v2, v1);
        res = new_inst_value(ctx, 0, v1->bits, restype);
        fprintf(ctx->f, "%%%d = mul i%d %%%d, %%%d\n",
            res->reg, v1->bits, v1->reg, v2->reg);
    } else if (restype == V_FLOAT) {
        res = new_inst_value(ctx, 0, v1->bits, restype);
        fprintf(ctx->f, "%%%d = fmul double %%%d, %%%d\n",
            res->reg, v1->reg, v2->reg);
    } else
        ERR("Invalid type: %d", restype);
    return res->reg;
}

int gen_div(struct gen_context *ctx, int a, int b)
{
    struct value *v1 = find_value(ctx, a);
    struct value *v2 = find_value(ctx, b);
    v1 = gen_load(ctx, v1, a);
    v2 = gen_load(ctx, v2, b);

    enum var_type restype = resolve_type(v1->type, v2->type);
    v1 = gen_cast(ctx, v1, restype);
    v2 = gen_cast(ctx, v2, restype);

    struct value *res;

    if (restype == V_INT) {
        v1 = gen_bits(ctx, v1, v2);
        v2 = gen_bits(ctx, v2, v1);
        res = new_inst_value(ctx, 0, v1->bits, restype);
        if (v1->sign && v2->sign) {
            fprintf(ctx->f, "%%%d = sdiv i%d %%%d, %%%d\n",
                res->reg, v1->bits, v1->reg, v2->reg);
        } else {
            fprintf(ctx->f, "%%%d = udiv i%d %%%d, %%%d\n",
                res->reg, v1->bits, v1->reg, v2->reg);
        }
    } else if (restype == V_FLOAT) {
        res = new_inst_value(ctx, 0, v1->bits, restype);
        fprintf(ctx->f, "%%%d = fdiv double %%%d, %%%d\n",
            res->reg, v1->reg, v2->reg);
    } else
        ERR("Invalid type: %d", restype);
    return res->reg;
}

int gen_negate(struct gen_context *ctx, int a)
{
    struct value *v = find_value(ctx, a);
    struct value *res;

    v = gen_load(ctx, v, a);
    if (v->type == V_INT) {
        int zeroreg = gen_store_int(ctx, 0);
        struct value *zero = find_value(ctx, zeroreg);
        zero = gen_load(ctx, zero, zeroreg);
        zero = gen_bits(ctx, zero, v);

        res = new_inst_value(ctx, 0, v->bits, v->type);
        fprintf(ctx->f, "%%%d = sub i%d %%%d, %%%d\n",
            res->reg, v->bits, zero->reg, v->reg);
    } else if (v->type == V_FLOAT) {
        res = new_inst_value(ctx, 0, v->bits, v->type);
        fprintf(ctx->f, "%%%d = fneg double %%%d\n",
            res->reg, v->reg);
    } else
        ERR("Invalid type of %d: %d", a, v->type);

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
            return gen_negate(ctx, resleft);
        case A_MUL:
            return gen_mul(ctx, resleft, resright);
        case A_DIV:
            return gen_div(ctx, resleft, resright);
        case A_MOD:
            fprintf(ctx->f, "gen mod\n");
            break;
        case A_INT_LIT:
            return gen_store_int(ctx, node);
        case A_DEC_LIT:
            // FIXME Double for now
            return gen_store_double(ctx, node);
    }
    return 0;
}

void gen_pre(struct gen_context *ctx, struct node *node)
{
    char *tmp;
    const char *type = var_str(node->type, node->bits, &tmp);
    fprintf(ctx->f, "define dso_local %s @%s() #0 {\n",
            type, ctx->name);
    if (tmp)
        free(tmp);
}

void gen_post(struct gen_context *ctx, struct node *node, int res)
{
    if (node->type != V_VOID) {
        char *tmp;
        const char *type = var_str(node->type, node->bits, &tmp);
        fprintf(ctx->f, "ret %s %%%d\n",
                type, res);
        if (tmp)
            free(tmp);
    }
    fprintf(ctx->f, "}\n");
}

int codegen(FILE *outfile, struct node *node)
{
    struct gen_context *ctx = init(outfile);
    int res;

    gen_pre(ctx, node);
    res = gen_recursive(ctx, node);
    gen_post(ctx, node, res);

    return res;
}
