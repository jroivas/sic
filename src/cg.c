#include "gc.h"
#include "parse.h"
#include <string.h>

struct type {
    int id;
    enum var_type type;
    int bits;
    int sign;
    const char *name;
    hashtype name_hash;
    struct type *ref;
    struct type *next;
};

struct variable {
    int id;
    int reg;
    int direct;
    struct type *type;
    const char *name;
    hashtype name_hash;
    struct variable *next;
};

struct gen_context {
    FILE *f;
    int ids;
    int regnum;
    int type;
    int safe;
    char *name;
    struct type *pending_type;
    struct type *types;
    struct variable *variables;
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

struct type *find_type_by_name(struct type *first, const char *name)
{
    struct type *res = first;
    FATAL(!name, "No type name provided!");
    hashtype h = hash(name);
    while (res) {
        if (res->name_hash == h && strcmp(res->name, name) == 0)
            return res;
        res = res->next;
    }
    return NULL;
}

struct type *find_type_by(struct type *first, enum var_type type, int bits, int sign)
{
    struct type *res = first;
    while (res) {
        if (res->type == type && res->bits == bits && res->sign == sign)
            return res;
        res = res->next;
    }
    return NULL;
}

struct type *init_type(const char *name, enum var_type t, int bits, int sign)
{
    struct type *res = calloc(1, sizeof(struct type));

    res->type = t;
    res->bits = bits;
    res->name = name;
    res->sign = sign;
    res->name_hash = hash(name);

    return res;
}

struct variable *find_variable_by_name(struct variable *first, const char *name)
{
    if (name == NULL)
        return NULL;
    struct variable *res = first;
    FATAL(!name, "No variable name provided!");
    hashtype h = hash(name);
    while (res) {
        if (res->name_hash == h && strcmp(res->name, name) == 0)
            return res;
        res = res->next;
    }
    return NULL;
}

struct variable *init_variable(const char *name, struct type *t)
{
    struct variable *res = calloc(1, sizeof(struct variable));

    res->type = t;
    res->name = name;
    res->name_hash = hash(name);

    return res;
}

void register_type(struct gen_context *ctx, struct type *type)
{
    //struct type *t = find_type(ctx->types, type->name);
    struct type *t = find_type_by(ctx->types, type->type, type->bits, type->sign);
    FATAL(t, "Type already registered: %s", type->name);

    type->id = ++ctx->ids;
    type->next = ctx->types;
    ctx->types = type;
}

void register_variable(struct gen_context *ctx, struct variable *var)
{
    struct variable *v = find_variable_by_name(ctx->variables, var->name);
    FATAL(v, "Variable already registered: %s", var->name);

    var->id = ++ctx->ids;
    var->next = ctx->variables;
    ctx->variables = var;
}

void register_builtin_types(struct gen_context *ctx)
{
    register_type(ctx, init_type("void", V_VOID, 0, 0));

    register_type(ctx, init_type("char", V_INT, 8, 1));
    register_type(ctx, init_type("unsigned char", V_INT, 8, 0));

    register_type(ctx, init_type("short", V_INT, 16, 1));
    register_type(ctx, init_type("unsigned short", V_INT, 16, 0));

    //register_type(ctx, init_type("unsigned", V_INT, 32, 0));
    register_type(ctx, init_type("int", V_INT, 32, 1));
    register_type(ctx, init_type("unsigned int", V_INT, 32, 0));

    register_type(ctx, init_type("long", V_INT, 64, 1));
    register_type(ctx, init_type("unsigned long", V_INT, 64, 0));

    register_type(ctx, init_type("float", V_FLOAT, 64, 1));
}

struct gen_context *init(FILE *outfile)
{
    struct gen_context *res = calloc(1, sizeof(struct gen_context));
    res->f = outfile;
    res->regnum = 1;
    res->pending_type = NULL;
    res->types = NULL;
    res->variables = NULL;
    res->type = V_VOID;
    res->safe = 1;
    res->name = "__global_context";
    register_builtin_types(res);
    return res;
}

struct variable *find_variable(struct gen_context *ctx, int reg)
{
    struct variable *val = ctx->variables;
    while (val != NULL) {
        if (val->reg == reg)
            return val;
        val = val->next;
    }
    return NULL;
}

struct variable *new_variable(struct gen_context *ctx,
        enum var_type type, int bits, int sign)
{
    struct variable *res = calloc(1, sizeof(struct variable));

    res->id = ++ctx->ids;
    // Float and fixed are always signed
    if (type == V_FLOAT)
        sign = 1;
    res->reg = ctx->regnum++;

    // If bits == 0 and we have a pendign type, use it
    if (bits == 0 && ctx->pending_type) {
        type = ctx->pending_type->type;
        bits = ctx->pending_type->bits;
        sign = ctx->pending_type->sign;
    } else if (bits == 0) {
        if (type == V_FLOAT)
            bits = 64;
        else
            // Default to 32
            bits = 32;
    }
    res->type = find_type_by(ctx->types, type, bits, sign);
    res->next = ctx->variables;
    FATAL(!res->type, "Didn't find type!");

    ctx->variables = res;

    return res;
}

struct variable *new_inst_variable(struct gen_context *ctx,
        enum var_type type, int bits, int sign)
{
    struct variable *res = new_variable(ctx, type, bits, sign);
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

struct variable *gen_cast(struct gen_context *ctx, struct variable *v, enum var_type target)
{
    if (v == NULL)
        ERR("Invalid cast!");
    if (v->type->type == target)
        return v;

    struct variable *val;
    if (target == V_FLOAT && v->type->type == V_INT) {
        val = new_variable(ctx, V_FLOAT, v->type->bits, 1);
        fprintf(ctx->f, "%%%d = sitofp i%d %%%d to double\n",
                val->reg, v->type->bits, v->reg);
        val->direct = 1;
    } else
        ERR("Invalid cast for %d, %d -> %d",
            v->reg, v->type->type, target);

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
    if (!n)
        ERR("No valid node given!");
    struct variable *val = new_variable(ctx, V_INT, n->bits, n->value < 0);
    gen_allocate_int(ctx, val->reg, val->type->bits);

    fprintf(ctx->f, "store i%d %llu, i%d* %%%d, align 4\n",
            val->type->bits, n->value, val->type->bits, val->reg);
    return val->reg;
}

int gen_store_int_lit(struct gen_context *ctx, literalnum value)
{
    struct variable *val = new_variable(ctx, V_INT, 32, value < 0);
    gen_allocate_int(ctx, val->reg, val->type->bits);

    fprintf(ctx->f, "store i%d %llu, i%d* %%%d, align 4\n",
            val->type->bits, value, val->type->bits, val->reg);
    return val->reg;
}

char *double_str(literalnum value, literalnum frac)
{
    char *tmp = calloc(1, 256);
    snprintf(tmp, 255, "%llu.%llue+00", value, frac);
    return tmp;
}

int gen_store_double(struct gen_context *ctx, struct node *n)
{
    struct variable *val = new_variable(ctx, V_FLOAT, n->bits, 1);
    gen_allocate_double(ctx, val->reg);

    char *tmp = double_str(n->value, n->fraction);

    fprintf(ctx->f, "store double %s, double* %%%d, align 8\n",
            tmp, val->reg);
    return val->reg;
}

struct variable *gen_load_int(struct gen_context *ctx, struct variable *v)
{
    if (v->direct)
        return v;
    struct variable *res = new_variable(ctx, V_INT, v->type->bits, 0);

    fprintf(ctx->f, "%%%d = load i%d, i%d* %%%d, align 4\n",
            res->reg, res->type->bits, res->type->bits, v->reg);
    return res;
}

struct variable *gen_load_float(struct gen_context *ctx, struct variable *v)
{
    if (v->direct)
        return v;
    struct variable *res = new_variable(ctx, V_FLOAT, v->type->bits, 1);

    fprintf(ctx->f, "%%%d = load double, double* %%%d, align 8\n",
            res->reg, v->reg);
    return res;
}

struct variable *gen_load(struct gen_context *ctx, struct variable *v)
{
    if (v == NULL)
        ERR("Can't load null!");
    if (v->type->type == V_INT)
        return gen_load_int(ctx, v);
    else if (v->type->type == V_FLOAT)
        return gen_load_float(ctx, v);

    ERR("Invalid type: %d", v->type->type);
}

struct variable *gen_bits(struct gen_context *ctx, struct variable *v1, struct variable *v2)
{
    int bits1 = v1->type->bits;
    int bits2 = v2->type->bits;
    if (bits1 == bits2)
        return v1;
    if (bits1 > bits2)
        return v1;

    struct variable *res = new_inst_variable(ctx, V_INT, bits2, v1->type->sign || v2->type->sign);
    if (v2->type->sign) {
        fprintf(ctx->f, "%%%d = sext i%d %%%d to i%d\n",
            res->reg, bits1, v1->reg, bits2);
    } else {
        fprintf(ctx->f, "%%%d = zext i%d %%%d to i%d\n",
            res->reg, bits1, v1->reg, bits2);
    }
    return res;
}

enum var_type get_and_cast(struct gen_context *ctx, struct variable **v1, struct variable **v2)
{
    FATAL(!*v1, "Can't load v1");
    *v1 = gen_load(ctx, *v1);
    FATAL(!*v2, "Can't load v2");
    *v2 = gen_load(ctx, *v2);

    enum var_type restype = resolve_type((*v1)->type->type, (*v2)->type->type);
    *v1 = gen_cast(ctx, *v1, restype);
    *v2 = gen_cast(ctx, *v2, restype);

    if (restype == V_INT) {
        *v1 = gen_bits(ctx, *v1, *v2);
        *v2 = gen_bits(ctx, *v2, *v1);
    }

    return restype;
}

int gen_add(struct gen_context *ctx, int a, int b)
{
    struct variable *v1 = find_variable(ctx, a);
    struct variable *v2 = find_variable(ctx, b);
    enum var_type restype = get_and_cast(ctx, &v1, &v2);
    struct variable *res = new_inst_variable(ctx, restype, v1->type->bits, v1->type->sign || v2->type->sign);

    if (restype == V_INT) {
        fprintf(ctx->f, "%%%d = add i%d %%%d, %%%d\n",
            res->reg, v1->type->bits, v1->reg, v2->reg);
    } else if (restype == V_FLOAT) {
        fprintf(ctx->f, "%%%d = fadd double %%%d, %%%d\n",
            res->reg, v1->reg, v2->reg);
    } else
        ERR("Invalid type: %d", restype);
    return res->reg;
}

int gen_sub(struct gen_context *ctx, int a, int b)
{
    struct variable *v1 = find_variable(ctx, a);
    struct variable *v2 = find_variable(ctx, b);
    enum var_type restype = get_and_cast(ctx, &v1, &v2);
    struct variable *res = new_inst_variable(ctx, restype, v1->type->bits, v1->type->sign || v2->type->sign);

    if (restype == V_INT) {
        fprintf(ctx->f, "%%%d = sub i%d %%%d, %%%d\n",
            res->reg, v1->type->bits, v1->reg, v2->reg);
    } else if (restype == V_FLOAT) {
        fprintf(ctx->f, "%%%d = fsub double %%%d, %%%d\n",
            res->reg, v1->reg, v2->reg);
    } else
        ERR("Invalid type: %d", restype);
    return res->reg;
}

int gen_mul(struct gen_context *ctx, int a, int b)
{
    struct variable *v1 = find_variable(ctx, a);
    struct variable *v2 = find_variable(ctx, b);
    enum var_type restype = get_and_cast(ctx, &v1, &v2);
    struct variable *res = new_inst_variable(ctx, restype, v1->type->bits, v1->type->sign || v2->type->sign);

    if (restype == V_INT) {
        fprintf(ctx->f, "%%%d = mul i%d %%%d, %%%d\n",
            res->reg, v1->type->bits, v1->reg, v2->reg);
    } else if (restype == V_FLOAT) {
        fprintf(ctx->f, "%%%d = fmul double %%%d, %%%d\n",
            res->reg, v1->reg, v2->reg);
    } else
        ERR("Invalid type: %d", restype);
    return res->reg;
}

int gen_div(struct gen_context *ctx, int a, int b)
{
    struct variable *v1 = find_variable(ctx, a);
    struct variable *v2 = find_variable(ctx, b);
    enum var_type restype = get_and_cast(ctx, &v1, &v2);
    struct variable *res = new_inst_variable(ctx, restype, v1->type->bits, v1->type->sign || v2->type->sign);

    if (restype == V_INT) {
        if (v1->type->sign || v2->type->sign) {
            fprintf(ctx->f, "%%%d = sdiv i%d %%%d, %%%d\n",
                res->reg, v1->type->bits, v1->reg, v2->reg);
        } else {
            fprintf(ctx->f, "%%%d = udiv i%d %%%d, %%%d\n",
                res->reg, v1->type->bits, v1->reg, v2->reg);
        }
    } else if (restype == V_FLOAT) {
        fprintf(ctx->f, "%%%d = fdiv double %%%d, %%%d\n",
            res->reg, v1->reg, v2->reg);
    } else
        ERR("Invalid type: %d", restype);
    return res->reg;
}

int gen_mod(struct gen_context *ctx, int a, int b)
{
    struct variable *v1 = find_variable(ctx, a);
    struct variable *v2 = find_variable(ctx, b);
    enum var_type restype = get_and_cast(ctx, &v1, &v2);
    struct variable *res = new_inst_variable(ctx, restype, v1->type->bits, v1->type->sign || v2->type->sign);

    if (restype == V_INT) {
        if (v1->type->sign && v2->type->sign) {
            fprintf(ctx->f, "%%%d = srem i%d %%%d, %%%d\n",
                res->reg, v1->type->bits, v1->reg, v2->reg);
        } else {
            fprintf(ctx->f, "%%%d = urem i%d %%%d, %%%d\n",
                res->reg, v1->type->bits, v1->reg, v2->reg);
        }
    } else if (restype == V_FLOAT) {
        fprintf(ctx->f, "%%%d = frem double %%%d, %%%d\n",
            res->reg, v1->reg, v2->reg);
    } else
        ERR("Invalid type: %d", restype);
    return res->reg;
}

int gen_negate(struct gen_context *ctx, int a)
{
    struct variable *v = find_variable(ctx, a);
    struct variable *res;

    FATAL(!v, "Can't negate zero");
    v = gen_load(ctx, v);
    if (v->type->type == V_INT) {
        int zeroreg = gen_store_int_lit(ctx, 0);
        struct variable *zero = find_variable(ctx, zeroreg);
        FATAL(!zero, "Can't load zero");
        zero = gen_load(ctx, zero);
        zero = gen_bits(ctx, zero, v);

        res = new_inst_variable(ctx, v->type->type, v->type->bits, 1);
        fprintf(ctx->f, "%%%d = sub i%d %%%d, %%%d\n",
            res->reg, v->type->bits, zero->reg, v->reg);
    } else if (v->type->type == V_FLOAT) {
        res = new_inst_variable(ctx, v->type->type, v->type->bits, 1);
        fprintf(ctx->f, "%%%d = fneg double %%%d\n",
            res->reg, v->reg);
    } else
        ERR("Invalid type of %d: %d", a, v->type->type);

    return res->reg;
}

int gen_type(struct gen_context *ctx, struct node *node)
{
    //struct type *t = find_type(ctx->types, node->value_string);
    struct type *t = find_type_by(ctx->types, node->type, node->bits, node->sign);
    if (t == NULL)
        ERR("Couldn't find type: %s", node->value_string);

    ctx->pending_type = t;

    return REF_CTX(t->id);
}

int gen_identifier(struct gen_context *ctx, struct node *node)
{
    struct variable *var = find_variable_by_name(ctx->variables, node->value_string);
    int res;
    if (var == NULL) {
        // Utilize pending type from previous type def
        FATAL(!ctx->pending_type, "Can't determine type of variable %s", node->value_string);
        struct type *t = ctx->pending_type;
        switch (t->type) {
            case V_INT:
                var = new_variable(ctx, V_INT, t->bits, 0);
                res = gen_allocate_int(ctx, var->reg, var->type->bits);
                break;
            case V_FLOAT:
                var = new_variable(ctx, V_FLOAT, t->bits, 1);
                res = gen_allocate_double(ctx, var->reg);
                break;
            default:
                ERR("Invalid type for variable: %s", type_str(var->type->type));
                break;
        }
    } else
        res = var->reg;
    return res;
}

int gen_assign(struct gen_context *ctx, struct node *node, int left, int right)
{
    struct variable *src_val = find_variable(ctx, right);
    FATAL(!src_val, "Can't assign from zero");
    struct variable *src = gen_load(ctx, src_val);
    struct variable *dst = find_variable(ctx, left);

    FATAL(!src, "No source in assign")
    FATAL(!dst, "No dest in assign")

    if (src->type->type == V_INT) {
        fprintf(ctx->f, "store i%d %%%d, i%d* %%%d, align 4\n",
                src->type->bits, src->reg, dst->type->bits, dst->reg);
    } else
        ERR("Invalid assign");
    return dst->reg;
}

int gen_declaration(struct gen_context *ctx, struct node *node, int left, int right)
{
    FATAL(left >= 0, "Invalid type definition in declaration");
    ctx->pending_type = NULL;
    return right;
}

int gen_recursive(struct gen_context *ctx, struct node *node)
{
    int resleft = 0, resright = 0;
    if (node == NULL)
        return 0;

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
            return gen_mod(ctx, resleft, resright);
        case A_INT_LIT:
            return gen_store_int(ctx, node);
        case A_DEC_LIT:
            // FIXME Double for now
            return gen_store_double(ctx, node);
        case A_LIST:
        case A_GLUE:
            if (resright)
                return resright;
            if (resleft)
                return resleft;
            break;
        case A_TYPE:
            return gen_type(ctx, node);
        case A_IDENTIFIER:
            return gen_identifier(ctx, node);
        case A_ASSIGN:
            return gen_assign(ctx, node, resleft, resright);
        case A_DECLARATION:
            return gen_declaration(ctx, node, resleft, resright);
        default:
            ERR("Unknown node in code gen: %s", node_str(node));
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
        struct variable *var = find_variable(ctx, res);
        FATAL(!var, "Invalid return variable: %d", res);
        if (!var->direct) {
            struct variable *tmp = gen_load(ctx, var);
            res = tmp->reg;
        }

        const char *type = var_str(node->type, node->bits, &tmp);
        fprintf(ctx->f, "ret %s %%%d\n", type, res);
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
