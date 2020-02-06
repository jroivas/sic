#include "gc.h"
#include "parse.h"
#include "buffer.h"
#include <string.h>

#define GLOBAL_START 0x10000
#define REGP(X) (X->global) ? "@G" : "%"

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
    int global;
    struct type *type;
    const char *name;
    hashtype name_hash;
    struct variable *next;
};

struct gen_context {
    FILE *f;
    int ids;
    int regnum;
    int regnum_global;
    int type;
    int safe;
    int global;
    const char *name;
    struct node *node;

    struct type *pending_type;
    struct type *types;

    struct variable *variables;
    struct variable *globals;

    struct gen_context *parent;
    struct gen_context *child;
    struct gen_context *next;

    struct buffer *pre;
    struct buffer *init;
    struct buffer *data;
    struct buffer *post;
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
        if (size == 0)
            size = 32;
        snprintf(tmp, 8, "i%d", size);
        *r = tmp;
        return tmp;
    }
    *r = NULL;

    return varstr[v];
}

#if 0
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
#endif

struct type *find_type_by(struct gen_context *ctx, enum var_type type, int bits, int sign)
{
    struct type *res = ctx->types;
    while (res) {
#if DEBUG
        if (res->type == type)
            printf("Typecheck: %d == %d, %d == %d, %s\n", res->bits, bits, res->sign, sign, type_str(type));
#endif
        if (res->type == type && res->bits == bits && res->sign == sign)
            return res;
        res = res->next;
    }
    if (ctx->parent)
        return find_type_by(ctx->parent, type, bits, sign);
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

struct variable *find_global_variable(struct gen_context *ctx, int reg)
{
    struct variable *val = ctx->globals;
    while (val != NULL) {
        if (val->reg == reg)
            return val;
        val = val->next;
    }
    if (ctx->parent)
        return find_global_variable(ctx->parent, reg);
    return NULL;
}

struct variable *find_variable(struct gen_context *ctx, int reg)
{
    if (reg > 0 && reg >= GLOBAL_START)
        return find_global_variable(ctx, reg);
    struct variable *val = ctx->variables;
    while (val != NULL) {
        if (val->reg == reg)
            return val;
        val = val->next;
    }
    //FXIME globals
#if 1
    if (ctx->parent)
        return find_variable(ctx->parent, reg);
#endif
    return NULL;
}

struct variable *find_global_variable_by_name(struct gen_context *ctx, const char *name)
{
    if (name == NULL)
        return NULL;
    struct variable *res = ctx->globals;
    FATAL(!name, "No variable name provided!");
    hashtype h = hash(name);
    while (res) {
        if (res->name_hash == h && strcmp(res->name, name) == 0)
            return res;
        res = res->next;
    }
    if (ctx->parent)
        return find_global_variable_by_name(ctx->parent, name);
    return NULL;
}

struct variable *find_variable_by_name(struct gen_context *ctx, const char *name)
{
    if (name == NULL)
        return NULL;
    struct variable *res = ctx->variables;
    FATAL(!name, "No variable name provided!");
    hashtype h = hash(name);
    while (res) {
        if (res->name_hash == h && strcmp(res->name, name) == 0)
            return res;
        res = res->next;
    }
    if (ctx->parent)
        return find_variable_by_name(ctx->parent, name);
    return find_global_variable_by_name(ctx, name);
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
    struct type *t = find_type_by(ctx, type->type, type->bits, type->sign);
    FATAL(t, "Type already registered: %s", type->name);

    type->id = ++ctx->ids;
    type->next = ctx->types;
    ctx->types = type;
}

void register_variable(struct gen_context *ctx, struct variable *var)
{
    struct variable *v = find_variable_by_name(ctx, var->name);
    FATAL(v, "Variable already registered: %s", var->name);

    var->id = ++ctx->ids;
    if (var->global) {
        var->next = ctx->globals;
        ctx->globals = var;
    } else {
        var->next = ctx->variables;
        ctx->variables = var;
    }
}

void register_builtin_types(struct gen_context *ctx)
{
    register_type(ctx, init_type("void", V_VOID, 0, 0));

    register_type(ctx, init_type("char", V_INT, 8, 1));
    register_type(ctx, init_type("unsigned char", V_INT, 8, 0));

    register_type(ctx, init_type("short", V_INT, 16, 1));
    register_type(ctx, init_type("unsigned short", V_INT, 16, 0));

    register_type(ctx, init_type("int", V_INT, 32, 1));
    register_type(ctx, init_type("unsigned int", V_INT, 32, 0));

    register_type(ctx, init_type("long", V_INT, 64, 1));
    register_type(ctx, init_type("unsigned long", V_INT, 64, 0));

    register_type(ctx, init_type("float", V_FLOAT, 64, 1));
}

struct gen_context *init_ctx(FILE *outfile, struct gen_context *parent)
{
    struct gen_context *res = calloc(1, sizeof(struct gen_context));
    res->f = outfile;
    res->regnum = 1;
    res->regnum_global = GLOBAL_START;
    res->pending_type = NULL;
    res->types = NULL;
    res->variables = NULL;
    res->globals = NULL;
    res->type = V_VOID;
    res->safe = 1;
    res->name = "__global_context";
    res->parent = parent;
    res->child = NULL;
    res->next = NULL;
    res->node = NULL;

    res->pre = buffer_init();
    res->init = buffer_init();
    res->data = buffer_init();
    res->post = buffer_init();

    if (!parent)
        register_builtin_types(res);
    return res;
}

void output_ctx(struct gen_context *ctx)
{
    if (ctx->global) {
        fprintf(ctx->f, "; Init\n%s\n", buffer_read(ctx->init));
        fprintf(ctx->f, "; Pre\n%s\n", buffer_read(ctx->pre));
    } else {
        fprintf(ctx->f, "; Pre\n%s\n", buffer_read(ctx->pre));
        fprintf(ctx->f, "; Init\n%s\n", buffer_read(ctx->init));
    }
    fprintf(ctx->f, "; Data\n%s\n", buffer_read(ctx->data));
    fprintf(ctx->f, "; Post\n%s\n", buffer_read(ctx->post));
}

void output_res(struct gen_context *ctx, int *got_main)
{
    struct gen_context *child = ctx->child;

    // Global
    if (strcmp(ctx->name, "main") == 0)
        *got_main = 1;
    output_ctx(ctx);
    while (child) {
        output_res(child, got_main);
        child = child->next;
    }
}

struct variable *new_variable(struct gen_context *ctx,
        const char *name, enum var_type type, int bits, int sign, int global)
{
    struct variable *res = calloc(1, sizeof(struct variable));

    res->id = ++ctx->ids;
    // Float and fixed are always signed
    if (type == V_FLOAT)
        sign = 1;
    if (global)
        res->reg = ctx->regnum_global++;
    else
        res->reg = ctx->regnum++;

    // If bits == 0 and we have a pendign type, use it
    if (bits == 0 && ctx->pending_type) {
        type = ctx->pending_type->type;
        bits = ctx->pending_type->bits;
        sign = ctx->pending_type->sign;
    } else if (type == V_VOID) {
        bits = 0;
        sign = 0;
    } else if (bits == 0 || type == V_FLOAT) {
        // TODO Fix float bits
        if (type == V_FLOAT)
            bits = 64;
        else
            // Default to 32
            bits = 32;
        sign = 1;
    }
    res->name = name;
    res->name_hash = hash(name);
    res->type = find_type_by(ctx, type, bits, sign);
    FATAL(!res->type, "Didn't find type!");
    res->global = global;
    if (res->global) {
        res->next = ctx->globals;
        ctx->globals = res;
    } else {
        res->next = ctx->variables;
        ctx->variables = res;
    }


    return res;
}

struct variable *new_inst_variable(struct gen_context *ctx,
        enum var_type type, int bits, int sign)
{
    struct variable *res = new_variable(ctx, NULL, type, bits, sign, 0);
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
        val = new_variable(ctx, NULL, V_FLOAT, v->type->bits, 1, 0);
        buffer_write(ctx->data, "%%%d = sitofp i%d %%%d to double\n",
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
    if (ctx->global) {
        buffer_write(ctx->init, "%s%d = global i%d 0, align 4\n",
            "@G", reg, bits);
    } else {
        buffer_write(ctx->init, "%%%d = alloca i%d, align 4\n",
            reg, bits);
    }
    return reg;
}

int gen_allocate_double(struct gen_context *ctx, int reg)
{
    if (ctx->global) {
        buffer_write(ctx->init, "%s%d = global double 0.0, align 8\n",
            "@G", reg);
    } else {
        buffer_write(ctx->init, "%s%d = alloca double, align 8\n",
            ctx->global ? "@G" : "%%", reg);
    }
    return reg;
}

int gen_store_int(struct gen_context *ctx, struct node *n)
{
    if (!n)
        ERR("No valid node given!");
    struct variable *val = new_variable(ctx, NULL, V_INT, n->bits, n->value < 0, ctx->global);
    gen_allocate_int(ctx, val->reg, val->type->bits);

    buffer_write(ctx->data, "store i%d %llu, i%d* %s%d, align 4\n",
            val->type->bits, n->value, val->type->bits, REGP(val), val->reg);
    return val->reg;
}

int gen_store_int_lit(struct gen_context *ctx, literalnum value)
{
    struct variable *val = new_variable(ctx, NULL, V_INT, 32, value < 0, ctx->global);
    gen_allocate_int(ctx, val->reg, val->type->bits);

    if (val->global) {
        buffer_write(ctx->init, "@G%d = global i%d %lld, align 4\n",
                val->reg, val->type->bits, value);
    } else {
        buffer_write(ctx->data, "store i%d %llu, i%d* %%%d, align 4\n",
                val->type->bits, value, val->type->bits, val->reg);
    }
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
    struct variable *val = new_variable(ctx, NULL, V_FLOAT, n->bits, 1, ctx->global);
    gen_allocate_double(ctx, val->reg);

    char *tmp = double_str(n->value, n->fraction);

    buffer_write(ctx->data, "store double %s, double* %s%d, align 8\n",
            tmp, REGP(val), val->reg);
    return val->reg;
}

struct variable *gen_load_int(struct gen_context *ctx, struct variable *v)
{
    if (v->direct)
        return v;
    struct variable *res = new_variable(ctx, NULL, V_INT, v->type->bits, 0, 0);

    buffer_write(ctx->data, "%%%d = load i%d, i%d* %s%d, align 4\n",
            res->reg, res->type->bits, res->type->bits, REGP(v), v->reg);
    return res;
}

struct variable *gen_load_float(struct gen_context *ctx, struct variable *v)
{
    if (v->direct)
        return v;
    struct variable *res = new_variable(ctx, NULL, V_FLOAT, v->type->bits, 1, 0);

    buffer_write(ctx->data, "%%%d = load double, double* %s%d, align 8\n",
            res->reg, REGP(v), v->reg);
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
        buffer_write(ctx->data, "%%%d = sext i%d %%%d to i%d\n",
            res->reg, bits1, v1->reg, bits2);
    } else {
        buffer_write(ctx->data, "%%%d = zext i%d %%%d to i%d\n",
            res->reg, bits1, v1->reg, bits2);
    }
    return res;
}

enum var_type get_and_cast(struct gen_context *ctx, struct variable **v1, struct variable **v2)
{
    FATAL(!*v1, "Can't load v1 in cast");
    *v1 = gen_load(ctx, *v1);
    FATAL(!*v2, "Can't load v2 in cast");
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
        buffer_write(ctx->data, "%%%d = add i%d %%%d, %%%d\n",
            res->reg, v1->type->bits, v1->reg, v2->reg);
    } else if (restype == V_FLOAT) {
        buffer_write(ctx->data, "%%%d = fadd double %%%d, %%%d\n",
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
        buffer_write(ctx->data, "%%%d = sub i%d %%%d, %%%d\n",
            res->reg, v1->type->bits, v1->reg, v2->reg);
    } else if (restype == V_FLOAT) {
        buffer_write(ctx->data, "%%%d = fsub double %%%d, %%%d\n",
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
        buffer_write(ctx->data, "%%%d = mul i%d %%%d, %%%d\n",
            res->reg, v1->type->bits, v1->reg, v2->reg);
    } else if (restype == V_FLOAT) {
        buffer_write(ctx->data, "%%%d = fmul double %%%d, %%%d\n",
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
            buffer_write(ctx->data, "%%%d = sdiv i%d %%%d, %%%d\n",
                res->reg, v1->type->bits, v1->reg, v2->reg);
        } else {
            buffer_write(ctx->data, "%%%d = udiv i%d %%%d, %%%d\n",
                res->reg, v1->type->bits, v1->reg, v2->reg);
        }
    } else if (restype == V_FLOAT) {
        buffer_write(ctx->data, "%%%d = fdiv double %%%d, %%%d\n",
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
            buffer_write(ctx->data, "%%%d = srem i%d %%%d, %%%d\n",
                res->reg, v1->type->bits, v1->reg, v2->reg);
        } else {
            buffer_write(ctx->data, "%%%d = urem i%d %%%d, %%%d\n",
                res->reg, v1->type->bits, v1->reg, v2->reg);
        }
    } else if (restype == V_FLOAT) {
        buffer_write(ctx->data, "%%%d = frem double %%%d, %%%d\n",
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
        buffer_write(ctx->data, "%%%d = sub i%d %%%d, %%%d\n",
            res->reg, v->type->bits, zero->reg, v->reg);
    } else if (v->type->type == V_FLOAT) {
        res = new_inst_variable(ctx, v->type->type, v->type->bits, 1);
        buffer_write(ctx->data, "%%%d = fneg double %%%d\n",
            res->reg, v->reg);
    } else
        ERR("Invalid type of %d: %d", a, v->type->type);

    return res->reg;
}

int gen_type(struct gen_context *ctx, struct node *node)
{
    struct type *t = find_type_by(ctx, node->type, node->bits, node->sign);
    if (t == NULL)
        ERR("Couldn't find type: %s", node->value_string);

    ctx->pending_type = t;

    return REF_CTX(t->id);
}

int gen_identifier(struct gen_context *ctx, struct node *node)
{
    struct variable *var = find_variable_by_name(ctx, node->value_string);
    int res;
    if (var == NULL) {
        // Utilize pending type from previous type def
        FATAL(!ctx->pending_type, "Can't determine type of variable %s", node->value_string);
        struct type *t = ctx->pending_type;
        switch (t->type) {
            case V_INT:
                var = new_variable(ctx, node->value_string, V_INT, t->bits, 0, ctx->global);
                var->global = ctx->global;
                res = gen_allocate_int(ctx, var->reg, var->type->bits);
                break;
            case V_FLOAT:
                var = new_variable(ctx, node->value_string, V_FLOAT, t->bits, 1, ctx->global);
                var->global = ctx->global;
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
    FATAL(!src_val, "Can't assign from zero: %d", right);
    struct variable *src = gen_load(ctx, src_val);
    struct variable *dst = find_variable(ctx, left);

    FATAL(!src, "No source in assign")
    FATAL(!dst, "No dest in assign: %d", left)

    if (src->type->type == V_INT) {
        buffer_write(ctx->data, "store i%d %%%d, i%d* %s%d, align 4\n",
                src->type->bits, src->reg, dst->type->bits, REGP(dst), dst->reg);
    } else
        ERR("Invalid assign");
    return dst->reg;
}

void gen_pre(struct gen_context *ctx, struct node *node)
{
    char *tmp = NULL;
    const char *type = var_str(node->type, node->bits, &tmp);
    buffer_write(ctx->pre, "define dso_local %s @%s() #0 {\n",
            type, ctx->name);
    if (tmp)
        free(tmp);
}

void gen_post(struct gen_context *ctx, struct node *node, int res)
{
    if (node && node->type != V_VOID) {
        char *tmp;
        struct variable *var = find_variable(ctx, res);
        FATAL(!var, "Invalid return variable: %d", res);
        if (!var->direct) {
            struct variable *tmp = gen_load(ctx, var);
            res = tmp->reg;
        }

        const char *type = var_str(node->type, node->bits, &tmp);
        buffer_write(ctx->post, "ret %s %%%d\n", type, res);
        if (tmp)
            free(tmp);
    }
    buffer_write(ctx->post, "}\n");
}


int gen_recursive(struct gen_context *ctx, struct node *node);
int gen_function(struct gen_context *ctx, struct node *node)
{
    struct gen_context *func_ctx = init_ctx(ctx->f, ctx);

    FATAL(!node->left, "Missing function definition");

    int func_proto = gen_recursive(func_ctx, node->left);

    struct node *r = node->right;
    FATAL(!r, "Function body missing");
    struct node *name = r->left;
    FATAL(!name, "Function name missing");
    FATAL(name->node != A_IDENTIFIER, "Faulty function name");
    func_ctx->name = name->value_string;

    // Need tod find from parent context
#if 0

    FATAL(!v, "No proto variable: %d", func_proto);
    FATAL(!v->type, "No proto type");
#else
    (void)func_proto;
#endif

    gen_pre(func_ctx, node->left);

    if (ctx->global && strcmp(func_ctx->name, "main") == 0) {
        struct node *node = ctx->node;
        if (node && node->type != V_VOID) {
            struct variable *ret = new_inst_variable(func_ctx, V_INT, 32, 1);
#if 0
            struct variable *ret = new_inst_variable(func_ctx, V_VOID, 0, 0);
            char *tmp;
            struct variable *var = find_variable(ctx, res);
            FATAL(!var, "Invalid return variable: %d", res);
            if (!var->direct) {
                struct variable *tmp = gen_load(ctx, var);
                res = tmp->reg;
            }

            const char *type = var_str(node->type, node->bits, &tmp);
            buffer_write(func_ctx->data, "%%%d = call %s @%s()\n", ret->reg, type, ctx->name);
            buffer_write(func_ctx->data, "ret %s %%%d \n", type, ret->reg);
            if (tmp)
                free(tmp);
#endif
            //FIXME i32
            buffer_write(func_ctx->init, "%%%d = call i32 @%s()\n", ret->reg, ctx->name);
        } else {
#if 0
        struct variable *global_res = new_inst_variable(func_ctx, V_VOID, 0, 0);
        buffer_write(func_ctx->init, "%%%d = invoke void %s()\n", global_res->reg, ctx->name);
#endif
            buffer_write(func_ctx->init, "call void @%s()\n", ctx->name);
        }
    }

    int res = gen_recursive(func_ctx, node->right);

    gen_post(func_ctx, NULL, res);

    func_ctx->next = ctx->child;
    ctx->child = func_ctx;

    return 0;
}

int gen_return(struct gen_context *ctx, struct node *node, int left, int right)
{
    if (!left && !right)
        return 0;
    int res = 0;
    struct variable *var;
    if (right)
        var = find_variable(ctx, right);
    else
        var = find_variable(ctx, left);

    if (!var->direct) {
        struct variable *tmp = gen_load(ctx, var);
        res = tmp->reg;
    } else
        res = var->reg;

    char *tmp;
    const char *type = var_str(var->type->type, var->type->bits, &tmp);
    buffer_write(ctx->data, "ret %s %%%d\n", type, res);
    if (tmp)
        free(tmp);

    return res;
#if 0
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
#endif
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

    if (node->node == A_FUNCTION)
        return gen_function(ctx, node);
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
        //case A_FUNCTION:
            //return gen_function(ctx, node, resleft, resright);
        case A_RETURN:
            return gen_return(ctx, node, resleft, resright);
        case A_ASSIGN:
            return gen_assign(ctx, node, resleft, resright);
        case A_DECLARATION:
            return gen_declaration(ctx, node, resleft, resright);
        default:
            ERR("Unknown node in code gen: %s", node_str(node));
    }
    return 0;
}

struct gen_context *fake_main(struct gen_context *ctx, struct node *node, int res)
{
    struct gen_context *main_ctx = init_ctx(ctx->f, ctx);
    main_ctx->name = "main";

    gen_pre(main_ctx, node);
    if (node && node->type != V_VOID) {
        struct variable *ret = new_inst_variable(main_ctx, V_VOID, 0, 0);
        char *tmp;
        struct variable *var = find_variable(ctx, res);
        FATAL(!var, "Invalid return variable: %d", res);
        if (!var->direct) {
            struct variable *tmp = gen_load(ctx, var);
            res = tmp->reg;
        }

        const char *type = var_str(node->type, node->bits, &tmp);
        buffer_write(main_ctx->data, "%%%d = call %s @%s()\n", ret->reg, type, ctx->name);
        buffer_write(main_ctx->data, "ret %s %%%d \n", type, ret->reg);
        if (tmp)
            free(tmp);
    } else {
        buffer_write(main_ctx->data, "call void @%s()\n", ctx->name);
        buffer_write(main_ctx->data, "ret i32 0 \n");
    }
    gen_post(main_ctx, NULL, res);

    main_ctx->next = ctx->child;
    ctx->child = main_ctx;
    return main_ctx;
}

int codegen(FILE *outfile, struct node *node)
{
    FATAL(!node, "Didn't get a node!");
    struct gen_context *ctx = init_ctx(outfile, NULL);
    int res;
    int got_main = 0;

    ctx->global = 1;
    ctx->node = node;

    gen_pre(ctx, node);
    res = gen_recursive(ctx, node);
    gen_post(ctx, node, res);

    output_res(ctx, &got_main);
    if (!got_main) {
        struct gen_context *main_ctx = fake_main(ctx, node, res);
        output_ctx(main_ctx);
    }

    return res;
}
