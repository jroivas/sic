#include "cg.h"
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
    int ptr;
    int addr;
    int strlen;
    int bits;
    struct type *type;
    const char *name;
    hashtype name_hash;
    struct variable *next;
};

struct gen_context {
    FILE *f;
    int ids;
    int regnum;
    int labels;
    int last_label;
    int rets;
    int regnum_global;
    int type;
    int safe;
    int global;
    int pending_ptr;
    int strs;
    int null_var;
    int is_decl;
    const char *name;
    struct node *node;
    struct node *main_type;

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
    "void", "null", "i32", "double", "invalid"
};

struct type *resolve_return_type(struct gen_context *ctx, struct node *node, int reg);
int gen_reserve_label(struct gen_context *ctx);

char *stype_str(struct type *t)
{
    char *tmp = calloc(256, sizeof(char));
    snprintf(tmp, 255, "%s, %d bits, %ssigned", type_str(t->type), t->bits, t->sign ? "" : "un");
    return tmp;
}

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

int align(int bits)
{
    if (bits == 0)
        return 4;
    if (bits >= 128)
        return 16;
    if (bits >= 64)
        return 8;
    if (bits >= 32)
        return 4;
    if (bits >= 16)
        return 2;
    return 1;
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

int same_type(struct type *a, struct type *b)
{
    if (a->type == V_VOID && b->type == V_VOID)
        return 1;
    if (a->type == V_STR && b->type == V_STR)
        return 1;
    if (a->type != b->type)
        return 0;
    if (a->type == V_FLOAT)
        return 1;
    return a->bits == b->bits && a->sign == b->sign;
}

struct type *find_type_by(struct gen_context *ctx, enum var_type type, int bits, int sign)
{
    struct type *res = ctx->types;
    while (res) {
#if DEBUG
        if (res->type == type)
            printf("Typecheck: %d == %d, %d == %d, %s\n", res->bits, bits, res->sign, sign, type_str(type));
#endif
        if (res->type == type && (res->bits == bits || bits == 0 || res->bits == 0) && res->sign == sign)
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
    if (ctx->parent)
        return find_variable(ctx->parent, reg);
    return NULL;
}

void dump_variables(struct gen_context *ctx)
{
    struct variable *var = ctx->variables;
    while (var != NULL) {
        printf("var %d: reg %d, direct: %d, global: %d, "
            "ptr: %d, addr: %d, strlen: %d, bits: %d, "
            "type: 0x%p, name: %s\n",
            var->id, var->reg,
            var->direct, var->global,
            var->ptr, var->addr, var->strlen, var->bits,
            (void*)var->type, var->name);
        var = var->next;
    }
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

    register_type(ctx, init_type("bool", V_INT, 1, 0));

    register_type(ctx, init_type("char", V_INT, 8, 1));
    register_type(ctx, init_type("unsigned char", V_INT, 8, 0));

    register_type(ctx, init_type("short", V_INT, 16, 1));
    register_type(ctx, init_type("unsigned short", V_INT, 16, 0));

    register_type(ctx, init_type("int", V_INT, 32, 1));
    register_type(ctx, init_type("unsigned int", V_INT, 32, 0));

    register_type(ctx, init_type("long", V_INT, 64, 1));
    register_type(ctx, init_type("unsigned long", V_INT, 64, 0));

    register_type(ctx, init_type("float", V_FLOAT, 64, 1));

    register_type(ctx, init_type("strgin", V_STR, 0, 0));
}

struct gen_context *init_ctx(FILE *outfile, struct gen_context *parent)
{
    struct gen_context *res = calloc(1, sizeof(struct gen_context));
    res->f = outfile;
    res->regnum = 1;
    res->labels = 1;
    res->last_label = 0;
    res->rets = 0;
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
    res->strs = 0;

    res->pre = buffer_init();
    res->init = buffer_init();
    res->data = buffer_init();
    res->post = buffer_init();

    if (!parent)
        register_builtin_types(res);

#if 1
    if (!parent) {
        struct type *null_type = init_type("nulltype", V_NULL, 0, 0);
        register_type(res, null_type);
        struct variable *null_var = init_variable("NULL", null_type);

        register_variable(res, null_var);
        res->null_var = null_var->reg;
    } else {
        res->null_var = parent->null_var;
    }
#endif
    return res;
}

void output_ctx(struct gen_context *ctx)
{
    if (ctx->global) {
        fprintf(ctx->f, "; Init - %s\n%s\n", ctx->name, buffer_read(ctx->init));
        fprintf(ctx->f, "; Pre - %s\n%s\n", ctx->name, buffer_read(ctx->pre));
    } else {
        fprintf(ctx->f, "; Pre - %s\n%s\n", ctx->name, buffer_read(ctx->pre));
        fprintf(ctx->f, "; Init - %s\n%s\n", ctx->name, buffer_read(ctx->init));
    }
    fprintf(ctx->f, "; Data - %s\n%s\n", ctx->name, buffer_read(ctx->data));
    fprintf(ctx->f, "; Post - %s\n%s\n", ctx->name, buffer_read(ctx->post));
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
        const char *name, enum var_type type, int bits, int sign, int ptr, int addr, int global)
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
    } else if (type != V_STR && (bits == 0 || type == V_FLOAT)) {
        // TODO Fix float bits
        if (type == V_FLOAT)
            bits = 64;
        else
            // Default to 32
            bits = 32;
        sign = 1;
    }
    res->ptr = ptr;
    res->addr = addr;
    res->name = name;
    res->name_hash = hash(name);
    res->type = find_type_by(ctx, type, bits, sign);
    res->bits = bits;
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
    struct variable *res = new_variable(ctx, NULL, type, bits, sign, 0, 0, 0);
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

struct variable *gen_cast(struct gen_context *ctx, struct variable *v, struct type *target, int force)
{
    FATAL(!v, "Invalid cast!");
    FATAL(!target, "No target type");
    if (!force && v->type->type == target->type)
        return v;
    if (target->bits == 0)
        target->bits = 32;

    struct variable *val = NULL;
    if (target->type == V_FLOAT && v->type->type == V_INT) {
        buffer_write(ctx->data, "; b\n");
        val = new_variable(ctx, NULL, V_FLOAT, v->type->bits, 1, 0, 0, 0);
        buffer_write(ctx->data, "%%%d = sitofp i%d %%%d to double\n",
                val->reg, v->type->bits, v->reg);
        val->direct = 1;
    } else if (!force) {
        ERR("Invalid cast for %d, %d -> %d",
            v->reg, v->type->type, target->type);
    } else {
        if (target->type == V_INT && v->type->type == V_FLOAT) {
            val = new_inst_variable(ctx, V_INT, target->bits, target->sign);
            if (target->sign) {
                buffer_write(ctx->data, "%%%d = fptosi double %%%d to i%d\n",
                    val->reg, v->reg, target->bits);
            } else {
                buffer_write(ctx->data, "%%%d = fptoui double %%%d to i%d\n",
                    val->reg, v->reg, target->bits);
            }
        } else if (target->type == V_INT && v->type->type == V_INT) {
            if (target->bits >= v->type->bits)
                return v;
            val = new_inst_variable(ctx, V_INT, target->bits, target->sign);
            buffer_write(ctx->data, "%%%d = trunc i%d %%%d to i%d\n",
                val->reg, v->type->bits, v->reg, target->bits);
        }
        else if (v->type->type == target->type)
            return v;
        else if (v->type->type == V_NULL && target->type == V_INT) {
#if 0
            val = new_inst_variable(ctx, V_INT, target->bits, target->sign);
            //buffer_write(ctx->data, "%%%d = sitofp i%d %%%d to double\n",
            buffer_write(ctx->data, "store i%d 0, i%d* %%%d; CAST NULL\n",
                    val->type->bits, val->type->bits, val->reg);
            val->direct = 1;
#endif
            return NULL;
        }
    }

    FATAL(!val, "Cast failed: %d -> %d, %d", v->type->type, target->type, force);

    return val;
}

int gen_allocate_int(struct gen_context *ctx, int reg, int bits, int ptr, int code_alloc)
{
    if (ctx->global) {
        FATAL(ptr, "Global pointer not supported");
        buffer_write(ctx->init, "%s%d = global i%d 0, align %d\n",
            "@G", reg, bits, align(bits));
    } else {
        char *tmp = get_stars(ptr);
        FATAL(!bits, "Invalid int type: reg %d, bits %d, ptr %d", reg, bits, ptr);
        buffer_write(code_alloc ? ctx->data : ctx->init, "%%%d = alloca i%d%s, align %d\n",
            reg, bits, ptr ? tmp : "", align(bits));
        buffer_write(code_alloc ? ctx->data : ctx->init,
            "store i%d%s %s, i%d%s* %%%d, align %d\n",
            bits, ptr ? tmp : "" , ptr ? "null" : "0", bits, ptr ? tmp : "", reg, align(bits)
            );
        if (tmp)
            free(tmp);
    }
    return reg;
}

int gen_allocate_double(struct gen_context *ctx, int reg, int ptr, int code_alloc)
{
    if (ctx->global) {
        buffer_write(ctx->init, "%s%d = global double 0.0, align %d\n",
            "@G", reg, align(64));
    } else {
        char *tmp = get_stars(ptr);
        buffer_write(ctx->init, "%s%d = alloca double%s, align %d\n",
            ctx->global ? "@G" : "%", reg, ptr ? tmp : "", align(64));
        buffer_write(code_alloc ? ctx->data : ctx->init,
            "store double%s %s, double%s* %%%d, align %d\n",
            ptr ? tmp : "" , ptr ? "null" : "0.0", ptr ? tmp : "", reg, align(64)
            );
    }
    return reg;
}

int gen_prepare_store_int(struct gen_context *ctx, struct node *n)
{
    if (!n)
        ERR("No valid node given!");
    struct variable *val = new_variable(ctx, NULL, V_INT, n->bits, n->value < 0, 0, 0, ctx->global);
    /*
     * It might be we haven't been able to determine bits so far.
     * However we need to have it now since alloc will need bits
     * or it will fail otherwise.
     */
    if (val->type->bits == 0)
        val->type->bits = 32;
    gen_allocate_int(ctx, val->reg, val->type->bits, 0, 0);
    n->reg = val->reg;
    return val->reg;
}

int gen_prepare_store_str(struct gen_context *ctx, struct node *n)
{
    if (!n)
        ERR("No valid node given!");
#if 0

    struct gen_context *glob = ctx;
    while (glob && !glob->global && glob->parent)
        glob = glob->parent;
    FATAL(!glob || !glob->global, "No global context found!");
    glob->strs++;
    buffer_write(glob->init, "@.str.%d = private unnamed_addr "
        "constant [%u x i8] c\"%s\\00\", align 1\n",
        glob->strs, strlen(n->value_string) + 1,
        n->value_string);
    n->strnum = glob->strs;
#endif
    struct gen_context *glob = ctx;
    while (glob && !glob->global && glob->parent)
        glob = glob->parent;
    FATAL(!glob || !glob->global, "No global context found!");

    int slen = strlen(n->value_string) + 1;
    struct variable *val = new_variable(glob, NULL, V_STR, slen, 0, 0, 0, 1);

    buffer_write(glob->init, "@.str.%d = private unnamed_addr "
        "constant [%u x i8] c\"%s\\00\", align 1\n",
        val->reg, slen, n->value_string);

    n->reg = val->reg;
    return val->reg;
}

int gen_prepare_store_double(struct gen_context *ctx, struct node *n)
{
    if (!n)
        ERR("No valid node given!");
    struct variable *val = new_variable(ctx, NULL, V_FLOAT, n->bits, 1, 0, 0, ctx->global);
    gen_allocate_double(ctx, val->reg, 0, 0);
    n->reg = val->reg;
    return val->reg;
}

int gen_store_int(struct gen_context *ctx, struct node *n)
{
    if (!n)
        ERR("No valid node given!");
    FATAL(!n->reg, "No register allocated!");
    struct variable *val = find_variable(ctx, n->reg);

    buffer_write(ctx->data, "store i%d %llu, i%d* %s%d, align %d\n",
            val->type->bits, n->value, val->type->bits, REGP(val), val->reg, align(val->type->bits));
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
    FATAL(!n->reg, "No register allocated!");
    struct variable *val = find_variable(ctx, n->reg);

    char *tmp = double_str(n->value, n->fraction);

    buffer_write(ctx->data, "store double %s, double* %s%d, align %d\n",
            tmp, REGP(val), val->reg, align(val->type->bits));
    return val->reg;
}

int gen_store_string(struct gen_context *ctx, struct node *n)
{
    struct variable *val = find_variable(ctx, n->reg);
    FATAL(!val, "No string allocated! %d", n->reg);
    return val->reg;
}

struct variable *gen_load_int(struct gen_context *ctx, struct variable *v)
{
    if (v->direct)
        return v;
    struct variable *prev = NULL;
    int reg = v->reg;

    if (v->ptr || v->addr) {
        char *tmp = get_stars(v->ptr);
        prev = new_variable(ctx, NULL, V_INT, v->type->bits, 0, 0, 0, 0);
        buffer_write(ctx->data, "%%%d = load i%d%s, i%d*%s %s%d, align %d ; %d\n",
                prev->reg, prev->type->bits,
                tmp ? tmp : "",
                prev->type->bits,
                tmp ? tmp : "",
                REGP(v), reg, align(prev->type->bits), v->addr);
        prev->ptr = v->ptr;
        prev->addr = v->addr;
        prev->direct = 1;
        if (tmp)
            free(tmp);
        return prev;
    }
#if 0
    for (int i = v->ptr; i > 0; i--) {
        char *tmp = get_stars(i);
        prev = new_variable(ctx, NULL, V_INT, v->type->bits, 0, 0, 0);
        buffer_write(ctx->data, "%%%d = load i%d%s, i%d*%s %s%d, align %d\n",
                prev->reg, prev->type->bits,
                tmp ? tmp : "", 
                prev->type->bits,
                tmp ? tmp : "", 
                REGP(v), reg, align(prev->type->bits));
        if (tmp)
            free(tmp);
        reg = prev->reg;
    }
#endif
    struct variable *res = new_variable(ctx, NULL, V_INT, v->type->bits, 0, 0, 0, 0);

    buffer_write(ctx->data, "%%%d = load i%d, i%d* %s%d, align %d\n",
            res->reg, res->type->bits, res->type->bits,
            REGP(v), reg, align(res->type->bits));
    res->ptr = v->ptr;
    res->addr = v->addr;
    res->direct = 1;
    return res;
}

struct variable *gen_load_float(struct gen_context *ctx, struct variable *v)
{
    if (v->direct)
        return v;
    struct variable *res = new_variable(ctx, NULL, V_FLOAT, v->type->bits, 1, 0, 0, 0);

    buffer_write(ctx->data, "%%%d = load double, double* %s%d, align %d\n",
            res->reg, REGP(v), v->reg, align(v->type->bits));
    res->direct = 1;
    return res;
}

struct variable *gen_load_str(struct gen_context *ctx, struct variable *v)
{
    return v;
#if 0
    if (v->direct)
        return v;
    struct variable *res = new_variable(ctx, NULL, V_FLOAT, v->type->bits, 1, 0, 0);

    buffer_write(ctx->data, "%%%d = load double, double* %s%d, align %d\n",
            res->reg, REGP(v), v->reg, align(v->type->bits));
    return res;
#endif
}

struct variable *gen_load(struct gen_context *ctx, struct variable *v)
{
    if (v == NULL)
        ERR("Can't load null!");
    if (v->type->type == V_INT)
        return gen_load_int(ctx, v);
    else if (v->type->type == V_FLOAT)
        return gen_load_float(ctx, v);
    else if (v->type->type == V_STR)
        return gen_load_str(ctx, v);
    else if (v->type->type == V_NULL)
        return v;
    else if (v->type->type == V_VOID)
        return v;

    ERR("Invalid type: %d", v->type->type);
}

struct variable *gen_bits_cast(struct gen_context *ctx, struct variable *v1, int bits2, int sign2)
{
    int bits1 = v1->type->bits;
    if (bits1 == bits2)
        return v1;
    if (bits1 > bits2)
        return v1;

    FATAL(v1->global, "Can't cast from global");
    struct variable *res = new_inst_variable(ctx, V_INT, bits2, v1->type->sign || sign2);
    if (sign2) {
        buffer_write(ctx->data, "%%%d = sext i%d %%%d to i%d\n",
            res->reg, bits1, v1->reg, bits2);
    } else {
        buffer_write(ctx->data, "%%%d = zext i%d %%%d to i%d\n",
            res->reg, bits1, v1->reg, bits2);
    }
    return res;
}

struct variable *gen_bits(struct gen_context *ctx, struct variable *v1, struct variable *v2)
{
    return gen_bits_cast(ctx, v1, v2->type->bits, v2->type->sign);
}

enum var_type get_and_cast(struct gen_context *ctx, struct variable **v1, struct variable **v2)
{
    FATAL(!*v1, "Can't load v1 in cast");
    *v1 = gen_load(ctx, *v1);
    FATAL(!*v2, "Can't load v2 in cast");
    *v2 = gen_load(ctx, *v2);

    enum var_type restype = resolve_type((*v1)->type->type, (*v2)->type->type);
    struct type *target = find_type_by(ctx, restype, 0, 1);
    FATAL(!target, "No target in cast");
    *v1 = gen_cast(ctx, *v1, target, 0);
    *v2 = gen_cast(ctx, *v2, target, 0);

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

int gen_eq(struct gen_context *ctx, struct node *node, int a, int b)
{
    struct variable *v1 = find_variable(ctx, a);
    struct variable *v2 = find_variable(ctx, b);
    FATAL(!v1, "No cmp1 var");
    FATAL(!v2, "No cmp2 var");
    v1 = gen_load(ctx, v1);
    v2 = gen_load(ctx, v2);
/*
    struct variable *res = find_variable(ctx, b);
    enum var_type restype = get_and_cast(ctx, &v1, &v2);

    res = new_inst_variable(ctx, V_INT, var->type->bits, var->type->sign);
*/
    //struct variable *res = new_inst_variable(ctx, V_INT, 1, 0);

    FATAL(!v1, "No cmp1 var");
    FATAL(!v2, "No cmp2 var");

    if (v1->type->type == V_INT && v2->type->type == V_INT) {
        if (v1->type->bits == v2->type->bits);
        else if (v1->type->bits > v2->type->bits)
            v2 = gen_bits_cast(ctx, v2, v1->bits, 1);
        else
            v1 = gen_bits_cast(ctx, v1, v2->bits, 1);

        struct variable *res = new_inst_variable(ctx, V_INT, 1, 0);
        char *stars1 = get_stars(v1->ptr);
        const char *op = node->node == A_EQ_OP ? "eq" : "ne";
        buffer_write(ctx->data, "%%%d = icmp %s i%d%s %%%d, "
            "%%%d\n",
            res->reg, op,
            v1->type->bits, stars1 ? stars1 : "", v1->reg,
            v2->reg);

        return res->reg;
    }
    else if (v1->type->type == V_FLOAT && v2->type->type == V_FLOAT) {
        struct variable *res = new_inst_variable(ctx, V_INT, 1, 0);
        char *stars1 = get_stars(v1->ptr);
        const char *op = node->node == A_EQ_OP ? "oeq" : "une";
        buffer_write(ctx->data, "%%%d = fcmp %s double %%%d%s, "
            "%%%d\n",
            res->reg, op,
            v1->reg, stars1 ? stars1 : "",
            v2->reg);

        return res->reg;
    }
    else if ((v1->type->type == V_INT && v2->type->type == V_NULL ) || (v1->type->type == V_NULL && v2->type->type == V_INT)) {
        struct variable *res = new_inst_variable(ctx, V_INT, 1, 0);
        if (v1->type->type == V_NULL)
            v1 = v2;

        FATAL(!v1->ptr, "Comparing non-pointer to NULL: %d, %d", v1->ptr, v2->ptr);

        char *stars1 = get_stars(v1->ptr);
        const char *op = node->node == A_EQ_OP ? "eq" : "ne";
        buffer_write(ctx->data, "%%%d = icmp %s i%d%s %%%d, null\n",
            res->reg, op,
            v1->type->bits, stars1 ? stars1 : "", v1->reg);
        return res->reg;
    }

    ERR("Invalid EQ: %s != %s", type_str(v1->type->type), type_str(v2->type->type));
/*
    printf("EQ: %d %s %d\n",
        a, node->node == A_EQ_OP ? "==" : "!=", b);
*/
    return 0;
}

int gen_negate(struct gen_context *ctx, int a)
{
    struct variable *v = find_variable(ctx, a);
    struct variable *res;

    FATAL(!v, "Can't negate zero");
    v = gen_load(ctx, v);
    if (v->type->type == V_INT) {
        res = new_inst_variable(ctx, v->type->type, v->type->bits, 1);
        buffer_write(ctx->data, "%%%d = sub i%d 0, %%%d\n",
            res->reg, v->type->bits, v->reg);
    } else if (v->type->type == V_FLOAT) {
        res = new_inst_variable(ctx, v->type->type, v->type->bits, 1);
        buffer_write(ctx->data, "%%%d = fsub double 0.0, %%%d\n",
            res->reg, v->reg);
    } else
        ERR("Invalid type of %d: %d", a, v->type->type);

    return res->reg;
}

int gen_type(struct gen_context *ctx, struct node *node)
{
    struct type *t = find_type_by(ctx, node->type, node->bits, node->sign);
    if (t == NULL)
        ERR("Couldn't find type: %s (%s, bits %d, %s", node->value_string, type_str(node->type), node->bits, node->sign ? "signed" : "unsigned");

    ctx->pending_type = t;

    return REF_CTX(t->id);
}

int gen_pointer(struct gen_context *ctx, struct node *node)
{
    if (ctx->pending_ptr)
        ERR("Unexpected pointer while handling pointer: %d", ctx->pending_ptr);
    ctx->pending_ptr = node->ptr;
    return 0;
}

int gen_use_ptr(struct gen_context *ctx)
{
    int res = ctx->pending_ptr;
    ctx->pending_ptr = 0;
    return res;
}

int gen_identifier(struct gen_context *ctx, struct node *node)
{
    struct variable *var = find_variable_by_name(ctx, node->value_string);
    int res;
    if (var == NULL) {
        // Utilize pending type from previous type def
        FATAL(!ctx->pending_type, "Can't determine type of variable %s", node->value_string);
        struct type *t = ctx->pending_type;
        int ptrval = 0;
        int addrval = 0;
        switch (t->type) {
            case V_INT:
                ptrval = gen_use_ptr(ctx);
                node->ptr = ptrval;
                node->addr = addrval;
                var = new_variable(ctx, node->value_string, V_INT, t->bits, 0, ptrval, addrval, ctx->global);
                var->global = ctx->global;
                var->addr = addrval;
                res = gen_allocate_int(ctx, var->reg, var->type->bits, var->ptr, 0);
                break;
            case V_FLOAT:
                ptrval = gen_use_ptr(ctx);
                node->ptr = ptrval;
                node->addr = addrval;
                var = new_variable(ctx, node->value_string, V_FLOAT, t->bits, 1, ptrval, addrval, ctx->global);
                var->global = ctx->global;
                res = gen_allocate_double(ctx, var->reg, var->ptr, 0);
                break;
            default:
                ERR("Invalid type for variable: %s", type_str(t->type));
                break;
        }
    } else {
            FATAL(ctx->is_decl >= 100 && ctx->is_decl < 102, "Redeclaring variable: %s (lvl %d)", node->value_string, ctx->is_decl);
            res = var->reg;
    }
    return res;
}

int gen_addr(struct gen_context *ctx, struct node *node, int reg)
{
    if (node->addr) {
        struct variable *var = find_variable(ctx, reg);
        FATAL(!var, "No variable to take address from!");

        char *dst = get_stars(var->ptr + node->addr + 1);
        char *src = get_stars(var->ptr + 1);
        struct variable *res = new_variable(ctx,
            NULL,
            var->type->type,
            var->type->bits, var->type->sign,
            var->ptr + node->addr,
            0, 0);

        gen_allocate_int(ctx, res->reg, res->type->bits, res->ptr, 1);
        if (var->type->type == V_INT) {
            buffer_write(ctx->data, "store i%d%s %%%d, i%d%s %s%d, align %d\n",
                res->type->bits,
                src ? src : "",
                reg,
                res->type->bits,
                dst ? dst : "",
                REGP(res),
                res->reg, align(res->type->bits)
                );
        } else if (var->type->type == V_FLOAT) {
            buffer_write(ctx->data, "store double %s %%%d, %s %s%d, align %d\n",
                src ? src : "",
                reg,
                dst ? dst : "",
                REGP(res),
                res->reg, align(res->type->bits)
                );
        } else
            ERR("Invalid type: %d", res->type->type);

        return res->reg;
    }
    return reg;
}

int get_identifier(struct gen_context *ctx, struct node *node)
{
    struct variable *var = find_variable_by_name(ctx, node->value_string);
    if (!var)
        return 0;
    FATAL(!var, "Variable not found in get_identitifier: %s", node->value_string);
    return var->reg;
}

int gen_assign(struct gen_context *ctx, struct node *node, int left, int right)
{
    struct variable *src_val = find_variable(ctx, right);
    FATAL(!src_val, "Can't assign from zero: %d to %d", right, left);
    struct variable *src = gen_load(ctx, src_val);
    struct variable *dst = find_variable(ctx, left);

    FATAL(!src, "No source in assign")
    FATAL(!dst, "No dest in assign: %d", left)

    if (src->ptr || src->addr) {
        char *tmp = get_stars(src->ptr);

        //dump_variables(ctx);
        buffer_write(ctx->data, "store i%d%s %%%d, i%d%s* %s%d, align %d\n",
                src->type->bits, tmp ? tmp : "", src->reg,
                dst->type->bits, tmp ? tmp : "",
                REGP(dst), dst->reg,
                align(dst->type->bits));
        return dst->reg;
    }

    if (src->type->type == V_INT) {
        buffer_write(ctx->data, "store i%d %%%d, i%d* %s%d, align %d\n",
                src->type->bits, src->reg, dst->type->bits, REGP(dst), dst->reg, align(dst->type->bits));
    } else if (src->type->type == V_FLOAT) {
        buffer_write(ctx->data, "store double %%%d, double* %s%d, align %d\n",
                src->reg, REGP(dst), dst->reg, align(dst->type->bits));
    } else if (src->type->type == V_STR) {
	    buffer_write(ctx->data, "store i8* getelementptr inbounds "
		"([%d x i8], [%d x i8]* @.str.%d, i32 0, i32 0), "
		"i8** %%%d, align 8\n",
		src_val->bits, src_val->bits, src->reg, dst->reg);
    } else if (src->type->type == V_VOID) {
        // TODO Void pointer
        return 0;
    } else
        ERR("Invalid assign");
    return dst->reg;
}

void gen_pre(struct gen_context *ctx, struct node *node)
{
    char *tmp = NULL;
    const char *type = NULL;
    if (ctx->main_type)
        type = var_str(ctx->main_type->type, ctx->main_type->bits, &tmp);
    else
        type = var_str(node->type, node->bits, &tmp);
    buffer_write(ctx->pre, "define dso_local %s @%s() #0 {\n",
            type, ctx->name);
    if (tmp)
        free(tmp);
}

void gen_post(struct gen_context *ctx, struct node *node, int res, struct type *target)
{
    if (target && target->type != V_VOID) {
        char *tmp = NULL;
        struct variable *var = find_variable(ctx, res);
        if (var && var->type->type != V_NULL) {
            if (!var->direct) {
                var = gen_load(ctx, var);
                FATAL(!var, "Invalid indirect return variable: %d", res);
                res = var->reg;
            }
            if (target->type != var->type->type || target->bits != var->type->bits) {
                var = gen_cast(ctx, var, target, 1);
                FATAL(!var, "Invalid cast");
                var = gen_bits_cast(ctx, var, node->bits, 1);
                res = var->reg;
            }
            const char *type = var_str(var->type->type, var->type->bits, &tmp);
            buffer_write(ctx->post, "ret %s %%%d ; RET1\n", type, res);
        } else {
            const char *type = var_str(node->type, node->bits, &tmp);
            buffer_write(ctx->post, "ret %s 0 ; RET2\n", type, res);
        }
        if (tmp)
            free(tmp);
    } else {
            buffer_write(ctx->post, "ret void ; RET4\n");
    }
#if 0
    if (node && node->type != V_VOID) {
        char *tmp = NULL;
        struct variable *var = find_variable(ctx, res);
        if (var) {
            FATAL(!var, "Invalid return variable (post): %d", res);
            if (!var->direct) {
                var = gen_load(ctx, var);
                FATAL(!var, "Invalid indirect return variable: %d", res);
                res = var->reg;
            }
            if (node->type != var->type->type || node->bits != var->type->bits) {
                //enum var_type restype = resolve_type(node->type, var->type->type);
                //enum var_type restype = node->type;

                //struct type *target = find_type_by(ctx, restype, 0, 1);
                FATAL(!target, "No target in post");
                var = gen_cast(ctx, var, target, 0);
                var = gen_bits_cast(ctx, var, node->bits, 1);
                printf("cast to: %d %d %d\n", var->type->type, var->type->bits, var->type->sign);
                res = var->reg;
            }
            const char *type = var_str(var->type->type, var->type->bits, &tmp);
            buffer_write(ctx->post, "ret %s %%%d\n", type, res);
        } else {
            const char *type = var_str(node->type, node->bits, &tmp);
            buffer_write(ctx->post, "ret %s 0\n", type, res);
        }
        if (tmp)
            free(tmp);
    }
#endif
    buffer_write(ctx->post, "}\n");
}


int gen_recursive_allocs(struct gen_context *ctx, struct node *node);
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
    struct node *functype = node->left;

    // Need tod find from parent context
#if 0

    FATAL(!v, "No proto variable: %d", func_proto);
    FATAL(!v->type, "No proto type");
#else
    (void)func_proto;
#endif

    gen_pre(func_ctx, node->left);

    struct node *func_node = NULL;
    struct type *target = calloc(1, sizeof(struct type));
    if (ctx->global && strcmp(func_ctx->name, "main") == 0) {
        func_node = ctx->node;
        if (func_node && functype->type != V_VOID) {
            /*
            func_node = calloc(1, sizeof(struct node));
            func_node->type = V_INT;
            func_node->bits = 32;
            func_node->sign = 1;
            */
            target->type = V_INT;
            target->bits = 32;
            target->sign = 1;
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
            /*
            func_node->type = V_VOID;
            func_node->bits = 0;
            func_node->sign = 0;
            */
            target->type = V_VOID;
            target->bits = 0;
            target->sign = 0;
        }
    }

    struct node *body = NULL;
    FATAL(node->right->node != A_GLUE, "Invalid function");

    body = node->right->right;
    FATAL(!body, "Invalid function body");

    int res = gen_recursive_allocs(func_ctx, body);
    res = gen_recursive(func_ctx, body);

    gen_post(func_ctx, func_node, res, target);

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
    struct type *target = resolve_return_type(ctx, ctx->node, res);
    if (right)
        var = find_variable(ctx, right);
    else
        var = find_variable(ctx, left);

    res = var->reg;

    if (!var->direct) {
        var = gen_load(ctx, var);
        FATAL(!var, "Invalid indirect return variable: %d", res);
        res = var->reg;
    }
    if (target->type != var->type->type || target->bits != var->type->bits) {
        var = gen_cast(ctx, var, target, 1);
        FATAL(!var, "Invalid cast");
        var = gen_bits_cast(ctx, var, target->bits, 1);
        res = var->reg;
    }
    char *tmp;
    const char *type = var_str(var->type->type, var->type->bits, &tmp);
    buffer_write(ctx->data, "ret %s %%%d ; RET3\n", type, res);
    ctx->rets++;

    return res;
}

int gen_declaration(struct gen_context *ctx, struct node *node, int left, int right)
{
    FATAL(left >= 0, "Invalid type definition in declaration");
    ctx->pending_type = NULL;
    return right;
}

int gen_cmp_bool(struct gen_context *ctx, struct variable *src)
{
    struct variable *var = gen_load(ctx, src);
    FATAL(!var, "Invalid variable for bool comparison");

    if (var->ptr) {
        struct variable *res = new_inst_variable(ctx, V_INT, var->type->bits, var->type->sign);
        char *stars = get_stars(var->ptr);

        buffer_write(ctx->data, "%%%d = icmp ne i%d%s %%%d, null\n",
            res->reg, res->type->bits,
            stars,
            var->reg);
        return res->reg;
    } else if (var->type->type == V_INT) {
        struct variable *res = new_inst_variable(ctx, V_INT, var->type->bits, var->type->sign);

        buffer_write(ctx->data, "%%%d = icmp ne i%d %%%d, 0\n",
            res->reg, res->type->bits,
            var->reg);
        return res->reg;
    } else if (var->type->type == V_FLOAT) {
        struct variable *res = new_inst_variable(ctx, V_FLOAT, var->type->bits, var->type->sign);

        buffer_write(ctx->data, "%%%d = fcmp une double %%%d, "
            "0.000000e+00\n",
            res->reg,
            var->reg);
        return res->reg;
    } else if (var->type->type == V_NULL) {
        printf("NULL CMP\n");
    }

    ERR("Invalid cmp to bool");

    return -1;
}

int gen_reserve_label(struct gen_context *ctx)
{
    return ctx->labels++;
}

int gen_if(struct gen_context *ctx, struct node *node)
{
    // Conditional clause on left
    FATAL(!node->left, "No conditional in if");

    int cond_reg = gen_recursive(ctx, node->left);
    struct variable *cond = find_variable(ctx, cond_reg);

    int cmp_reg = gen_cmp_bool(ctx, cond);

    struct buffer *cmpblock = buffer_init();
    struct buffer *ifblock = buffer_init();
    struct buffer *tmp = ctx->data;
    int inc = 0;
    int inc2 = 0;

    ctx->data = cmpblock;
    int label1 = gen_reserve_label(ctx);
    buffer_write(cmpblock, "L%d:\n", label1);
    if (node->mid) {
        int rets = ctx->rets;
        gen_recursive(ctx, node->mid);
        inc = rets < ctx->rets;
    }
    /* Hack to handle "unnamed" and unreachable branch */
    if (inc)
        ctx->regnum++;

    ctx->data = ifblock;
    int label2 = gen_reserve_label(ctx);
    buffer_write(ifblock, "L%d:\n", label2);
    if (node->right) {
        int rets = ctx->rets;
        gen_recursive(ctx, node->right);
        inc2 = rets < ctx->rets;
    } else {
        ctx->last_label = label2;
    }

    int label3 = ctx->last_label;
    if (!label3) {
        label3 = gen_reserve_label(ctx);
        /* There was return on previous branch, need to inc */
        if (inc2)
            ctx->regnum++;
        buffer_write(ifblock, "br label %%L%d\n", label3);
        buffer_write(ifblock, "L%d:\n", label3);
        ctx->last_label = label3;
    }

    ctx->data = tmp;
    buffer_write(ctx->data, "br i1 %%%d, label %%L%d, label %%L%d\n",
        cmp_reg, label1, label2);
    buffer_append(ctx->data, buffer_read(cmpblock));
    if (label2 != label3) {
        buffer_write(ctx->data, "br label %%L%d\n", label3);
    } else if (inc) {
        ctx->regnum--;
    }
    buffer_append(ctx->data, buffer_read(ifblock));

    buffer_del(cmpblock);
    buffer_del(ifblock);

    return 0;
}

// First pass to scan types and alloc
int gen_recursive_allocs(struct gen_context *ctx, struct node *node)
{
    if (node == NULL)
        return 0;

    if (node->node == A_FUNCTION)
        return 0;

    switch (node->node) {
        case A_TYPE:
            gen_type(ctx, node);
            break;
        case A_POINTER:
            gen_pointer(ctx, node);
            break;
        case A_IDENTIFIER:
            gen_identifier(ctx, node);
            break;
        case A_INT_LIT:
            gen_prepare_store_int(ctx, node);
            break;
        case A_DEC_LIT:
            gen_prepare_store_double(ctx, node);
            break;
        case A_STR_LIT:
            gen_prepare_store_str(ctx, node);
            break;
        case A_DECLARATION:
            ctx->is_decl = 100;
            break;
        case A_ASSIGN:
            /* If It's declaration, and assign increase is_decl since we're declaring a variable. */
            if (ctx->is_decl)
                ctx->is_decl++;
        default:
            break;
    }

    if (node->left)
        gen_recursive_allocs(ctx, node->left);
    /* After handling left side of assign we need to stop checking for variables since right side can't be declaration */
    if (node->node == A_ASSIGN)
            ctx->is_decl++;
    if (node->mid)
        gen_recursive_allocs(ctx, node->mid);
    if (node->right)
        gen_recursive_allocs(ctx, node->right);
    if (node->node == A_DECLARATION)
        ctx->is_decl = 0;
    return 0;
}

int gen_recursive(struct gen_context *ctx, struct node *node)
{
    int resleft = 0, resright = 0;
    if (node == NULL)
        return 0;

    /* Special cases */
    if (node->node == A_FUNCTION)
        return gen_function(ctx, node);
    if (node->node == A_IF)
        return gen_if(ctx, node);

    /* Recurse first to get children solved */
    if (node->left)
        resleft = gen_recursive(ctx, node->left);
    if (node->right)
        resright = gen_recursive(ctx, node->right);

    /* Then generate this node */
    switch (node->node) {
        case A_ADD:
            ctx->last_label = 0;
            return gen_add(ctx, resleft, resright);
        case A_MINUS:
            ctx->last_label = 0;
            return gen_sub(ctx, resleft, resright);
        case A_NEGATE:
            ctx->last_label = 0;
            return gen_negate(ctx, resleft);
        case A_MUL:
            ctx->last_label = 0;
            return gen_mul(ctx, resleft, resright);
        case A_DIV:
            ctx->last_label = 0;
            return gen_div(ctx, resleft, resright);
        case A_MOD:
            ctx->last_label = 0;
            return gen_mod(ctx, resleft, resright);
        case A_EQ_OP:
        case A_NE_OP:
            ctx->last_label = 0;
            return gen_eq(ctx, node, resleft, resright);
        case A_INT_LIT:
            ctx->last_label = 0;
            return gen_store_int(ctx, node);
        case A_DEC_LIT:
            ctx->last_label = 0;
            return gen_store_double(ctx, node);
        case A_STR_LIT:
            ctx->last_label = 0;
            return gen_store_string(ctx, node);
        case A_LIST:
        case A_GLUE:
            if (resright)
                return resright;
            if (resleft)
                return resleft;
            break;
        case A_TYPE:
            return gen_type(ctx, node);
        case A_POINTER:
            //return gen_pointer(ctx, node);
            return resleft;
        case A_ADDR:
            ctx->last_label = 0;
            return gen_addr(ctx, node, resleft);
        case A_IDENTIFIER:
            ctx->last_label = 0;
            return get_identifier(ctx, node);
        case A_RETURN:
            ctx->last_label = 0;
            return gen_return(ctx, node, resleft, resright);
        case A_ASSIGN:
            ctx->last_label = 0;
            return gen_assign(ctx, node, resleft, resright);
        case A_DECLARATION:
            return gen_declaration(ctx, node, resleft, resright);
        case A_NULL:
            return ctx->null_var;
        default:
            ERR("Unknown node in code gen: %s", node_str(node));
    }
    return 0;
}

struct gen_context *fake_main(struct gen_context *ctx, struct node *node, int res)
{
    struct gen_context *main_ctx = init_ctx(ctx->f, ctx);
    main_ctx->name = "main";
    struct node main_node;
    main_node.type = V_INT;
    main_node.bits = 32;

    gen_pre(main_ctx, &main_node);
    if (node && node->type != V_VOID) {
        char *tmp;
        struct variable *var = find_variable(ctx, res);
        FATAL(!var, "Invalid return variable (fake): %d", res);
        if (!var->direct) {
            var = gen_load(ctx, var);
            FATAL(!var, "Invalid indirect return variable: %d", res);
            res = var->reg;
        }
        struct variable *ret = new_inst_variable(main_ctx, var->type->type, var->type->bits, var->type->sign);

        const char *type = var_str(node->type, node->bits, &tmp);
        buffer_write(main_ctx->data, "%%%d = call %s @%s()\n", ret->reg, type, ctx->name);
        // TODO FIXME Hacks for type solving
        if (node->type != var->type->type || node->bits != var->type->bits) {
            struct type *target = find_type_by(main_ctx, V_INT, 32, 1);
            FATAL(!target, "No tarkget in global main");
            buffer_write(main_ctx->data, "; bits %d , %d\n", node->bits, ret->type->bits);
            if (node->bits > 0)
                ret->type->bits = node->bits;
            ret = gen_cast(main_ctx, ret, target, 1);
            if (ret)
                ret = gen_bits_cast(main_ctx, ret, target->bits, 1);
        }
        buffer_write(main_ctx->data, "ret i32 %%%d \n", ret->reg);
        if (tmp)
            free(tmp);
    } else {
        buffer_write(main_ctx->data, "call void @%s()\n", ctx->name);
        buffer_write(main_ctx->data, "ret i32 0 \n");
    }
#if 0
    struct type *target = calloc(1, sizeof(struct type));
    target->type = V_INT;
    target->bits = 32;
    target->sign = 1;
#endif
    gen_post(main_ctx, NULL, res, NULL);

    main_ctx->next = ctx->child;
    ctx->child = main_ctx;
    return main_ctx;
}

struct type *resolve_return_type(struct gen_context *ctx, struct node *node, int reg)
{
    struct type *res = calloc(1, sizeof(struct type));
    int got = 0;
    if (ctx->main_type) {
        if (ctx->main_type->type == V_VOID) {
            res->type = V_VOID;
            buffer_write(ctx->post, "; FV %s\n", stype_str(res));
            got = 1;
        } else {
            res->type = ctx->main_type->type;
            res->bits = ctx->main_type->bits;
            res->sign = ctx->main_type->sign;
            buffer_write(ctx->post, "; FM %s\n", stype_str(res));
            got = 1;
        }
    } else if (node && node->type != V_VOID) {
#if 0
        struct variable *var = find_variable(ctx, reg);
        if (var) {
            if (!var->direct) {
                var = gen_load(ctx, var);
                FATAL(!var, "Invalid indirect return variable: %d", reg);
            }
#if 0
            if (node->type != var->type->type || node->bits != var->type->bits) {
                enum var_type restype = resolve_type(node->type, var->type->type);
                struct type *target = find_type_by(ctx, restype, 0, 1);
                var = gen_cast(ctx, var, target, 0);
                var = gen_bits_cast(ctx, var, node->bits, 1);
            }
#endif
            if (res->type == node->type && res->bits >= node->bits) {
                res->type = var->type->type;
                res->bits = var->type->bits;
                res->sign = var->type->sign;
            } else {
                res->type = node->type;
                res->bits = node->bits;
                res->sign = node->sign;
            }
            got = 1;
        }
#else
        res->type = node->type;
        res->bits = node->bits;
        res->sign = node->sign;
        buffer_write(ctx->post, "; FF %s\n", stype_str(res));
        got = 1;
#endif

    }
    if (!got) {
        res->type = V_INT;
        res->bits = 32;
        res->sign = 1;
    }
    return res;
}

struct node *find_main_type(struct node *node)
{
    if (node->node == A_FUNCTION) {
        if (node->right && node->right->left) {
            if (strcmp(node->right->left->value_string, "main") == 0) {
                return node->left;
            }
        }
    }
    struct node *res = NULL;
    if (node->right)
        res = find_main_type(node->right);
    if (!res && node->left)
        res = find_main_type(node->left);
    return res;
}

int codegen(FILE *outfile, struct node *node)
{
    FATAL(!node, "Didn't get a node!");
    struct gen_context *ctx = init_ctx(outfile, NULL);
    int res;
    int got_main = 0;

    ctx->global = 1;
    ctx->node = node;
    ctx->main_type = find_main_type(node);

    gen_pre(ctx, node);
    res = gen_recursive_allocs(ctx, node);
    res = gen_recursive(ctx, node);
    struct type *target = resolve_return_type(ctx, node, res);
    buffer_write(ctx->post, "; F2 %s, %d\n", stype_str(target), target->type);
    gen_post(ctx, node, res, target);

    output_res(ctx, &got_main);
    if (!got_main) {
        struct gen_context *main_ctx = fake_main(ctx, node, res);
        output_ctx(main_ctx);
    }

    return res;
}
