#include "cg.h"
#include "parse.h"
#include "fatal.h"
#include "buffer.h"
#include <string.h>

#include <llvm-c/Analysis.h>
#include <llvm-c/Core.h>
#include <llvm-c/BitWriter.h>

#define GLOBAL_START 0x100000
#define REGP(X) (X->global) ? "@G" : "%"
static const char *global_ctx_name = "__global_context";

enum logical_op_type {
    LOGICAL_AND,
    LOGICAL_OR
};

enum vartype {
    VAR_NORMAL,
    VAR_DIRECT
};

enum looptype {
    LOOP_WHILE,
    LOOP_DO,
    LOOP_FOR
};

enum cast_opts {
    CAST_NORMAL = 0,
    CAST_FORCE = 1,
    CAST_FLATTEN_PTR = 2,
    CAST_NO_LOAD_STRUCT = 4,
};

enum generated_variables {
    GEN_NONE,
    GEN_FUNCTION = 1 << 0,
    GEN_PRETTY_FUNCTION = 1 << 1,
};

enum builtin_function {
    BUILTIN_NONE = 0,
    BUILTIN_VA_START,
    BUILTIN_VA_ARG,
    BUILTIN_VA_END,
    BUILTIN_BSWAP16,
    BUILTIN_BSWAP32,
    BUILTIN_BSWAP64,
};

struct type {
    int id;
    enum var_type type;
    enum type_sign sign;
    int bits;
    int array_size;
    int ptr;
    int is_const;
    int is_extern;
    int is_static;
    int is_inline;
    int temporary;
    int forward;
    int opaque;

    const char *name;
    const char *type_name;
    hashtype name_hash;
    struct type *ref;
    struct type *next;

    const struct type *custom_type;
    /* Struct/union items */
    int itemcnt;
    struct type_item *items;

    const struct type *retval;
    struct node *params;
    char *paramstr;
};

struct type_item {
    const struct type *item;
    const char *name;
};

struct struct_name {
    const char *name;
    struct struct_name *parent;
    struct struct_name *next;
};

struct variable {
    int id;
    int reg;
    int direct;
    int global;
    int addr;
    int strlen;
    int bits;
    int func;
    int constant;
    int literal;
    int assigned;
    int prototype;

    LLVMValueRef val;
    /*
     * If this is bigger than 0 it's array of "array" elements.
     * In case this is less than 0, it's size is still unknown
     * marking dynamic array, or non-initializes one
     */
    int array;
    /* Initial value of the variable */
    literalnum value;
    const struct type *type;
    const char *name;
    const char *ext_name;
    hashtype name_hash;
    struct variable *next;
    struct node *params;
    char *paramstr;
};


struct gen_context {
    FILE *f;
    int __ids;
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
    int debug;
    int gen_flags;
    int breaklabel;
    int continuelabel;
    int last_is_ret;

    const char *name;
    const char *decl_name;
    struct node *node;
    //struct node *main_type;
    const struct type *main_type;

    const struct type *pending_type;
    struct type *types;

    struct variable *variables;
    struct variable *globals;
    //struct variable *last_ident;

    const struct codegen_config *conf;

    struct gen_context *parent;
    struct gen_context *child;
    struct gen_context *next;

    struct buffer *pre;
    struct buffer *init;
    struct buffer *data;
    struct buffer *post;

    struct struct_name *structs;

    char **struct_names;
    unsigned int struct_names_cnt;

    LLVMModuleRef mod_ref;
    LLVMBuilderRef build_ref;
    LLVMBasicBlockRef block_ref;
    LLVMContextRef context_ref;
    LLVMValueRef func_ref;
#if 0
    LLVMTypeRef functype;
    LLVMValueRef start;
    LLVMBasicBlockRef entry;
    LLVMContextRef context;
#endif
};

static const char *varstr[] = {
    "void", "null", "i32", "double", "fixed", "string", "struct", "union", "enum", "custom", "builtin", "invalid"
};

int gen_recurse(struct gen_context *ctx, struct node *node);
const struct type *resolve_return_type(struct gen_context *ctx, struct node *node, int reg);
int gen_reserve_label(struct gen_context *ctx);
int gen_recursive_allocs(struct gen_context *ctx, struct node *node);
int gen_negate(struct gen_context *ctx, struct node *node, int a);
struct variable *gen_load(struct gen_context *ctx, struct variable *v);
struct variable *new_variable(struct gen_context *ctx, const char *name, enum var_type type, int bits, enum type_sign sign, int ptr, int addr, int global);
struct variable *new_variable_from_type(struct gen_context *ctx, const char *name, const struct type *type, int ptr, int addr, int global);
int gen_allocate_int(struct gen_context *ctx, int reg, int bits, int ptr, int array, int code_alloc, literalnum val, struct node *node);
struct variable *gen_access_ptr(struct gen_context *ctx, struct variable *var, struct variable *res, struct variable *idx_var, int index);
const struct type *gen_type_list_type(struct gen_context *ctx, struct node *node);
struct variable *gen_load_struct(struct gen_context *ctx, struct variable *v);
const struct type *type_wrap(struct gen_context *ctx, const struct type *src);
const struct type *type_wrap_to(struct gen_context *ctx, const struct type *src, int ptrval);
int gen_type(struct gen_context *ctx, struct node *node);
void free_ctx(struct gen_context *ctx);
int get_type_list(struct gen_context *ctx, struct node *node);
const struct type *find_type_by_id(struct gen_context *ctx, int id);
char *get_param_type_str(struct gen_context *ctx, struct node *node);
struct variable *new_variable_ext(struct gen_context *ctx, const char *name, enum var_type type, int bits, enum type_sign sign, int ptr, int addr, int global, const char *type_name);
char *gen_func_params_with(struct gen_context *ctx, struct node *orig, int allocate_params);

void struct_add(struct gen_context *ctx, struct struct_name *new_struct)
{
        if (ctx->structs == NULL) {
            ctx->structs = new_struct;
        } else {
            struct struct_name *tmp = ctx->structs;
            while (tmp->next != NULL)
                tmp = tmp->next;
            tmp->next = new_struct;
            new_struct->parent = tmp;
        }
}

char *get_name(struct variable *var)
{
    char *res = calloc(1, 32);
    if (var->global) {
        if (var->ext_name) {
            sprintf(res, "@%s", var->ext_name);
        } else {
            sprintf(res, "@G%d", var->reg);
        }
    } else {
        sprintf(res, "%%%d", var->reg);
    }
    return res;
}

char *llvm_gen_name(void)
{
    char *tmp = calloc(1, 256);
    static unsigned idx = 0;

    //snprintf(tmp, 256, "__sic_tmp%u", ++idx);
    snprintf(tmp, 256, "__%u", ++idx);
    tmp[255] = 0;
    return tmp;
}

LLVMValueRef llvm_zero_from_sic_type(const struct type *t)
{
    switch (t->type) {
    case V_INT:
        switch (t->bits) {
        case 1:
            return LLVMConstInt(LLVMInt1Type(), 0, 0);
        case 8:
            return LLVMConstInt(LLVMInt8Type(), 0, 0);
        case 16:
            return LLVMConstInt(LLVMInt16Type(), 0, 0);
        default:
        case 32:
            return LLVMConstInt(LLVMInt32Type(), 0, 0);
        case 64:
            return LLVMConstInt(LLVMInt64Type(), 0, 0);
        case 128:
            return LLVMConstInt(LLVMInt128Type(), 0, 0);
        }
    case V_FLOAT:
        switch (t->bits) {
        case 32:
            return LLVMConstReal(LLVMFloatType(), 0);
        default:
        case 64:
            return LLVMConstReal(LLVMDoubleType(), 0);
        case 128:
            return LLVMConstReal(LLVMFP128Type(), 0);
        }
    case V_VOID:
    default:
        return NULL;
    }
}

LLVMTypeRef sic_type_to_llvm_type(const struct type *t)
{
    switch (t->type) {
    case V_INT:
        switch (t->bits) {
        case 1:
            return LLVMInt1Type();
        case 8:
            return LLVMInt8Type();
        case 16:
            return LLVMInt16Type();
        default:
        case 32:
            return LLVMInt32Type();
        case 64:
            return LLVMInt64Type();
        case 128:
            return LLVMInt128Type();
        }
    case V_FLOAT:
        switch (t->bits) {
        case 32:
            return LLVMFloatType();
        default:
        case 64:
            return LLVMDoubleType();
        case 128:
            return LLVMFP128Type();
        }
    case V_VOID:
    default:
        return LLVMVoidType();
    }
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

char *stype_str(const struct type *t)
{
    if (!t)
        return NULL;
    char *tmp = calloc(256, sizeof(char));
    snprintf(tmp, 255, "%s, %d bits, ptr %d, %ssigned%s%s%s%s%s%s%s",
        type_str(t->type), t->bits, t->ptr, t->sign ? "" : "un",
        t->is_extern ? ", extern" : "", t->is_const ? ", const" : "",
        t->is_static ? ", static" : "", t->is_inline ? ", inline" : "",
        t->type_name ? ", " : "", t->type_name ? t->type_name : "",
        t->temporary ? ", temporary" : "");
    tmp[255] = 0;
    return tmp;
}

struct node *flatten_list(struct node *node)
{
    struct node *res = node;

    while (res->node == A_LIST && !res->right && res->left && res->left->node == A_LIST) {
        res = res->left;
    }

    return res;
}

const struct type *custom_type_get(struct gen_context *ctx, const struct type *cust)
{
    // Not a custom type, so return as-is
    if (!cust || cust->type != V_CUSTOM)
        return cust;
    FATAL(!cust->custom_type, "No target type defined in custom type: %s", stype_str(cust));

    return custom_type_get(ctx, cust->custom_type);
}

const char *float_str(int bits)
{
    if (bits == 32)
        return "float";
    else if (bits == 64)
        return "double";
    else if (bits == 128)
        return "double";
        // TODO Fix long double
        //return "x86_fp80";

    ERR("Invalid bits for float: %d", bits);
}

char *get_type_str(struct gen_context *ctx, const struct type *type)
{
    if (type == NULL)
        return NULL;

    #define TYPE_MAX_LEN 256

    type = custom_type_get(ctx, type);
    char *res = calloc(1, TYPE_MAX_LEN + 1);
    char *stars = get_stars(type->ptr);
    switch (type->type) {
        case V_VOID:
            if (type->ptr)
                sprintf(res, "u8%s", stars);
            else
                sprintf(res, "void");
            break;
        case V_INT:
            sprintf(res, "i%d%s", type->bits > 0 ? type->bits : 32, stars);
            break;
        case V_FLOAT:
            if (type->bits == 32)
                sprintf(res, "float%s", stars);
            else if (type->bits == 64)
                sprintf(res, "double%s", stars);
            else if (type->bits == 128)
                sprintf(res, "double%s", stars); // FIXME
            else
                ERR("Invalid floating point: %d", type->bits);
            break;
        case V_FIXED:
            ERR("Fixed numbers not implemented");
            break;
        case V_STR:
            sprintf(res, "[%d x i8]%s", type->bits, stars);
            break;
        case V_STRUCT:
            snprintf(res, TYPE_MAX_LEN, "%%struct.%s%s", type->type_name, stars);
            break;
        case V_UNION:
            snprintf(res, TYPE_MAX_LEN, "%%union.%s%s", type->type_name, stars);
            break;
        case V_ENUM:
            sprintf(res, "i32%s", stars); // FIXME
            break;
        case V_CUSTOM:
            ERR("Should not get custom type here!");
        case V_FUNCPTR:
            {
                char *tmp = get_type_str(ctx, type->retval);
                char *params = get_param_type_str(ctx, type->params);
                sprintf(res, "%s (%s)%s", tmp, params, stars);
                free(tmp);
                free(params);
            }
            break;
        case V_NULL:
            sprintf(res, "i8%s", stars); // FIXME
            break;
        default:
            ERR("Invalid type");
    }
    free(stars);
    res[TYPE_MAX_LEN] = 0;
    #undef TYPE_MAX_LEN
    return res;
}

char *__get_param_type_str(struct gen_context *ctx, struct node *node, int allocate_params)
{
    FATALN(node && node->node != A_LIST && node->type != V_VOID, node, "Parameters is not list or void");

    struct node *paramnode = node;

    struct buffer *allocs = buffer_init();
    struct buffer *params = buffer_init();
    int paramcnt = 0;
    int ellipsis = 0;
    while (node && node->node == A_LIST) {
        struct node *pval = node;
        if (node->right && node->right->node == A_LIST)
            pval = node->left;
        pval = flatten_list(pval);

        struct node *ptype = pval->left;
        struct node *pname = pval->right;
        FATALN(!ptype, pval, "Invalid parameter");
        FATALN(ellipsis, pval, "Got elements after ellipsis \"...\"");
        if (ptype->node == A_ELLIPSIS) {
            ellipsis = 1;
            paramcnt++;
            buffer_write(params, "%s...",
                paramcnt > 1 ? ", " : "");
            node = node->right;
            continue;
        }
        int t = get_type_list(ctx, ptype);
        FATALN(t >= 0, pval, "Invalid parameter type: %s", node_type_str(ptype->node));
        const struct type *par_type = custom_type_get(ctx, find_type_by_id(ctx, REF_CTX(t)));
        FATALN(!par_type, pval, "Invalid parameter type: %s", node_type_str(ptype->node));
        int pointer = 0;
        while (pname && pname->node == A_POINTER) {
            pointer += pname->ptr;
            pname = pname->left;
        }
        // Need to update pointer value only once when allocting
        if (allocate_params)
            ptype->ptr += pointer;
        pointer = ptype->ptr;

        char *stars = get_stars(pointer);
        paramcnt++;
        if (par_type->type == V_INT) {
            buffer_write(params, "%si%d%s",
                paramcnt > 1 ? ", " : "",
                par_type->bits,
                ESTR(stars));
        } else if (par_type->type == V_FLOAT) {
            if (par_type->bits == 32)
                buffer_write(params, "%sfloat%s",
                    paramcnt > 1 ? ", " : "",
                    ESTR(stars));
            else
                buffer_write(params, "%sdouble%s",
                    paramcnt > 1 ? ", " : "",
                    ESTR(stars));
        } else if (par_type->type == V_VOID && pointer) {
            buffer_write(params, "%si8%s",
                paramcnt > 1 ? ", " : "",
                ESTR(stars));
        } else if (par_type->type == V_STRUCT) {
            buffer_write(params, "%s%%struct.%s%s",
                paramcnt > 1 ? ", " : "",
                par_type->type_name,
                ESTR(stars));
        } else if (par_type->type == V_UNION) {
            buffer_write(params, "%s%%union.%s%s",
                paramcnt > 1 ? ", " : "",
                par_type->type_name,
                ESTR(stars));
        } else if (par_type->type == V_VOID && pointer) {
            buffer_write(params, "%si8%s*",
                paramcnt > 1 ? ", " : "",
                ESTR(stars));
        } else if (par_type->type == V_VOID && !pointer) {
        } else {
            stack_trace();
            ERR("Invalid parameter type: %s", type_str(par_type->type));
        }
        if (stars)
            free(stars);

        node = node->right;
    }

    if (allocate_params) {
        node = paramnode;
        int parami = 0;
        if (ellipsis) {
            if (paramcnt)
                ctx->regnum += paramcnt - 1;
        } else
            ctx->regnum += paramcnt;
        while (node && node->node == A_LIST) {
            struct node *pval = node;
            if (node->right && node->right->node == A_LIST)
                pval = node->left;
            pval = flatten_list(pval);

            struct node *ptype = pval->left;
            struct node *pname = pval->right;
            if (ptype->node == A_ELLIPSIS) {
                node = node->right;
                continue;
            }
            int t = get_type_list(ctx, ptype);
            FATALN(t >= 0, pval, "Invalid parameter type: %s", node_type_str(ptype->node));
            const struct type *par_type = custom_type_get(ctx, find_type_by_id(ctx, REF_CTX(t)));
            // TODO: parse types properly, now just shortcutting
            while (pname && pname->node == A_POINTER)
                pname = pname->left;
            if (par_type->type == V_VOID && !ptype->ptr) {
                // This is just "void", skip and reduce it
                // from parameters
                node = node->right;
                ctx->regnum--;
                continue;
            }

            FATALN(!pname, paramnode->parent, "No name in");

            char *stars = get_stars(ptype->ptr);
            if (par_type->type == V_INT) {
                struct variable *res = new_variable(ctx, pname->value_string, par_type->type, par_type->bits, par_type->sign, ptype->ptr, ptype->addr, 0);
                FATALN(!res, pname, "Couldn't generate res");
                buffer_write(allocs, "%%%d = alloca i%d%s, align %d\n",
                    res->reg,
                    par_type->bits,
                    ESTR(stars),
                    align(par_type->bits));
                buffer_write(allocs, "store i%d%s %%%d, i%d%s* %%%d, align %d ; func_params\n",
                    par_type->bits,
                    ESTR(stars),
                    parami,
                    par_type->bits,
                    ESTR(stars),
                    res->reg,
                    align(par_type->bits));
                pname->reg = res->reg;
            } else if (par_type->type == V_FLOAT) {
                struct variable *res = new_variable(ctx, pname->value_string, par_type->type, par_type->bits, par_type->sign, ptype->ptr, ptype->addr, 0);
                FATALN(!res, pname, "Couldn't generate res");

                buffer_write(allocs, "%%%d = alloca %s%s, align %d\n",
                    res->reg,
                    float_str(par_type->bits),
                    ESTR(stars),
                    align(par_type->bits));
                buffer_write(allocs, "store %s%s %%%d, %s%s* %%%d, align %d\n",
                    float_str(par_type->bits),
                    ESTR(stars),
                    parami,
                    float_str(par_type->bits),
                    ESTR(stars),
                    res->reg,
                    align(par_type->bits));
                pname->reg = res->reg;
            } else if (par_type->type == V_VOID) {
                struct variable *res = new_variable(ctx, pname->value_string, par_type->type, par_type->bits, par_type->sign, ptype->ptr, ptype->addr, 0);
                FATALN(!res, pname, "Couldn't generate res");
                buffer_write(allocs, "%%%d = alloca i%d%s, align %d\n",
                    res->reg,
                    8,
                    ESTR(stars),
                    8);
                buffer_write(allocs, "store i%d%s %%%d, i%d%s* %%%d, align %d ; func_params\n",
                    8,
                    ESTR(stars),
                    parami,
                    8,
                    ESTR(stars),
                    res->reg,
                    8);
                pname->reg = res->reg;
            } else if (par_type->type == V_STRUCT) {
                struct variable *res = new_variable_ext(ctx, pname->value_string, par_type->type, par_type->bits, par_type->sign, ptype->ptr, ptype->addr, 0, par_type->type_name);

                buffer_write(ctx->init, "%%%d = alloca %%struct.%s%s, align 8\n", res->reg, par_type->type_name, ESTR(stars));
                buffer_write(allocs, "store %%struct.%s%s %%%d, %%struct.%s%s* %%%d, align %d; func param list cast\n",
                    par_type->type_name,
                    ESTR(stars),
                    parami,
                    par_type->type_name,
                    ESTR(stars),
                    res->reg,
                    8);
            } else if (par_type->type == V_UNION) {
                struct variable *res = new_variable_ext(ctx, pname->value_string, par_type->type, par_type->bits, par_type->sign, ptype->ptr, ptype->addr, 0, par_type->type_name);

                buffer_write(ctx->init, "%%%d = alloca %%union.%s%s, align 8\n", res->reg, par_type->type_name, ESTR(stars));
                buffer_write(allocs, "store %%union.%s%s %%%d, %%union.%s%s* %%%d, align %d\n",
                    par_type->type_name,
                    ESTR(stars),
                    parami,
                    par_type->type_name,
                    ESTR(stars),
                    res->reg,
                    8);
            } else
                ERR("Invalid parameter type: %s", type_str(par_type->type));
            if (stars)
                free(stars);
            parami++;

            node = node->right;
        }
    }
    const char *tmp = buffer_read(params);
    int tmplen = strlen(tmp) + 1;
    char *resbuf = calloc(1, tmplen);
    resbuf = memcpy(resbuf, tmp, tmplen);
    buffer_del(params);
    if (allocate_params)
        buffer_append(ctx->init, buffer_read(allocs));
    buffer_del(allocs);
    return resbuf;
}

char *get_param_type_str(struct gen_context *ctx, struct node *node)
{
    return __get_param_type_str(ctx, node, 0);
}

void struct_pop(struct gen_context *ctx)
{
    if (ctx->structs == NULL)
        return;

    if (ctx->structs->next == NULL) {
        free(ctx->structs);
        ctx->structs = NULL;
        return;
    }

    struct struct_name *tmp = ctx->structs;
    struct struct_name *prev = tmp;
    while (tmp->next != NULL) {
        prev = tmp;
        tmp = tmp->next;
    }
    free(prev->next);
    prev->next = NULL;
}

char *struct_name(struct gen_context *ctx)
{
    if (!ctx->structs)
        return NULL;

    char *res = NULL;
    struct struct_name *tmp = ctx->structs;

    if (tmp && tmp->next == NULL) {
        size_t l = strlen(tmp->name);
        res = calloc(1, l + 1);
        memcpy(res, tmp->name, l);
        ctx->struct_names_cnt++;
        ctx->struct_names = realloc(ctx->struct_names, sizeof(char*) * ctx->struct_names_cnt + 1);
        ctx->struct_names[ctx->struct_names_cnt - 1] = res;
        return res;
    }

    while (tmp != NULL) {
        if (!tmp->name) {
            tmp = tmp->next;
            continue;
        }

        size_t l = strlen(tmp->name);
        if (res == NULL) {
            res = calloc(1, l + 2);
            memcpy(res, tmp->name, l);
            res[l] = '_';
            res[l + 1] = 0;
        } else {
            size_t ll = strlen(res);
            res = realloc(res, ll + l + 2);
            memcpy(res + ll, tmp->name, l);
            res[ll + l] = '_';
            res[ll + l + 1] = 0;
        }
        tmp = tmp->next;
    }

    if (res != NULL) {
        int ln = strlen(res);
        if (ln > 0)
            res[ln - 1] = 0;
    }

    ctx->struct_names_cnt++;
    ctx->struct_names = realloc(ctx->struct_names, sizeof(char*) * ctx->struct_names_cnt + 1);
    ctx->struct_names[ctx->struct_names_cnt - 1] = res;
    return res;
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

char *variable_str(struct variable *var)
{
    char *tmp = calloc(512, sizeof(char));
    snprintf(tmp, 511, "var %d: reg %d, direct: %d, global: %d, "
        "ptr: %d, addr: %d, strlen: %d, bits: %d, "
        "type: 0x%p, name: %s",
        var->id, var->reg,
        var->direct, var->global,
        var->type->ptr, var->addr, var->strlen, var->bits,
        (void*)var->type, var->name);
    return tmp;
}

int float_has_128() {
    return strcmp(float_str(128), "double") != 0;
}

enum builtin_function builtin_func(const char *name)
{
    if (strcmp(name, "__builtin_va_start") == 0)
        return BUILTIN_VA_START;
    if (strcmp(name, "__builtin_va_end") == 0)
        return BUILTIN_VA_END;
    if (strcmp(name, "__builtin_va_arg") == 0)
        return BUILTIN_VA_ARG;
    if (strcmp(name, "__builtin_bswap16") == 0)
        return BUILTIN_BSWAP16;
    if (strcmp(name, "__builtin_bswap32") == 0)
        return BUILTIN_BSWAP32;
    if (strcmp(name, "__builtin_bswap64") == 0)
        return BUILTIN_BSWAP64;

    return BUILTIN_NONE;
}

const struct type *__find_type_by(struct gen_context *ctx, enum var_type type, int bits, enum type_sign sign, int ptr, const char *name)
{
    struct type *res = ctx->types;
    while (res) {
#if DEBUG
        if (res->type == type)
            printf("Typecheck: bits %d == %d, sign %d == %d, ptr %d == %d, %s, names %s == %s\n", res->bits, bits, res->sign, sign, res->ptr, ptr, type_str(type), name, res ? res->name : NULL);
#endif
#if 0
        if (name && res->name)
            printf("CMP: %s == %s\n", res->name, name);
#endif
        if (name != NULL && res->name != NULL && strcmp(res->name, name) == 0 && ptr == res->ptr)
            return res;
        if (res->type == type && (res->bits == bits || bits == 0 || res->bits == 0) && res->sign == sign && res->ptr == ptr) {
            if (name != NULL && res->name != NULL && strcmp(res->name, name) == 0)
                return res;
            else if (res->type != V_STRUCT && res->type != V_UNION && res->type != V_CUSTOM && res->type != V_FUNCPTR)
                return res;
        }
        res = res->next;
    }
    if (ctx->parent)
        return __find_type_by(ctx->parent, type, bits, sign, ptr, name);
    return NULL;
}

const struct type *find_type_by_name(struct gen_context *ctx, const char *name)
{
    struct type *res = ctx->types;

    while (res) {
        if (res->name && strcmp(res->name, name) == 0)
            return res;
        res = res->next;
    }
    if (ctx->parent)
        return find_type_by_name(ctx->parent, name);

    return NULL;
}

#define swaptype(a, b) do { const struct type *tmp = a; a = b; b = tmp; } while(0)

const struct type *sic_solve_type(struct gen_context *ctx, const struct type *a, const struct type *b)
{
    int wanted_bits;
    int wanted_sign;

    if (a->type == V_NULL)
        return b;
    if (b->type == V_NULL)
        return a;

    if (a->type != b->type) {
        if (a->type == V_FLOAT && b->type == V_INT);
        else if (a->type == V_INT && b->type == V_FLOAT)
            swaptype(a, b);
        else
            return NULL;
    }
    /* Make sure a is bigger than b */
    if (b->bits > a->bits)
        swaptype(a, b);
    wanted_bits = a->bits;
    wanted_sign = a->sign;
    /* Check for signess */
    if (a->sign != b->sign) {
        /*
         * If we have same bits we might have an issue. For now force
         * unsigned.
         */
        if (a->bits == b->bits)
            wanted_sign = 0;
    }
    /* If pointer value differs we have issue */
#if 0
    if (a->ptr != b->ptr)
        ERR("Pointer value differs in type!");
#endif
    //return __find_type_by(ctx, a->type, wanted_bits, wanted_sign, a->ptr, NULL);
    return __find_type_by(ctx, a->type, wanted_bits, wanted_sign, 0, NULL);
}


const struct type *find_type_by(struct gen_context *ctx, enum var_type type, int bits, enum type_sign sign, int ptr)
{
    return __find_type_by(ctx, type, bits, sign, ptr, NULL);
}

const struct type *find_type_by_id(struct gen_context *ctx, int id)
{
    struct type *res = ctx->types;
    while (res) {
        if (res->id == id)
            return res;
        res = res->next;
    }
    if (ctx->parent)
        return find_type_by_id(ctx->parent, id);
    return NULL;
}

struct gen_context *get_global_ctx(struct gen_context *ctx)
{
    struct gen_context *global_ctx = ctx;
    while (global_ctx && global_ctx->parent)
        global_ctx = global_ctx->parent;

    return global_ctx;
}

int ctx_reserve_id(struct gen_context *ctx)
{
    /* Always reserve ids from global context */
    struct gen_context *global_ctx = get_global_ctx(ctx);
    int res = ++global_ctx->__ids;
    return res;
}

struct type *register_type_ptr(struct gen_context *ctx, const char *name, enum var_type type, int bits, enum type_sign sign, int ptr, const struct type *custom)
{
    const struct type *ot = __find_type_by(ctx, type, bits, sign, ptr, name);
    struct type *t;

    FATAL(ot, "Type already registered: %s, %s, %d bits, %s, ptr %d, got: %s %s", name, type_str(type), bits, sign ? "signed" : "unsigned", ptr, get_type_str(ctx, ot), ot->type_name);

    t = calloc(1, sizeof(struct type));
    t->type = type;
    t->bits = bits;
    t->name = name;
    if (name && (type == V_STRUCT || type == V_UNION || type == V_ENUM))
        t->type_name = name;
    t->sign = sign;
    t->ptr = ptr;
    t->name_hash = hash(name);
    t->custom_type = custom;

    t->id = ctx_reserve_id(ctx);
    t->next = ctx->types;
    ctx->types = t;

    return t;
}

struct type *register_custom_type(struct gen_context *ctx, const char *name, enum var_type type, int bits, enum type_sign sign, const struct type *custom)
{
    return register_type_ptr(ctx, name, type, bits, sign, 0, custom);
}

struct type *register_type(struct gen_context *ctx, const char *name, enum var_type type, int bits, enum type_sign sign)
{
    return register_type_ptr(ctx, name, type, bits, sign, 0, NULL);
}

struct node *find_struct_item_name(struct node *node)
{
    struct node *namenode = node;

    while (namenode && namenode->right) {
        if (namenode->node == A_INDEX || namenode->node == A_INDEXDEF) {
            namenode = namenode->left;
            break;
        }
        namenode = namenode->right;
    }

    while (namenode && namenode->left) {
        if (namenode->node == A_INDEX || namenode->node == A_INDEXDEF) {
            namenode = namenode->left;
            break;
        }
        namenode = namenode->left;
    }
    return namenode;
}

void complete_struct_type(struct gen_context *ctx, struct type *type, struct node *node, int is_union, struct buffer *struct_init)
{
    struct node *tmp = node;
    int first = 1;
    int ok_gen = 1;
    int union_size = 0;

    /* This must be forward declaration, or then invalid */
    if (!tmp)
        return;
    FATALN(!tmp, node, "Invalid struct/union: %p", (void *)node);

    do {
        if (tmp->left) {
            struct node *l = tmp->left;
            struct node *namenode = l->right;
            const struct type *t = gen_type_list_type(ctx, l);
            FATALN(!t, l, "Invalid type definition: %s", type_str(l->type));
            char *stars = get_stars(l->ptr);
            int itemsize = 0;

            type->itemcnt++;

            if (!namenode)
                namenode = l;
            namenode = find_struct_item_name(namenode);

            if (is_union)
                ok_gen = 0;

            if (!first && ok_gen)
                buffer_write(struct_init, ", ");
            first = 0;
            if (t->type == V_CUSTOM)
                t = custom_type_get(ctx, t);
            if (t->type == V_INT) {
                itemsize = t->bits ? t->bits : 32;
                if (ok_gen)
                    buffer_write(struct_init, "i%d%s", (t->bits ? t->bits : 32), stars);
            } else if (t->type == V_FLOAT) {
                if (ok_gen) {
                    if (t->bits == 32)
                        buffer_write(struct_init, "float%s", stars);
                    else
                        buffer_write(struct_init, "double%s", stars);
                }
                itemsize = t->bits;
            } else if (t->type == V_STRUCT) {
                /*
                 * We need to resolve the size of struct now in
                 * order to make sizeof and other things working.
                 * This is needed because at parse time we do not
                 * have reference to the struct this is referring
                 * so we just mark 0 as size.
                 */
                itemsize = t->bits;
                type->bits += t->bits;
                if (ok_gen)
                    buffer_write(struct_init, "%%struct.%s%s", t->type_name, stars);
                namenode = l;
            } else if (t->type == V_UNION) {
                itemsize = t->bits;
                type->bits += t->bits;
                if (ok_gen)
                    buffer_write(struct_init, "%%union.%s%s", t->type_name, stars);
                namenode = l;
            } else if (t->ptr && t->type == V_VOID) {
                if (ok_gen)
                    buffer_write(struct_init, "i8%s", stars);
            } else {
                node_walk(tmp);
                ERR("Unsupported type: %s", type_str(t->type));
            }

            if (t->ptr)
                itemsize = 8; //FIXME

            if (itemsize > union_size)
                union_size = itemsize;
            if (type->items == NULL)
                type->items = calloc(type->itemcnt, sizeof(struct type_item));
            else
                type->items = realloc(type->items, type->itemcnt * sizeof(struct type_item));

            FATALN(!namenode, tmp, "No name");
            //printf("Struct new item: %s, type %s\n", namenode->value_string, stype_str(t));
            type->items[type->itemcnt - 1].item = t;
            FATALN(!namenode->value_string && !namenode->type_name, namenode, "Nameless struct value");
            //if (namenode->value_string)
            type->items[type->itemcnt - 1].name = namenode->value_string;
            if (stars)
                free(stars);
        }
        tmp = tmp->right;
    } while (tmp);
    if (is_union) {
        switch (union_size) {
            case 8:
            case 16:
            case 32:
            case 64:
                buffer_write(struct_init, "i%d", union_size);
                break;
            default:
                buffer_write(struct_init, "[%d x i%d]", union_size);
        }
    }
}

void complete_enum_type(struct gen_context *global_ctx, struct gen_context *ctx, struct type *type, struct node *node)
{
    struct node *tmp = node;
    int value = 0;

    do {
        if (tmp->left) {
            struct node *l = tmp->left;
            if (l->left) {
                // TODO Better handling of enum value, this supports only int constants
                value = l->left->value;
            }

            buffer_write(ctx->init, "; ENUM: %s\n", l->value_string);
            struct variable *var = new_variable(global_ctx, l->value_string, V_INT, 32, 1, 0, 0, global_ctx->global);
            gen_allocate_int(global_ctx, var->reg, var->type->bits, var->type->ptr, 0, 0, value, NULL);

            value++;
        }
        tmp = tmp->right;
    } while (tmp);

}

const struct type *type_unwrap(struct gen_context *ctx, const struct type *src)
{
    if (!src->ptr)
        return src;

    const struct type *res = __find_type_by(ctx, src->type, src->bits, src->sign, src->ptr - 1, src->name);
    return type_unwrap(ctx, res);
}

const struct type *struct_get_by_index(const struct type *type, int index)
{
    FATAL(!type, "No struct type");
    //FATAL(index >= type->itemcnt, "Struct/union access out of bounds");

    if (index >= type->itemcnt)
        return NULL;

    return type->items[index].item;
}

int struct_get_by_name(struct gen_context *ctx, const struct type *type, const char *name, const struct type **res)
{
    FATAL(!type, "No struct type");
    FATAL(!name, "Can't access empty from struct");

    type = type_unwrap(ctx, type);

    for (int i = 0; i < type->itemcnt; i++) {
        FATAL(!type->items[i].name, "Struct element has no name");
        if (strcmp(type->items[i].name, name) == 0) {
            if (res)
                *res = type->items[i].item;
            return i;
        }
    }
    return -1;
}

const struct type *type_wrap(struct gen_context *ctx, const struct type *src)
{
    const struct type *res_old = __find_type_by(ctx, src->type, src->bits, src->sign, src->ptr + 1, src->name);
    if (res_old) {
        FATAL(res_old->ptr != src->ptr + 1, "Wrap failure");
        return res_old;
    }

    struct type *res = register_type_ptr(ctx, NULL, src->type, src->bits, src->sign, src->ptr + 1, src->custom_type);
    res->name = src->name;
    res->type_name = src->type_name;
    if (src->type == V_CUSTOM) {
        // For custom types we need to wrap the custom as well
        res->custom_type = type_wrap(ctx, src->custom_type);
    }
    return res;
}


const struct type *type_wrap_to(struct gen_context *ctx, const struct type *src, int ptrval)
{
    const struct type *res = src;
    if (!res)
        return res;
    while (ptrval--)
        res = type_wrap(ctx, res);
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

struct variable *find_literal(struct gen_context *ctx, enum var_type type, int bits, enum type_sign sign, literalnum value)
{
    struct variable *val = ctx->variables;
    while (val != NULL) {
        if (val->literal && val->type->type == type && (bits == 0 || val->type->bits == 0 || val->type->bits == bits) && val->value == value)
            return val;
        val = val->next;
    }
    if (ctx->parent)
        return find_literal(ctx->parent, type, bits, sign, value);
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
            var->type->ptr, var->addr, var->strlen, var->bits,
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

struct variable *find_variable_by_name_scope(struct gen_context *ctx, const char *name, int globals, int parents)
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
    if (parents && ctx->parent)
        return find_variable_by_name_scope(ctx->parent, name, globals, parents);
    if (globals)
        return find_global_variable_by_name(ctx, name);
    return NULL;
}

struct variable *find_variable_by_name(struct gen_context *ctx, const char *name)
{
    return find_variable_by_name_scope(ctx, name, 1, 1);
}

struct variable *init_variable(const char *name, const struct type *t)
{
    struct variable *res = calloc(1, sizeof(struct variable));

    res->type = t;
    res->name = name;
    res->name_hash = hash(name);

    return res;
}

void register_variable(struct gen_context *ctx, struct variable *var)
{
    struct variable *v = find_variable_by_name(ctx, var->name);
    FATAL(v, "Variable already registered: %s", var->name);

    var->id = ctx_reserve_id(ctx);
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
    register_type(ctx, "void", V_VOID, 0, TYPE_UNSIGNED);

    register_type(ctx, "bool", V_INT, 1, TYPE_UNSIGNED);

    register_type(ctx, "char", V_INT, 8, TYPE_SIGNED);
    register_type(ctx, "unsigned char", V_INT, 8, TYPE_UNSIGNED);

    register_type(ctx, "short", V_INT, 16, TYPE_SIGNED);
    register_type(ctx, "unsigned short", V_INT, 16, TYPE_UNSIGNED);

    register_type(ctx, "int", V_INT, 32, TYPE_SIGNED);
    register_type(ctx, "unsigned int", V_INT, 32, TYPE_UNSIGNED);

    register_type(ctx, "long", V_INT, 64, TYPE_SIGNED);
    register_type(ctx, "unsigned long", V_INT, 64, TYPE_UNSIGNED);

    register_type(ctx, "float", V_FLOAT, 32, TYPE_SIGNED);
    register_type(ctx, "double", V_FLOAT, 64, TYPE_SIGNED);
    register_type(ctx, "long double", V_FLOAT, 128, TYPE_SIGNED);

    register_type(ctx, "string", V_STR, 0, TYPE_UNSIGNED);
}

struct gen_context *init_ctx(FILE *outfile, struct gen_context *parent)
{
    struct gen_context *res = calloc(1, sizeof(struct gen_context));
    res->f = outfile;

    if (parent)
        res->mod_ref = parent->mod_ref;


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
    res->name = global_ctx_name;
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

    if (!parent) {
        // Register singleton NULL variable to global context
        register_type(res, "nulltype", V_NULL, 0, TYPE_UNSIGNED);
        const struct type *null_type = find_type_by(res, V_NULL, 0, TYPE_UNSIGNED, 0);
        FATAL(!null_type, "Couldn't find NULL type");
#if 1
        struct variable *null_var = new_variable(res, "NULL", V_NULL, 0, TYPE_UNSIGNED, 0, 0, 1);
        buffer_write(res->init, "@G%u = dso_local global i8* null, align 8\n",
            null_var->reg);
#else
        struct variable *null_var = init_variable("NULL", null_type);
        register_variable(res, null_var);
#endif

        res->null_var = null_var->reg;
    } else {
        res->null_var = parent->null_var;
    }

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

struct variable *new_variable_ext(struct gen_context *ctx, const char *name, enum var_type type, int bits, enum type_sign sign, int ptr, int addr, int global, const char *type_name)
{
    struct variable *res = calloc(1, sizeof(struct variable));

    res->id = ctx_reserve_id(ctx);
    // Float and fixed are always signed
    if (type == V_FLOAT)
        sign = TYPE_SIGNED;
    if (global)
        res->reg = ctx->regnum_global++;
    else
        res->reg = ctx->regnum++;

    // If bits == 0 and we have a pendign type which matches requested type, use it
    const struct type *pend = custom_type_get(ctx, ctx->pending_type);
    if (type == V_NULL) {
        bits = 0;
        sign = TYPE_UNSIGNED;
    } else if (bits == 0 && pend && pend->type == type) {
        type = pend->type;
        bits = pend->bits;
        sign = pend->sign;
        type_name = pend->type_name;
        //ptr = ctx->pending_type->ptr;
    } else if (type == V_VOID) {
        bits = 0;
        sign = TYPE_UNSIGNED;
    } else if (type != V_STR && (bits == 0 || type == V_FLOAT)) {
        // Default to 32
        if (type == V_INT)
            bits = 32;
        sign = TYPE_SIGNED;
    }
    res->addr = addr;
    res->name = name;
    res->name_hash = hash(name);
    res->bits = bits;
    res->type = __find_type_by(ctx, type, bits, sign, 0, type_name);
    res->type = type_wrap_to(ctx, res->type, ptr);
    FATAL(!res->type, "Didn't find type: %s, %d bits, sign: %s, name: %s", type_str(type), bits, sign ? "true" : "false", type_name);
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

struct variable *new_variable(struct gen_context *ctx, const char *name, enum var_type type, int bits, enum type_sign sign, int ptr, int addr, int global)
{
    return new_variable_ext(ctx, name, type, bits, sign, ptr, addr, global, NULL);
}

struct variable *new_variable_from_type(struct gen_context *ctx, const char *name, const struct type *type, int ptr, int addr, int global)
{
    return new_variable_ext(ctx, name, type->type, type->bits, type->sign, ptr, addr, global, type->name);
}

struct variable *new_inst_variable(struct gen_context *ctx,
        enum var_type type, int bits, enum type_sign sign)
{
    struct variable *res = new_variable(ctx, NULL, type, bits, sign, 0, 0, 0);
    res->direct = 1;
    return res;
}

struct variable *new_bool(struct gen_context *ctx, enum vartype direct)
{
    if (direct == VAR_DIRECT)
        return new_inst_variable(ctx, V_INT, 1, TYPE_UNSIGNED);
    return new_variable(ctx, NULL, V_INT, 1, TYPE_UNSIGNED, 0, 0, 0);
}

struct variable *new_bool_alloc(struct gen_context *ctx, enum vartype direct)
{
    struct variable *res = new_bool(ctx, direct);
    buffer_write(ctx->data, "%%%d = alloca i1, align 1\n",
        res->reg);
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

struct variable *gen_cast(struct gen_context *ctx, struct variable *v, const struct type *target_orig, int force)
{
    FATAL(!v, "Invalid cast!");
    FATAL(!target_orig, "No target type");
    if (!force && v->type->type == target_orig->type)
        return v;
    struct type __target;
    struct type *target = &__target;
    memcpy(&__target, target_orig, sizeof(struct type));
    if (target->bits == 0) {
        target->bits = 32;
    }

    struct variable *val = NULL;
    if (target->type == V_FLOAT && v->type->type == V_INT) {
        val = new_variable(ctx, NULL, V_FLOAT, 64, TYPE_SIGNED, 0, 0, 0);
        buffer_write(ctx->data, "%%%d = sitofp i%d %%%d to double; gen_cast\n",
                val->reg, v->type->bits, v->reg, 64);
        val->direct = 1;
    } else if (!force) {
        ERR("Invalid cast for %d, %d -> %d",
            v->reg, v->type->type, target->type);
    } else {
        if (target->type == V_VOID && !target->ptr) {
            // Casting to void thus provide null
            val = find_variable(ctx, ctx->null_var);
        } else if (target->type == V_INT && v->type->type == V_FLOAT) {
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
        } else if (target->type == V_FLOAT && v->type->type == V_FLOAT) {
            if (target->bits >= v->type->bits)
                return v;
            // 64 -> 32
            val = new_inst_variable(ctx, V_FLOAT, target->bits, TYPE_SIGNED);
            if (v->type->bits == 64 && target->bits == 32)
                buffer_write(ctx->data, "%%%d = fptrunc double %%%d to float\n",
                    val->reg,  v->reg);
            else
                ERR("Can't cast bits %d to %d\n", v->type->bits, target->bits);
        } else if (v->type->type == target->type)
            return v;
        else if (v->type->type == V_NULL && target->type == V_INT) {
            val = new_variable(ctx, NULL, V_INT, target->bits, target->sign, 0, 0, 0);
            buffer_write(ctx->data, "%%%d = alloca i%d, align %d ; null to int\n",
                val->reg, val->type->bits, align(val->type->bits));
            buffer_write(ctx->data, "store i%d 0, i%d* %s%d, align %d ; gen_cast NULL to int\n",
                val->type->bits, val->type->bits, REGP(val), val->reg, align(val->type->bits));
        }
        else if (target->type == V_INT && v->type->type == V_STR) {
            val = new_variable(ctx, NULL, V_INT, target->bits, target->sign, 0, 0, 0);
            buffer_write(ctx->data, "%%%d = getelementptr inbounds "
                "[%d x i8], [%d x i8]* @.str.%d, i32 0, i32 0\n",
                val->reg, v->array, v->array, v->reg);
        }
        else if (target->type == V_INT && v->type->type == V_STRUCT) {
            //FATAL(!target->ptr, "Can't convert int to struct, need pointer");
            buffer_write(ctx->data, "; ptr %d -> %d\n", target->ptr, v->type->ptr);
            if (target->ptr > v->type->ptr)
                v = gen_load_struct(ctx, v);

            char *stars = get_stars(v->type->ptr);
            char *stars2 = get_stars(target->ptr);

#if 0
            struct type *access_type = struct_get_by_index(v->type, 0);

            struct variable *tmp_val = new_variable(ctx, NULL, access_type->type, access_type->bits, access_type->sign, 0, 0, 0);
            buffer_write(ctx->data, "%%%d = load %%struct.%s*, %%struct.%s** %%%d\n",
                tmp_val->reg, v->type->name, v->type->name, v->reg);
/*
            buffer_write(ctx->data, "%%%d = getelementptr inbounds %%struct.%s, %%struct.%s* %%%d, i32 0, i32 %d\n",
            //buffer_write(ctx->data, "%%%d = getelementptr inbounds i8*, %%struct.%s* %%%d, i32 0, i32 %d\n",
                tmp_val->reg, v->type->name, v->type->name, v->reg, 0);
*/
#endif
            val = new_variable(ctx, NULL, V_INT, target->bits, target->sign, 0, 0, 0);
            if (v->type->ptr && !target->ptr) {
                buffer_write(ctx->data, "%%%d = ptrtoint %%struct.%s%s %s%d to i%d; gen_cast struct ptr to int\n",
                    val->reg, v->type->type_name, stars, REGP(v), v->reg, target->bits);
            } else {
                buffer_write(ctx->data, "%%%d = bitcast %%struct.%s%s %%%d to i%d%s ; gen_cast struct to int_ptr\n",
                    val->reg, v->type->type_name, stars, v->reg, target->bits, stars2);
            }
#if 0
            buffer_write(ctx->data, "%%%d = bitcast %%struct.%s %%%d to i%d%s ; gen_cast int_ptr to struct\n",
                val->reg, v->type->type_name, tmp_val->reg, target->bits, stars);
#endif
            if (stars)
                free(stars);
            if (stars2)
                free(stars2);
        }

    }

    FATAL(!val, "Cast failed: %s -> %s, %s", type_str(v->type->type), type_str(target->type), force ? "forced" : "no-force");

    return val;
}

struct variable *gen_bits_cast(struct gen_context *ctx, struct variable *v1, int bits2, enum type_sign sign2)
{
    int bits1 = v1->type->bits;
    if (bits1 == bits2)
        return v1;
    if (bits1 > bits2)
        return v1;

    FATAL(v1->global, "Can't cast from global");
    FATAL(v1->type->type != V_INT && v1->type->ptr, "Can't extend pointer bits: %d\n", v1->reg);
    struct variable *res = NULL;

    if (v1->type->ptr) {
        char *stars = get_stars(v1->type->ptr);

        res = new_inst_variable(ctx, V_INT, bits2, v1->type->sign);
        buffer_write(ctx->data, "%%%d = bitcast i%d%s %%%d to i%d%s ; gen_bit_cast cast ptr\n",
                res->reg, bits1, ESTR(stars), v1->reg, bits2, stars);
        if (stars)
            free(stars);
    } else if (v1->type->type == V_INT) {
        res = new_inst_variable(ctx, V_INT, bits2, v1->type->sign || sign2 ? TYPE_SIGNED : TYPE_UNSIGNED);
        /* We can't sign extend 1 bit */
        if (sign2 && bits1 > 1) {
            buffer_write(ctx->data, "%%%d = sext i%d %%%d to i%d\n",
                res->reg, bits1, v1->reg, bits2);
        } else {
            buffer_write(ctx->data, "%%%d = zext i%d %%%d to i%d\n",
                res->reg, bits1, v1->reg, bits2);
        }
    } else if (v1->type->type == V_FLOAT) {
        if (bits2 == 128 && !float_has_128())
            return v1;
        res = new_inst_variable(ctx, V_FLOAT, bits2, TYPE_SIGNED);
        buffer_write(ctx->data, "%%%d = fpext %s %%%d to %s\n",
            res->reg, float_str(bits1), v1->reg, float_str(bits2));
    } else
        ERR("Can't cast");
    res->value = v1->value;
    return res;
}
int gen_dereference(struct gen_context *ctx, struct node *node, int reg);

struct variable *var_cast_to(struct gen_context *ctx, struct variable *src, const struct type *target)
{
    struct variable *dst = src;

    FATAL(!src, "Cast source not defined");
    FATAL(!target, "Cast target not defined");

    if (target->type != dst->type->type || target->bits != dst->type->bits) {
        dst = gen_cast(ctx, dst, target, 1);
        FATAL(!dst, "Cast failed from %s to %s", type_str(src->type->type), type_str(target->type));
        dst = gen_bits_cast(ctx, dst, target->bits, TYPE_SIGNED);
        FATAL(!dst, "Bit cast failed");
    }

    return dst;
}

struct variable *load_and_cast_to(struct gen_context *ctx, struct variable *src, const struct type *target, int cast_flags)
{
    FATAL(!src, "Cast source not defined");
    FATAL(!target, "Cast target not defined");

    if ((cast_flags & CAST_FLATTEN_PTR) && src->type->ptr) {
        if (src->type->type == V_INT) {
            struct variable *res = NULL;
            char *stars = get_stars(src->type->ptr);

            res = new_inst_variable(ctx, V_INT, target->bits, src->type->sign);
            buffer_write(ctx->data, "%%%d = ptrtoint i%d%s* %%%d to i%d ; load_and_cast_to\n",
                res->reg, src->type->bits, stars, src->reg, target->bits);
            if (stars)
                free(stars);
            src = res;
        }
    }
    if (!src->direct && (src->type->type != V_STRUCT || (cast_flags & CAST_NO_LOAD_STRUCT) == 0)) {
        src = gen_load(ctx, src);
    }
    else if (src->type->type == V_STRUCT) {
        int now_ptr = src->type->ptr;
        int prev_reg = src->reg;
        struct variable *res = NULL;

        while (target->ptr < now_ptr) {
            char *stars = get_stars(now_ptr - 1);
            res = new_variable_ext(ctx, NULL, V_STRUCT, src->type->bits, src->type->sign, now_ptr - 1, 0, 0, src->type->type_name);

            buffer_write(ctx->data, "%%%u = load %%struct.%s%s, %%struct.%s%s* %%%u, align %u\n", res->reg, src->type->type_name, stars, src->type->type_name, stars, prev_reg, align(src->type->bits));
            prev_reg = res->reg;
            now_ptr--;
        }
        if (res)
            src = res;
    }

    return var_cast_to(ctx, src, target);
}

struct variable *cast_int_to_ptr(struct gen_context *ctx, struct variable *var)
{
    struct variable *res = var;

    if (var->type->type == V_INT && !var->type->ptr) {
        res = new_inst_variable(ctx, V_INT, var->type->bits, var->type->sign);
        buffer_write(ctx->data, "%%%d = inttoptr i%d %%%d to i%d* ; cast_int_to_ptr\n",
            res->reg,
            var->type->bits,
            var->reg,
            res->type->bits);
        res->type = type_wrap(ctx, res->type);
    }

    return res;
}

struct variable *gen_bits(struct gen_context *ctx, struct variable *v1, struct variable *v2)
{
    return gen_bits_cast(ctx, v1, v2->type->bits, v2->type->sign);
}

int gen_allocate_int(struct gen_context *ctx, int reg, int bits, int ptr, int array, int code_alloc, literalnum val, struct node *node)
{
    if (ctx->global) {
        FATAL(ptr, "Global pointer not supported");
        if (array) {
            char *stars = get_stars(ptr);
            struct buffer *buf = code_alloc ? ctx->data : ctx->init;
            buffer_write(buf, "@G%d = global [%d x i%d%s] [",
                reg, array, bits, ptr ? stars : "", 16);
            struct node *init = node->parent->mid;
            if (init)
                init = init->left;
            for (int i = 0; i < array; i++) {
                if (i > 0)
                    buffer_write(buf, ", ");
                if (init && init->left) {
                    buffer_write(buf, "i%d %d", bits, init->left->value);
                    init = init->right;
                } else
                    buffer_write(buf, "i%d %d", bits, 0);
            }
            buffer_write(buf, "], align 16\n");
            if (stars)
                free(stars);
        } else
            buffer_write(ctx->init, "%s%d = global i%d %d, align %d\n",
                "@G", reg, bits, val, align(bits));
    } else if (array) {
        char *stars = get_stars(ptr);
        static int arrayinit = 0;
        struct gen_context *global_ctx = get_global_ctx(ctx);

        FATAL(!bits, "Invalid int type: reg %d, bits %d, ptr %d", reg, bits, ptr);
        struct buffer *buf = global_ctx->init;

        buffer_write(code_alloc ? ctx->data : ctx->init, "%%%d = alloca [%d x i%d%s], align %d\n",
            reg, array, bits, ptr ? stars : "", 16);
        buffer_write(buf, "@__const.values.arrayinit%d = private unnamed_addr constant [%d x i%d%s] [",
            ++arrayinit, array, bits, ptr ? stars : "");
        struct node *init = node->parent->mid;
        if (init)
            init = init->left;
        for (int i = 0; i < array; i++) {
            if (i > 0)
                buffer_write(buf, ", ");
            if (init && init->left) {
                buffer_write(buf, "i%d %d", bits, init->left->value);
                init = init->right;
            } else
                buffer_write(buf, "i%d %d", bits, 0);
        }
        buffer_write(buf, "], align 16\n");

        struct variable *tmpv = new_variable(ctx, NULL, V_INT, 8, 0, 1, 0, 0);
        FATAL(!tmpv, "Could not allocate variable");
        buffer_write(code_alloc ? ctx->data : ctx->init, "%%%d = bitcast [%d x i%d]* %%%d to i8*\n",
            tmpv->reg, array, bits, reg);
        if (arrayinit == 1)
            buffer_write(buf, "declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly, i8* noalias nocapture readonly, i64, i1 immarg)\n");
        buffer_write(code_alloc ? ctx->data : ctx->init, "call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 16 %%%d, i8* align 16 bitcast([%d x i%d]* @__const.values.arrayinit%d to i8*), i64 %u, i1 false)\n",
            tmpv->reg, array, bits, arrayinit, array * bits / 8);

        if (stars)
            free(stars);
    } else {
        char *stars = get_stars(ptr);
        char *vals = NULL;
        FATAL(!bits, "Invalid int type: reg %d, bits %d, ptr %d", reg, bits, ptr);
        buffer_write(code_alloc ? ctx->data : ctx->init, "%%%d = alloca i%d%s, align %d ; gen_alloc_int\n",
            reg, bits, ptr ? stars : "", align(bits));
        vals = int_to_str(val);
        buffer_write(code_alloc ? ctx->data : ctx->init,
            "store i%d%s %s, i%d%s* %%%d, align %d ; allocate_int %lld\n",
            bits, ESTR(stars), ptr ? "null" : vals, bits, ESTR(stars), reg, align(bits), val);
        free(vals);
        if (stars)
            free(stars);
    }
    return reg;
}

int gen_allocate_void_ptr(struct gen_context *ctx, int reg, int ptr, int global)
{
    char *stars = get_stars(ptr);

    buffer_write(ctx->init,
        "%s%u = alloca i8%s, align 8\n",
        global ? "@P" : "%", reg, stars);
    return reg;
}

int gen_allocate_struct_union(struct gen_context *ctx, int reg, const struct type *ot, const struct type *t, struct variable *var, int ptrval, int is_union)
{

    char *stars = get_stars(ptrval);

    if (ctx->global) {
        if (ot->is_extern) {
            buffer_write(ctx->init, "@%s = external dso_local global %%%s.%s%s, align 8\n", var->name, is_union ? "union" : "struct", t->name, stars);
            var->ext_name = var->name;
        } else {
            buffer_write(ctx->init, "@G%d = common dso_local global %%%s.%s%s, align 8\n", reg, is_union ? "union" : "struct", t->name, stars);
        }
    } else if (var->array) {
        // TODO generalize these!
        buffer_write(ctx->init, "%%%d = alloca [%u x %%%s.%s%s], align 16 ; gen_allocate_%s\n", var->reg, var->array, is_union ? "union" : "struct", t->name, stars, is_union ? "union" : "struct");
    } else {
        buffer_write(ctx->init, "%%%d = alloca %%%s.%s%s, align 8 ; gen_allocate_%s\n", var->reg, is_union ? "union" : "struct", t->name, stars, is_union ? "union" : "struct");

        /* Zeroing the struct */
        if (ptrval == 0) {
            struct variable *casted;
            static int __initted = 0;

            if (!__initted) {
                struct gen_context *global_ctx = get_global_ctx(ctx);

                buffer_write(global_ctx->init, "declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1 immarg)");
                __initted = 1;
            }

            casted = new_inst_variable(ctx, V_INT, 8, TYPE_UNSIGNED);
            buffer_write(ctx->init, "%%%d = bitcast %%%s.%s* %%%d to i%d%s ; gen_%s_cast_to\n",
                    casted->reg, is_union ? "union" : "struct", t->name, var->reg, 8, "*", is_union ? "union" : "struct");

            buffer_write(ctx->init, "call void @llvm.memset.p0i8.i64(i8* align 4 %%%d, i8 0, i64 %u, i1 false)\n", casted->reg, t->bits / 8);
        }
    }
    free(stars);
    return reg;
}

int gen_allocate_struct(struct gen_context *ctx, int reg, const struct type *ot, const struct type *t, struct variable *var, int ptrval)
{
    return gen_allocate_struct_union(ctx, reg, ot, t, var, ptrval, 0);
}

int gen_allocate_union(struct gen_context *ctx, int reg, const struct type *ot, const struct type *t, struct variable *var, int ptrval)
{
    return gen_allocate_struct_union(ctx, reg, ot, t, var, ptrval, 1);
}

int gen_allocate_double(struct gen_context *ctx, int reg, int bits, int ptr, int code_alloc, literalnum val, literalnum frac)
{
    if (ctx->global) {
        buffer_write(ctx->init, "%s%d = global %s 0.0, align %d\n", "@G", reg, float_str(bits), align(bits));
    } else {
        char *stars = get_stars(ptr);
        char *vals = NULL;
        buffer_write(code_alloc ? ctx->data : ctx->init, "%s%d = alloca %s%s, align %d ; allocate_double\n",
            ctx->global ? "@G" : "%", reg, float_str(bits), ptr ? stars : "", align(bits));
        vals = double_to_str(val, frac);
        buffer_write(code_alloc ? ctx->data : ctx->init,
            "store %s%s %s, %s%s* %%%d, align %d ; allocate_double\n",
            float_str(bits), ESTR(stars), ptr ? "null" : vals, float_str(bits), ESTR(stars), reg, align(bits));
        free(vals);
        if (stars)
            free(stars);
    }
    return reg;
}

int gen_prepare_store_int(struct gen_context *ctx, struct node *n)
{
    if (!n)
        ERR("No valid node given!");
    struct variable *val = find_literal(ctx, V_INT, n->bits, n->value < 0 ? TYPE_SIGNED : TYPE_UNSIGNED, n->value);
    if (val) {
        n->reg = val->reg;
        return val->reg;
    }
    /*
     * It might be we haven't been able to determine bits so far.
     * However we need to have it now since alloc will need bits
     * or it will fail otherwise.
     */
    if (n->bits == 0)
        n->bits = 32;
    // Auto convert to 64 bit if literal is too small
    if ((unsigned int)n->value < n->value)
        n->bits = 64;
    val = new_variable(ctx, NULL, V_INT, n->bits, n->value < 0 ? TYPE_SIGNED : TYPE_UNSIGNED, 0, 0, ctx->global);
    buffer_write(ctx->init, "; Int literal: %d\n", n->value);
#if 0
    // FIXME, causes issue
    if (ctx->is_decl >= 100 && ctx->last_ident) {
        printf("Last ident val to %lld, %p\n", n->value, (void*)ctx->last_ident);
        ctx->last_ident->value = n->value;
    }
#endif
    val->value = n->value;
    val->literal = 1;
    if (!ctx->global)
        val->assigned = 1;
    gen_allocate_int(ctx, val->reg, val->type->bits, 0, 0, 0, n->value, NULL);
    n->reg = val->reg;
    return val->reg;
}

int gen_prepare_store_double(struct gen_context *ctx, struct node *n)
{
    if (!n)
        ERR("No valid node given!");
    struct variable *val = find_literal(ctx, V_FLOAT, n->bits, TYPE_UNSIGNED, n->value);
    if (val) {
        n->reg = val->reg;
        return val->reg;
    }
    val = new_variable(ctx, NULL, V_FLOAT, n->bits, TYPE_SIGNED, 0, 0, ctx->global);

    buffer_write(ctx->init, "; Double literal: %f\n", n->value);
    val->value = n->value;
    val->literal = 1;
    if (!ctx->global)
        val->assigned = 1;
    gen_allocate_double(ctx, val->reg, n->bits, 0, 0, n->value, 0/*n->fraction*/);
    n->reg = val->reg;
    return val->reg;
}

int gen_prepare_store_str(struct gen_context *ctx, struct node *n)
{
    if (!n)
        ERR("No valid node given!");


    struct gen_context *glob = get_global_ctx(ctx);
    FATALN(!glob || !glob->global, n, "No global context found!");

    if (strcmp(n->value_string, "__PRETTY_FUNCTION__") == 0) {
        struct buffer *pretty = buffer_init();
        buffer_write(pretty, "@__PRETTY_FUNCTION__.%s", ctx->name);
        n->value_string = buffer_read(pretty);
        struct variable *val = find_variable_by_name(ctx, buffer_read(pretty));
        FATALN(!val, n, "Didn't find __PRETTY_FUNCTION__");
        buffer_del(pretty);
        n->reg = val->reg;
        return val->reg;
    }
    if (strcmp(n->value_string, "__FUNCTION__") == 0) {
        struct buffer *pretty = buffer_init();
        buffer_write(pretty, "@__FUNCTION__.%s", ctx->name);
        n->value_string = buffer_read(pretty);
        struct variable *val = find_variable_by_name(ctx, buffer_read(pretty));
        FATALN(!val, n, "Didn't find __FUNCTION__");
        buffer_del(pretty);
        n->reg = val->reg;
        return val->reg;
    }

    int slen = 1;
    char *tmpstr = convert_escape(n->value_string, &slen);
    struct variable *val = new_variable(glob, NULL, V_STR, slen, TYPE_UNSIGNED, 0, 0, 1);
    if (!val->type->ptr)
        val->type = type_wrap(ctx, val->type);

    buffer_write(ctx->init, "; String literal: %s\n", n->value_string);
    buffer_write(glob->init, "@.str.%d = private unnamed_addr "
        "constant [%u x i8] c\"%s\\00\", align 1\n",
        val->reg, slen, tmpstr);
    val->array = slen;
    val->literal = 1;
    free(tmpstr);

    n->reg = val->reg;
    return val->reg;
}

int gen_store_int(struct gen_context *ctx, struct node *n)
{
    if (!n)
        ERR("No valid node given!");

    FATALN(!n->reg, n, "No register allocated");
    struct variable *val = find_variable(ctx, n->reg);
    if (val->assigned)
        return val->reg;
    val->value = n->value;

    buffer_write(ctx->data, "store i%d %llu, i%d* %s%d, align %d ; store_int %llu\n",
            val->type->bits, n->value, val->type->bits, REGP(val), val->reg, align(val->type->bits), val->value);
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
    FATALN(!n->reg, n, "No register allocated!");
    struct variable *val = find_variable(ctx, n->reg);
    if (val->assigned)
        return val->reg;

    //char *tmp = double_str(n->value, n->fraction);
    char *tmp = double_str(n->value, 0);

    buffer_write(ctx->data, "store %s %s, %s* %s%d, align %d ; store_double\n",
            float_str(val->type->bits), tmp, float_str(val->type->bits), REGP(val), val->reg, align(val->type->bits));
    return val->reg;
}

int gen_store_string(struct gen_context *ctx, struct node *n)
{
    struct variable *val = find_variable(ctx, n->reg);
    FATALN(!val, n, "No string allocated! %d", n->reg);
    return val->reg;
}

int gen_store_var(struct gen_context *ctx, struct variable *dst, struct variable *src)
{
    FATAL(!dst, "Invalid store destination");
    FATAL(!src, "Invalid store source");

    if (dst->type->type != src->type->type)
        ERR("Source should be same type");

    if (dst->type->type == V_INT) {
        char *stars = get_stars(dst->type->ptr); // FIXME
        buffer_write(ctx->data, "store i%d%s %%%d, i%d%s* %s%d, align %d ; store_var\n",
            src->type->bits, ESTR(stars), src->reg, dst->type->bits, ESTR(stars), REGP(dst), dst->reg, align(dst->type->bits));
        if (stars)
            free(stars);
    } else if (dst->type->type == V_FLOAT) {
        buffer_write(ctx->data, "store %s %%%d, %s* %s%d, align %d ; store_var\n",
            float_str(dst->type->bits), src->reg, float_str(dst->type->bits), REGP(src), dst->reg, align(dst->type->bits));
    }
    return 0;
}

struct variable *gen_access_ptr(struct gen_context *ctx, struct variable *var, struct variable *res, struct variable *idx_var, int index)
{
    if (idx_var)
        index = idx_var->reg;

    if (var->array) {
        buffer_write(ctx->data, "%%%d = getelementptr inbounds [%d x i%d], [%d x i%d]* %s%d, i64 %s%d ; gen_access_ptr array\n",
            res->reg, var->array, var->type->bits, var->array, var->type->bits, REGP(var), var->reg, idx_var ? "%": "", index);
    } else {
        buffer_write(ctx->data, "%%%d = getelementptr inbounds i%d, i%d* %s%d, i64 %s%d ; gen_access_ptr\n",
            res->reg, res->type->bits, res->type->bits, REGP(var), var->reg, idx_var ? "%" : "", index);
    }
    return res;
}

struct variable *gen_access_ptr_item(struct gen_context *ctx, struct variable *var, struct variable *res, struct variable *idx_var, int index)
{
    if (idx_var)
        index = idx_var->reg;
    char *stars = get_stars(res->type->ptr);
    char *stars2 = get_stars(var->type->ptr);

    if (var->array) {
        buffer_write(ctx->data, "%%%d = getelementptr inbounds [%d x i%d], [%d x i%d]* %s%d, i64 0, i64 %s%d ; gen_access_ptr_item arr\n",
            res->reg, var->array, var->type->bits, var->array, var->type->bits, REGP(var), var->reg, idx_var ? "%": "", index);
    } else {
        buffer_write(ctx->data, "%%%d = getelementptr inbounds i%d%s, i%d%s %s%d, i64 %s%d ; gen_access_ptr_item\n",
            res->reg, res->type->bits, ESTR(stars), res->type->bits, ESTR(stars2), REGP(var), var->reg, idx_var ? "%" : "", index);
    }
    if (stars)
        free(stars);
    if (stars2)
        free(stars2);

    return res;
}

struct variable *gen_load_int(struct gen_context *ctx, struct variable *v)
{
    if (v->direct)
        return v;
    struct variable *prev = NULL;
    int reg = v->reg;

    if (v->type->ptr || v->addr) {
        char *stars = get_stars(v->type->ptr);
        prev = new_variable(ctx, NULL, V_INT, v->type->bits, v->type->sign, v->type->ptr, 0, 0);
        buffer_write(ctx->data, "%%%d = load i%d%s, i%d*%s %s%d, align %d ; gen_load_int %d, %d, %d\n",
                prev->reg, prev->type->bits,
                ESTR(stars),
                prev->type->bits,
                ESTR(stars),
                REGP(v), reg, align(prev->type->bits), v->type->ptr, v->addr, v->reg);
        prev->addr = v->addr;
        prev->direct = 1;
        if (stars)
            free(stars);
        return prev;
    }
    if (v->array) {
        struct variable *tmp = new_variable(ctx,
            NULL,
            v->type->type,
            v->type->bits, v->type->sign,
            v->type->ptr + 1,
            0, 0);
        tmp = gen_access_ptr_item(ctx, v, tmp, NULL, 0);
        tmp->direct = 1;
        return tmp;
    }
    struct variable *res = new_variable(ctx, NULL, V_INT, v->type->bits, v->type->sign, v->type->ptr, 0, 0);

    buffer_write(ctx->data, "%%%d = load i%d, i%d* %s%d, align %d; gen_load_int\n",
            res->reg, res->type->bits, res->type->bits,
            REGP(v), reg, align(res->type->bits));
    res->addr = v->addr;
    res->value = v->value;
    res->direct = 1;
    return res;
}

struct variable *gen_load_float(struct gen_context *ctx, struct variable *v)
{
    if (v->direct)
        return v;
    char *stars = get_stars(v->type->ptr);
    struct variable *prev = NULL;
    int reg = v->reg;

    if (v->type->ptr || v->addr) {
        prev = new_variable(ctx, NULL, V_FLOAT, v->type->bits, TYPE_SIGNED, v->type->ptr, 0, 0);
        buffer_write(ctx->data, "%%%d = load %s%s, %s*%s %s%d, align %d ; gen_load_float %d, %d, %d\n",
                prev->reg,
                float_str(v->type->bits),
                ESTR(stars),
                float_str(v->type->bits),
                ESTR(stars),
                REGP(v), reg, align(prev->type->bits), v->type->ptr, v->addr, v->reg);
        prev->addr = v->addr;
        prev->direct = 1;
        free(stars);
        return prev;
    }
    struct variable *res = new_variable(ctx, NULL, V_FLOAT, v->type->bits, TYPE_SIGNED, 0, 0, 0);
    buffer_write(ctx->data, "%%%d = load %s%s, %s%s* %s%d, align %d ; load_float\n",
            res->reg,
            float_str(v->type->bits),
            stars,
            float_str(v->type->bits),
            stars,
            REGP(v),
            v->reg,
            align(v->type->bits));
    res->direct = 1;
    free(stars);
    return res;
}

struct variable *gen_load_str(struct gen_context *ctx, struct variable *v)
{
    // TODO
    return v;
#if 0
    if (v->direct)
        return v;
    struct variable *res = new_variable(ctx, NULL, V_FLOAT, v->type->bits, TYPE_SIGNED, 0, 0);

    buffer_write(ctx->data, "%%%d = load double, double* %s%d, align %d\n",
            res->reg, REGP(v), v->reg, align(v->type->bits));
    return res;
#endif
}

struct variable *gen_load_void(struct gen_context *ctx, struct variable *v)
{
    if (!v->type->ptr)
        return v;

    struct variable *res = NULL;
    char *stars = get_stars(v->type->ptr);

    res = new_variable(ctx, NULL, V_VOID, 8, TYPE_UNSIGNED, v->type->ptr, 0, 0);
    buffer_write(ctx->data, "%%%d = load i%d%s, i%d*%s %s%d, align %d\n",
            res->reg, 8, //res->type->bits,
            ESTR(stars),
            8, //res->type->bits,
            ESTR(stars),
            REGP(v), v->reg, align(res->type->bits), v->type->ptr, v->addr);
    res->addr = v->addr;
    res->direct = 1;
    if (stars)
        free(stars);

    return res;
}

struct variable *gen_load_struct_union(struct gen_context *ctx, struct variable *v, int is_union)
{
    struct variable *res = NULL;
    char *stars = get_stars(v->type->ptr);
    char *sname = is_union ? "union" : "struct";

    buffer_write(ctx->data, "; load from %d ptr %d\n", v->reg, v->type->ptr);
    // Refuse to load ptr to non-ptr
    if (v->array) {
        res = new_variable_ext(ctx, NULL, V_STRUCT, v->type->bits, v->type->sign, v->type->ptr + 1, 0, 0, v->type->type_name);
        buffer_write(ctx->data, "%%%d = getelementptr inbounds [%d x %%struct.%s], [%d x %%struct.%s]* %s%d, i64 0, i64 0 ; loadptr %s array\n",
            res->reg,
            v->array, v->type->type_name,
            v->array, v->type->type_name,
            REGP(v), v->reg, sname);
    } else if (v->type->ptr < 1) {
        free(stars);
        stars = get_stars(v->type->ptr + 1);
        res = new_variable_ext(ctx, NULL, V_STRUCT, v->type->bits, v->type->sign, v->type->ptr + 1, 0, 0, v->type->type_name);
        buffer_write(ctx->data, "%%%d = alloca %%%s.%s%s, align %d\n",
            res->reg,
            sname,
            v->type->type_name,
            stars, 8);
        buffer_write(ctx->data, "store %%%s.%s%s %s%d, %%%s.%s%s* %%%d, align %d ; load %s ptr-nonptr\n",
            sname,
            v->type->type_name,
            stars,
            REGP(v),
            v->reg,
            sname,
            v->type->type_name,
            stars,
            res->reg,
            8,
            sname);
        //buffer_write(ctx->data, "%%%d = bitcast %%struct.%s%s, %%struct.%s*%s %s%d, align %d ; gen_load_struct\n",
        res->direct = 0;

        free(stars);

        FATAL(res->type == v->type, "Couldn't change type");
        return gen_load_struct(ctx, res);

    } else {
        res = new_variable_ext(ctx, NULL, V_STRUCT, v->type->bits, v->type->sign, v->type->ptr, 0, 0, v->type->type_name);
#if 0
        buffer_write(ctx->data, "%%%d = load %%%s.%s%s, %%%s.%s*%s %s%d, align %d ; gen_load_%s\n",
                res->reg,
                sname,
                v->type->type_name,
                ESTR(stars),
                sname,
                v->type->type_name,
                ESTR(stars),
                REGP(v), v->reg, 8, sname);
#else
        char *nn = get_name(v);
        buffer_write(ctx->data, "%%%d = load %%%s.%s%s, %%%s.%s*%s %s, align %d ; gen_load_%s\n",
            res->reg,
            sname,
            v->type->type_name,
            ESTR(stars),
            sname,
            v->type->type_name,
            ESTR(stars),
            nn, 8, sname);
        free(nn);
#endif
        res->direct = 1;
    }
    res->addr = v->addr;
    if (stars)
        free(stars);

    return res;
}

struct variable *gen_load_struct(struct gen_context *ctx, struct variable *v)
{
    return gen_load_struct_union(ctx, v, 0);
}

struct variable *gen_load_union(struct gen_context *ctx, struct variable *v)
{
    return gen_load_struct_union(ctx, v, 1);
}

struct variable *gen_load_func(struct gen_context *ctx, struct variable *v)
{
        if (v->func)
            return v;

        char *stars = get_stars(v->type->ptr + 1);
        struct variable *res = new_variable_ext(ctx, NULL, V_FUNCPTR, v->type->bits, v->type->sign, v->type->ptr, 0, 0, v->type->type_name);
        char *ret = get_type_str(ctx, v->type->retval);
        char *par = get_param_type_str(ctx, v->type->params);

        buffer_write(ctx->data, "%%%d = load %s (%s)%s, %s (%s)%s* %%%u, align %d ; gen_load_func\n",
            res->reg,
            ret, par, ESTR(stars),
            ret, par, ESTR(stars),
            v->reg, 8);
        if (stars)
            free(stars);

        return res;
}

struct variable *gen_load_null(struct gen_context *ctx, struct variable *v)
{
#if 1
    struct variable *res = new_variable_ext(ctx, NULL, V_NULL, 0, TYPE_UNSIGNED, 1, 0, 0, NULL);
    char *stars = get_stars(v->type->ptr + 1);

    buffer_write(ctx->data, "%%%d = load i8%s, i8%s* %s%u, align 4; gen_load_null\n",
        res->reg, ESTR(stars),
        ESTR(stars), REGP(v), v->reg);
    return res;
#else
    return v;
#endif
}

struct variable *gen_load(struct gen_context *ctx, struct variable *v)
{
    if (v == NULL)
        ERR("Can't load null!");

    if (v->direct)
        return v;

    //struct type *type = custom_type_get(ctx, v->type);
    switch (v->type->type) {
        case V_INT:
            return gen_load_int(ctx, v);
        case V_FLOAT:
            return gen_load_float(ctx, v);
        case V_STR:
            return gen_load_str(ctx, v);
        case V_VOID:
            return gen_load_void(ctx, v);
        case V_STRUCT:
            return gen_load_struct(ctx, v);
        case V_UNION:
            return gen_load_union(ctx, v);
        case V_FUNCPTR:
            return gen_load_func(ctx, v);
        case V_NULL:
            return gen_load_null(ctx, v);
        case V_CUSTOM:
            return v;
        default:
            stack_trace();
    }

    ERR("Invalid type: %d, %s", v->type->type, stype_str(v->type));
}

enum var_type get_and_cast(struct gen_context *ctx, struct variable **v1, struct variable **v2)
{
    FATAL(!*v1, "Can't load v1 in cast");
    *v1 = gen_load(ctx, *v1);
    FATAL(!*v2, "Can't load v2 in cast");
    *v2 = gen_load(ctx, *v2);

    enum var_type restype = resolve_type((*v1)->type->type, (*v2)->type->type);
    const struct type *target = find_type_by(ctx, restype, 0, TYPE_SIGNED, 0);
    FATAL(!target, "No target in cast");
    *v1 = gen_cast(ctx, *v1, target, 0);
    *v2 = gen_cast(ctx, *v2, target, 0);

    if (restype == V_INT) {
        *v1 = gen_bits(ctx, *v1, *v2);
        *v2 = gen_bits(ctx, *v2, *v1);
    }

    return restype;
}

struct variable *gen_fix_ptr_index(struct gen_context *ctx, struct node *node, struct variable **v1, struct variable **v2, int negate)
{
    if ((*v1)->array || (*v1)->type->ptr || (*v2)->type->ptr) {
         struct variable *idx;

        if ((*v2)->type->ptr && !(*v1)->type->ptr && !(*v1)->array) {
            struct variable *tmp = *v1;
            *v1 = *v2;
            *v2 = tmp;
        }
        struct type idx_target;
        idx_target.type = V_INT;
        idx_target.bits = 64;
        idx_target.sign = TYPE_UNSIGNED;

        idx = load_and_cast_to(ctx, *v2, &idx_target, CAST_NORMAL);
        if (negate) {
            int idx_neg = gen_negate(ctx, node, idx->reg);
            idx = find_variable(ctx, idx_neg);
        }
        return idx;
    }
    return NULL;
}

int gen_add(struct gen_context *ctx, struct node *node, int a, int b)
{
    struct variable *v1 = find_variable(ctx, a);
    struct variable *v2 = find_variable(ctx, b);
    struct variable *idx = gen_fix_ptr_index(ctx, node, &v1, &v2, 0);
    enum var_type restype = get_and_cast(ctx, &v1, &v2);
    struct variable *res = new_inst_variable(ctx, restype, v1->type->bits, v1->type->sign || v2->type->sign ? TYPE_SIGNED : TYPE_UNSIGNED);

    if (v1->type->ptr) {
        FATALN(!idx, node, "Invalid index on add to ptr");
        gen_access_ptr(ctx, v1, res, idx, 0);
        res->type = type_wrap_to(ctx, res->type, v1->type->ptr);
    } else if (restype == V_INT) {
        res->value = v1->value + v2->value;
        buffer_write(ctx->data, "%%%d = add i%d %%%d, %%%d\n",
            res->reg, v1->type->bits, v1->reg, v2->reg);
    } else if (restype == V_FLOAT) {
        buffer_write(ctx->data, "%%%d = fadd double %%%d, %%%d\n",
            res->reg, v1->reg, v2->reg);
    } else
        ERR("Invalid type: %d", restype);
    return res->reg;
}

int gen_sub(struct gen_context *ctx, struct node *node, int a, int b)
{
    struct variable *v1 = find_variable(ctx, a);
    struct variable *v2 = find_variable(ctx, b);
    struct variable *idx = gen_fix_ptr_index(ctx, node, &v1, &v2, 1);
    enum var_type restype = get_and_cast(ctx, &v1, &v2);
    struct variable *res = new_inst_variable(ctx, restype, v1->type->bits, v1->type->sign || v2->type->sign ? TYPE_SIGNED : TYPE_UNSIGNED);

    if (v1->type->ptr) {
        FATALN(!idx, node, "Invalid index on add to ptr");
        gen_access_ptr(ctx, v1, res, idx, 0);
        res->type = type_wrap_to(ctx, res->type, v1->type->ptr);
    } else if (restype == V_INT) {
        buffer_write(ctx->data, "%%%d = sub i%d %%%d, %%%d\n",
            res->reg, v1->type->bits, v1->reg, v2->reg);
    } else if (restype == V_FLOAT) {
        buffer_write(ctx->data, "%%%d = fsub double %%%d, %%%d\n",
            res->reg, v1->reg, v2->reg);
    } else
        ERR("Invalid type: %d", restype);
    return res->reg;
}

int gen_mul(struct gen_context *ctx, struct node *node, int a, int b)
{
    struct variable *v1 = find_variable(ctx, a);
    struct variable *v2 = find_variable(ctx, b);
    enum var_type restype = get_and_cast(ctx, &v1, &v2);
    struct variable *res = new_inst_variable(ctx, restype, v1->type->bits, v1->type->sign || v2->type->sign ? TYPE_SIGNED : TYPE_UNSIGNED);

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

int gen_div(struct gen_context *ctx, struct node *node, int a, int b)
{
    struct variable *v1 = find_variable(ctx, a);
    struct variable *v2 = find_variable(ctx, b);
    enum var_type restype = get_and_cast(ctx, &v1, &v2);
    struct variable *res = new_inst_variable(ctx, restype, v1->type->bits, v1->type->sign || v2->type->sign ? TYPE_SIGNED : TYPE_UNSIGNED);

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

int gen_mod(struct gen_context *ctx, struct node *node, int a, int b)
{
    struct variable *v1 = find_variable(ctx, a);
    struct variable *v2 = find_variable(ctx, b);
    enum var_type restype = get_and_cast(ctx, &v1, &v2);
    struct variable *res = new_inst_variable(ctx, restype, v1->type->bits, v1->type->sign || v2->type->sign ? TYPE_SIGNED : TYPE_UNSIGNED);

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

int gen_shift(struct gen_context *ctx, struct node *node, enum nodetype type, int a, int b)
{
    struct variable *v1 = find_variable(ctx, a);
    struct variable *v2 = find_variable(ctx, b);
    enum var_type restype = get_and_cast(ctx, &v1, &v2);
    struct variable *res = new_inst_variable(ctx, restype, v1->type->bits, v1->type->sign || v2->type->sign ? TYPE_SIGNED : TYPE_UNSIGNED);

    if (restype == V_INT) {
        buffer_write(ctx->data, "%%%d = %s i%d %%%d, %%%d\n",
            res->reg, type == A_LEFT ? "shl" : "ashr",
            v1->type->bits, v1->reg, v2->reg);
    } else
        ERR("Invalid type for shift: %d", restype);
    return res->reg;
}

int gen_bitwise(struct gen_context *ctx, struct node *node, enum nodetype type, int a, int b)
{
    struct variable *v1 = find_variable(ctx, a);
    struct variable *v2 = find_variable(ctx, b);
    enum var_type restype = get_and_cast(ctx, &v1, &v2);
    struct variable *res = new_inst_variable(ctx, restype, v1->type->bits, v1->type->sign || v2->type->sign ? TYPE_SIGNED : TYPE_UNSIGNED);

    if (restype == V_INT) {
        const char *op;

        switch (type) {
            case A_OR:
                op = "or";
                break;
            case A_XOR:
                op = "xor";
                break;
            case A_AND:
                op = "and";
                break;
            default:
                ERR("Invalid inclusive operator: %d", type);
        }

        buffer_write(ctx->data, "%%%d = %s i%d %%%d, %%%d\n",
            res->reg, op,
            v1->type->bits, v1->reg, v2->reg);
    } else
        ERR("Invalid type for inclusive operation: %d", restype);
    return res->reg;
}

int gen_bool_cast(struct gen_context *ctx, struct variable *var)
{
    var = gen_load(ctx, var);
    FATAL(!var, "Didn't get variable");

    struct variable *res = new_bool(ctx, VAR_DIRECT);

    if (var->type->type == V_INT) {
        buffer_write(ctx->data, "%%%d = icmp ne i%d %%%d, 0\n",
            res->reg, var->type->bits, var->reg);
    } else
        ERR("Invalid type for bool cast: %d", var->type->type);


    return res->reg;
}

int gen_recursive(struct gen_context *ctx, struct node *node);
int gen_logical_op(struct gen_context *ctx, struct node *node, enum logical_op_type op)
{
    FATALN(!node->left, node, "Exclusive or/and no left hand tree");
    FATALN(!node->right, node, "Exclusive or/and no right hand tree");

    struct variable *real_res = new_bool_alloc(ctx, VAR_NORMAL);

    int a = gen_recursive(ctx, node->left);
    struct variable *v1 = find_variable(ctx, a);
    int src1 = gen_bool_cast(ctx, v1);

    struct variable *res = new_bool(ctx, VAR_DIRECT);
    buffer_write(ctx->data, "%%%d = icmp eq i1 %%%d, 1\n",
        res->reg, src1);

    struct buffer *and_ok = buffer_init();

    int label1 = gen_reserve_label(ctx);
    struct variable *res3 = new_bool(ctx, VAR_DIRECT);
    buffer_write(and_ok, "L%d:\n", label1);
    buffer_write(and_ok, "%%%d = icmp eq i1 %%%d, 1\n",
        res3->reg, src1);

    struct buffer *tmp = ctx->data;
    ctx->data = and_ok;
    int b = gen_recursive(ctx, node->right);
    struct variable *v2 = find_variable(ctx, b);
    int src2 = gen_bool_cast(ctx, v2);
    struct variable *res2 = new_bool(ctx, VAR_DIRECT);
    buffer_write(and_ok, "%%%d = icmp eq i1 %%%d, 1\n",
        res2->reg, src2);
    ctx->data = tmp;

    int label2 = gen_reserve_label(ctx);
    int label3 = gen_reserve_label(ctx);
    if (op == LOGICAL_OR)
        buffer_write(ctx->data, "br i1 %%%d, label %%L%d, label %%L%d\n",
            res->reg, label3, label1);
    else
        buffer_write(ctx->data, "br i1 %%%d, label %%L%d, label %%L%d\n",
            res->reg, label1, label3);
    buffer_append(ctx->data, buffer_read(and_ok));
    if (op == LOGICAL_OR)
        buffer_write(ctx->data, "br i1 %%%d, label %%L%d, label %%L%d\n",
            res2->reg, label3, label2);
    else
        buffer_write(ctx->data, "br i1 %%%d, label %%L%d, label %%L%d\n",
            res2->reg, label2, label3);
    buffer_write(ctx->data, "L%d:\n", label2);
    if (op == LOGICAL_OR)
        buffer_write(ctx->data, "store i1 0, i1 *%%%d\n",
            real_res->reg);
    else
        buffer_write(ctx->data, "store i1 1, i1 *%%%d\n",
            real_res->reg);
    int label4 = gen_reserve_label(ctx);
    buffer_write(ctx->data, "br label %%L%d\n",
        label4);

    buffer_write(ctx->data, "L%d:\n", label3);
    if (op == LOGICAL_OR)
        buffer_write(ctx->data, "store i1 1, i1 *%%%d\n",
            real_res->reg);
    else
        buffer_write(ctx->data, "store i1 0, i1 *%%%d\n",
            real_res->reg);
    buffer_write(ctx->data, "br label %%L%d\n",
        label4);
    buffer_write(ctx->data, "L%d:\n", label4);
    return real_res->reg;
}

int gen_logical_and(struct gen_context *ctx, struct node *node)
{
    return gen_logical_op(ctx, node, LOGICAL_AND);
}

int gen_logical_or(struct gen_context *ctx, struct node *node)
{
    return gen_logical_op(ctx, node, LOGICAL_OR);
}

int gen_eq(struct gen_context *ctx, struct node *node, int a, int b)
{
    struct variable *v1 = find_variable(ctx, a);
    struct variable *v2 = find_variable(ctx, b);
    FATALN(!v1, node, "No cmp1 var");
    FATALN(!v2, node, "No cmp2 var");
    v1 = gen_load(ctx, v1);
    v2 = gen_load(ctx, v2);

    FATALN(!v1, node, "No cmp1 var");
    FATALN(!v2, node, "No cmp2 var");

    if (v1->type->type == V_INT && v2->type->type == V_INT) {
        if (v1->type->bits == v2->type->bits);
        else if (v1->type->bits > v2->type->bits)
            v2 = gen_bits_cast(ctx, v2, v1->bits, TYPE_SIGNED);
        else
            v1 = gen_bits_cast(ctx, v1, v2->bits, TYPE_SIGNED);

        struct variable *res = new_bool(ctx, VAR_DIRECT);
        char *stars1 = get_stars(v1->type->ptr);
        const char *op = node->node == A_EQ_OP ? "eq" : "ne";
        buffer_write(ctx->data, "%%%d = icmp %s i%d%s %%%d, "
            "%%%d\n",
            res->reg, op,
            v1->type->bits, ESTR(stars1), v1->reg,
            v2->reg);

        if (stars1)
            free(stars1);
        return res->reg;
    } else if (v1->type->type == V_FLOAT && v2->type->type == V_FLOAT) {
        if (v1->type->bits == v2->type->bits);
        else if (v1->type->bits > v2->type->bits)
            v2 = gen_bits_cast(ctx, v2, v1->bits, TYPE_SIGNED);
        else
            v1 = gen_bits_cast(ctx, v1, v2->bits, TYPE_SIGNED);

        struct variable *res = new_bool(ctx, VAR_DIRECT);
        char *stars1 = get_stars(v1->type->ptr);
        const char *op = node->node == A_EQ_OP ? "oeq" : "une";
        buffer_write(ctx->data, "%%%d = fcmp %s %s %%%d%s, "
            "%%%d\n",
            res->reg, op,
            float_str(v1->type->bits),
            v1->reg, ESTR(stars1),
            v2->reg);

        if (stars1)
            free(stars1);
        return res->reg;
    }
    else if ((v1->type->type == V_INT && v2->type->type == V_NULL ) || (v1->type->type == V_NULL && v2->type->type == V_INT)) {
        struct variable *res = new_bool(ctx, VAR_DIRECT);
        if (v1->type->type == V_NULL)
            v1 = v2;

        char *stars1 = get_stars(v1->type->ptr);
        const char *op = node->node == A_EQ_OP ? "eq" : "ne";
        buffer_write(ctx->data, "%%%d = icmp %s i%d%s %%%d, null\n",
            res->reg, op,
            v1->type->bits, ESTR(stars1), v1->reg);

        if (stars1)
            free(stars1);
        return res->reg;
    } else if (v1->type->type == V_STRUCT && v2->type->type == V_STRUCT) {
        struct variable *res = new_bool(ctx, VAR_DIRECT);
        const char *op = node->node == A_EQ_OP ? "eq" : "ne";
        char *stars1 = get_stars(v1->type->ptr);
        buffer_write(ctx->data, "%%%d = icmp %s %%struct.%s%s %%%u, %%%u\n",
            res->reg, op,
            v1->type->type_name,
            ESTR(stars1),
            v1->reg,
            v2->reg);
        if (stars1)
            free(stars1);
        return res->reg;
    } else if (v1->type->type == V_STRUCT && (v2->type->type == V_NULL ||
            (v2->type->type == V_INT && v2->value == 0))) {
        struct variable *res = new_bool(ctx, VAR_DIRECT);
        const char *op = node->node == A_EQ_OP ? "eq" : "ne";
        char *stars1 = get_stars(v1->type->ptr);
        buffer_write(ctx->data, "%%%d = icmp %s %%struct.%s%s %%%u, null\n",
            res->reg, op,
            v1->type->type_name,
            ESTR(stars1),
            v1->reg);
        if (stars1)
            free(stars1);
        return res->reg;
    }

    ERR("Invalid EQ: %s != %s", type_str(v1->type->type), type_str(v2->type->type));
    return 0;
}

int gen_lt_gt(struct gen_context *ctx, struct node *node, int a, int b)
{
    struct variable *v1 = find_variable(ctx, a);
    struct variable *v2 = find_variable(ctx, b);
    FATALN(!v1, node, "No cmp1 var");
    FATALN(!v2, node, "No cmp2 var");
    v1 = gen_load(ctx, v1);
    v2 = gen_load(ctx, v2);

    FATALN(!v1, node, "No cmp1 var");
    FATALN(!v2, node, "No cmp2 var");

    if (v1->type->type == V_INT && v2->type->type == V_INT) {
        if (v1->type->bits == v2->type->bits);
        else if (v1->type->bits > v2->type->bits)
            v2 = gen_bits_cast(ctx, v2, v1->bits, TYPE_SIGNED);
        else
            v1 = gen_bits_cast(ctx, v1, v2->bits, TYPE_SIGNED);

        struct variable *res = new_bool(ctx, VAR_DIRECT);
        char *stars1 = get_stars(v1->type->ptr);
        const char *op;
        int unsig = !v1->type->sign || !v2->type->sign;
        switch (node->node) {
            case A_LT:
                op = unsig ? "ult": "slt";
                break;
            case A_GT:
                op = unsig ? "ugt": "sgt";
                break;
            case A_LT_EQ:
                op = unsig ? "ule": "sle";
                break;
            case A_GT_EQ:
                op = unsig ? "uge": "sge";
                break;
            default:
                ERR("Invalid operator: %d\n", node->node);
        }
        buffer_write(ctx->data, "%%%d = icmp %s i%d%s %%%d, "
            "%%%d\n",
            res->reg, op,
            v1->type->bits, ESTR(stars1), v1->reg,
            v2->reg);

        if (stars1)
            free(stars1);
        return res->reg;
    }
    else if (v1->type->type == V_FLOAT && v2->type->type == V_FLOAT) {
        struct variable *res = new_bool(ctx, VAR_DIRECT);
        char *stars1 = get_stars(v1->type->ptr);
        const char *op;
        int ordered = 1;
        switch (node->node) {
            case A_LT:
                op = ordered ? "olt": "ult";
                break;
            case A_GT:
                op = ordered ? "ogt": "ugt";
                break;
            case A_LT_EQ:
                op = ordered ? "ole": "ule";
                break;
            case A_GT_EQ:
                op = ordered ? "oge": "uge";
                break;
            default:
                ERR("Invalid operator: %d\n", node->node);
        }
        buffer_write(ctx->data, "%%%d = fcmp %s double %%%d%s, "
            "%%%d\n",
            res->reg, op,
            v1->reg, ESTR(stars1),
            v2->reg);

        if (stars1)
            free(stars1);
        return res->reg;
    }
    ERR("Invalid comparison: %s != %s", type_str(v1->type->type), type_str(v2->type->type));

    return 0;
}

int gen_negate(struct gen_context *ctx, struct node *node, int a)
{
    struct variable *v = find_variable(ctx, a);
    struct variable *res;

    FATALN(!v, node, "Invalid variable in negate");
    v = gen_load(ctx, v);
    if (v->type->type == V_INT) {
        res = new_inst_variable(ctx, v->type->type, v->type->bits, TYPE_SIGNED);
        buffer_write(ctx->data, "%%%d = sub i%d 0, %%%d\n",
            res->reg, v->type->bits, v->reg);
    } else if (v->type->type == V_FLOAT) {
        res = new_inst_variable(ctx, v->type->type, v->type->bits, TYPE_SIGNED);
        buffer_write(ctx->data, "%%%d = fsub double 0.0, %%%d\n",
            res->reg, v->reg);
    } else
        ERR("Invalid type of %d: %d", a, v->type->type);

    return res->reg;
}

int gen_tilde(struct gen_context *ctx, struct node *node, int a)
{
    struct variable *v = find_variable(ctx, a);
    struct variable *res;

    FATALN(!v, node, "Invalid variable in tilde op");
    v = gen_load(ctx, v);
    if (v->type->type == V_INT) {
        res = new_inst_variable(ctx, v->type->type, v->type->bits, TYPE_SIGNED);
        buffer_write(ctx->data, "%%%d = xor i%d -1, %%%d\n",
            res->reg, v->type->bits, v->reg);
    } else
        ERR("Invalid type for unary tilde %d: %d", a, v->type->type);

    return res->reg;
}

int gen_not(struct gen_context *ctx, struct node *node, int a)
{
    struct variable *v = find_variable(ctx, a);
    struct variable *tmp;
    struct variable *res;

    FATALN(!v, node, "Invalid variable in not");
    v = gen_load(ctx, v);
    if (v->type->type == V_INT) {
        if (v->type->ptr) {
            char *stars = get_stars(v->type->ptr);
            tmp = new_inst_variable(ctx, v->type->type, 1, TYPE_UNSIGNED);
            buffer_write(ctx->data, "%%%d = icmp ne i%d%s %%%d, null\n",
                tmp->reg, v->type->bits, ESTR(stars), v->reg);
            if (stars)
                free(stars);
        } else {
            tmp = new_inst_variable(ctx, v->type->type, 1, TYPE_UNSIGNED);
            buffer_write(ctx->data, "%%%d = icmp ne i%d %%%d, 0\n",
                tmp->reg, v->type->bits, v->reg);
        }
    } else if (v->type->type == V_FLOAT) {
        tmp = new_inst_variable(ctx, v->type->type, 1, TYPE_UNSIGNED);
        buffer_write(ctx->data, "%%%d = fcmp ne double %%%d, 0.0\n",
            tmp->reg, v->reg);
    } else
        ERR("Invalid type of %d: %d", a, v->type->type);

    res = new_bool(ctx, VAR_DIRECT);
    buffer_write(ctx->data, "%%%d = xor i%d %%%d, true\n",
        res->reg, tmp->type->bits, tmp->reg);
    return res->reg;
}

char *gen_call_params(struct gen_context *ctx, struct node *provided, struct node *param_node, struct node *func)
{
    if (!provided)
        return NULL;
    struct node *wanted = param_node;

    FATALN(provided->node != A_LIST, provided, "Parameters is not list");

    struct buffer *params = buffer_init();
    int paramcnt = 0;
    enum builtin_function builtin = builtin_func(func->value_string);
    int ellipsis = 0;

    while (provided) {
        struct node *pval = NULL;
        struct node *ptype = NULL;
        struct node *pname = NULL;
        if (ellipsis)
            pval = NULL;
        else {
            pval = wanted;
            if (!pval) {
                printf("a: %u\n", ellipsis);
                node_walk(param_node);
            }
            FATAL(!pval, "Too many parameters for %s", func->value_string);
            if (wanted->right && wanted->right->node == A_LIST)
                pval = wanted->left;
            pval = flatten_list(pval);

            ptype = pval->left;
            FATALN(!ptype, pval, "Invalid parameter");
            pname = pval->right;
            if (ptype->node == A_ELLIPSIS)
                ellipsis = 1;
#if 0
            int t = get_type_list(ctx, ptype);
            FATALN(t >= 0, pval, "Invalid parameter type: %s", node_type_str(ptype->node));
            const struct type *par_type = custom_type_get(ctx, find_type_by_id(ctx, REF_CTX(t)));
            FATALN(!par_type, pval, "Invalid parameter type: %s", node_type_str(ptype->node));
#endif
        }

        int r = gen_recursive(ctx, provided->left);
        FATALN(!r, provided, "Expected parameter for function call: %u", r);

        struct variable *par = find_variable(ctx, r);
        par = gen_load(ctx, par);
        FATALN(!par, provided, "Invalid parameter for function call");
        int pointer = 0;
        if (pname) {
            while (pname && pname->node == A_POINTER) {
                pointer += pname->ptr;
                pname = pname->left;
            }
            pointer += ptype->ptr;
        } else if (ellipsis) {
            if (par)
                pointer = par->type->ptr;
            else if (ptype)
                pointer = ptype->ptr;
        }

        paramcnt++;
        if (builtin == BUILTIN_VA_START && paramcnt > 1)
            break;
        if (builtin == BUILTIN_VA_END && paramcnt > 1)
            break;
        char *stars = get_stars(pointer);
        struct variable *tgt;
        const struct type *target;
        struct type target_raw;
        const char *type_name = NULL;
        int type_ptr;

        if (!ellipsis) {
            target_raw.type = ptype->type;
            target_raw.bits = ptype->bits;
            target_raw.sign = ptype->sign;
            type_name = ptype->type_name;
            //type_ptr = ptype->ptr;
            type_ptr = pointer;
            //if (!type_ptr && par->ptr)
            //    type_ptr = par->ptr;
            target_raw.ptr = type_ptr;
            if (target_raw.type == V_CUSTOM && ptype->left)
                target = find_type_by_name(ctx, ptype->left->value_string);
            else
                target =  &target_raw;
        } else {
            target_raw.type = par->type->type;
            target_raw.bits = par->type->bits;
            if (target_raw.type == V_INT && target_raw.bits == 0)
                target_raw.bits = 32;
            target_raw.sign = par->type->sign;
            type_name = par->type->type_name;
            //type_ptr = par->ptr;
            type_ptr = pointer;
            target_raw.ptr = type_ptr;
            if (target_raw.type == V_CUSTOM && ptype->left)
                target = find_type_by_name(ctx, ptype->left->value_string);
            else
                target =  &target_raw;
        }
        if (target->type == V_CUSTOM)
            target = custom_type_get(ctx, target);
#if 0
        if (target_raw.type == V_CUSTOM) {
            printf("NAME: %s\n", ptype->left->value_string);
            node_walk(ptype);
            target = custom_type_get(ctx, &target_raw);
        } else
            target =  &target_raw;
#endif
        switch (target->type) {
            case V_INT:
                tgt = load_and_cast_to(ctx, par, target, CAST_NO_LOAD_STRUCT);
                buffer_write(params, "%si%d%s %%%d",
                    paramcnt > 1 ? ", " : "",
                    target->bits,
                    ESTR(stars),
                    tgt->reg);
                break;
            case V_FLOAT:
                tgt = load_and_cast_to(ctx, par, target, CAST_NORMAL);
                buffer_write(params, "%sdouble%s %%%d",
                    paramcnt > 1 ? ", " : "",
                    ESTR(stars),
                    tgt->reg);
                break;
            case V_STRUCT:
                tgt = load_and_cast_to(ctx, par, target, CAST_NORMAL);
                buffer_write(params, "%s%%struct.%s%s %%%d",
                    paramcnt > 1 ? ", " : "",
                    type_name,
                    ESTR(stars),
                    tgt->reg);
                break;
            case V_UNION:
                buffer_write(params, "%s%%union.%s%s %%%d",
                    paramcnt > 1 ? ", " : "",
                    type_name,
                    ESTR(stars),
                    par->reg);
                break;
            case V_STR:
                buffer_write(params, "%si8* getelementptr inbounds "
                    "([%d x i8], [%d x i8]* @.str.%d, i32 0, i32 0)",
                    paramcnt > 1 ? ", " : "",
                    par->bits, par->bits, par->reg);
                break;
            case V_VOID:
                if (type_ptr) {
                    buffer_write(params, "%si8%s %s%d",
                        paramcnt > 1 ? ", " : "",
                        ESTR(stars),
                        REGP(par),
                        par->reg);
                }
                break;
            default:
                ERR("Invalid parameter type: %s", type_str(ptype->type));
        }

        if (stars)
            free(stars);
        if (provided->right == NULL || (!ellipsis && wanted->right == NULL))
            break;
        provided = provided->right;
        if (!ellipsis)
            wanted = wanted->right;
        else
            wanted = NULL;
    }
    FATALN(wanted && !provided, param_node, "Not enought parameters");

    const char *tmp = buffer_read(params);
    int tmplen = strlen(tmp) + 1;
    char *res = calloc(1, tmplen);
    res = memcpy(res, tmp, tmplen);
    buffer_del(params);
    return res;
}

int gen_func_call(struct gen_context *ctx, struct node *node)
{
    int func_name_reg = gen_recursive(ctx, node->left);
    struct variable *func = find_variable(ctx, func_name_reg);
    struct variable *res = NULL;
    char *paramstr;

    FATALN(!func, node, "Invalid function to call");
    //FATALN(!func->func, node, "Not calling a function");
    struct variable *fn = func;
    if (!func->func)
        fn = gen_load(ctx, func);
    enum builtin_function builtin = builtin_func(func->name);
    if (builtin == BUILTIN_VA_START) {
        func->name = "llvm.va_start";
        func->paramstr = strcopy("i8*");
    } else if (builtin == BUILTIN_VA_END) {
        func->name = "llvm.va_end";
        func->paramstr = strcopy("i8*");
    } else if (builtin == BUILTIN_BSWAP16) {
        func->name = "llvm.bswap.16";
        func->paramstr = strcopy("i16");
    } else if (builtin == BUILTIN_BSWAP32) {
        func->name = "llvm.bswap.32";
        func->paramstr = strcopy("i32");
    } else if (builtin == BUILTIN_BSWAP64) {
        func->name = "llvm.bswap.64";
        func->paramstr = strcopy("i64");
    } else if (builtin == BUILTIN_VA_ARG) {
        func->name = "llvm.va_arg";

        struct node *params = node->right;
        FATALN(!params, node, "No params in va_args");
        FATALN(!params->left, node, "No first argument in va_args");

        struct node *valistnode = params->left;
        struct node *partype = params->right;
        const struct type *thetype = gen_type_list_type(ctx, partype);
        FATALN(!thetype, node, "Invadid va_arg destination type");

        struct type target;
        target.type = V_INT;
        target.bits = 8;
        target.sign = TYPE_UNSIGNED;
        target.ptr = 1;

        int valist_reg = gen_recursive(ctx, valistnode);
        FATALN(!valist_reg, valistnode, "Invalid va_list for va_arg, can't resolve");
        struct variable *valist_var = find_variable(ctx, valist_reg);
        FATALN(!valist_var, valistnode, "Invalid va_list for va_arg");

        struct variable *src = load_and_cast_to(ctx, valist_var, &target, CAST_NO_LOAD_STRUCT);
        FATALN(!src, valistnode, "Can't cast va_list argument to u8*");

        res = new_inst_variable(ctx, thetype->type, thetype->bits, thetype->sign);
        if (thetype->type == V_INT) {
            buffer_write(ctx->data, "%%%d = va_arg i8* %%%d, i%d\n",
                res->reg,
                src->reg,
                thetype->bits);
        } else
            ERR("Unsupported type for va_arg");

        return res->reg;
    }
    if (!func->params)
        paramstr = gen_call_params(ctx, node->right, func->type->params, node->left);
    else
        paramstr = gen_call_params(ctx, node->right, func->params, node->left);
    const struct type *func_ret_type = func->type->retval;
    FATAL(!func_ret_type, "Didn't get return type for function: %s", func->name);
    if (func_ret_type->type == V_CUSTOM) {
        func_ret_type = custom_type_get(ctx, func_ret_type);
    }
    if (func_ret_type->type == V_INT) {
        res = new_inst_variable(ctx, V_INT, func_ret_type->bits, TYPE_SIGNED);

        if (func->func)
            buffer_write(ctx->data, "%%%d = call i%u (%s) @%s(%s); FUNCCALL int\n",
                res->reg,
                func_ret_type->bits,
                func->paramstr ? func->paramstr : "",
                func->name,
                paramstr ? paramstr : "");
        else {
            buffer_write(ctx->data, "%%%d = call i%u (%s) %%%u(%s); FUNCCALL int\n",
                res->reg,
                func_ret_type->bits,
                func->paramstr ? func->paramstr : "",
                fn->reg,
                paramstr ? paramstr : "");
        }
    } else if (func_ret_type->type == V_FLOAT) {
        res = new_inst_variable(ctx, V_FLOAT, func_ret_type->bits, TYPE_SIGNED);

        buffer_write(ctx->data, "%%%d = call double (%s) @%s(%s); FUNCCALL float\n",
            res->reg,
            func->paramstr ? func->paramstr : "",
            func->name,
            paramstr ? paramstr : "");
    } else if (func_ret_type->type == V_VOID) {
        res = new_inst_variable(ctx, V_VOID, 0, TYPE_UNSIGNED);
        buffer_write(ctx->data, "%%%u = alloca i8, align 8; void call\n", res->reg);
        buffer_write(ctx->data, "call void (%s) @%s(%s); FUNCCALL void\n",
            func->paramstr ? func->paramstr : "",
            func->name,
            paramstr ? paramstr : "");
    } else if (func_ret_type->type == V_STRUCT) {
        char *stars = get_stars(func_ret_type->ptr);
        res = new_variable_ext(ctx, NULL, V_STRUCT, func_ret_type->bits, func_ret_type->sign, func_ret_type->ptr, 0, 0, func_ret_type->type_name);
        res->direct = 1;
        buffer_write(ctx->data, "%%%u = call %%struct.%s%s (%s) @%s(%s); FUNCCALL struct\n",
            res->reg,
            func_ret_type->type_name,
            ESTR(stars),
            func->paramstr ? func->paramstr : "",
            func->name,
            paramstr ? paramstr : "");
    } else {
        stack_trace();
        ERR("Invalid function \"%s\" return type: %s", func->name, type_str(func_ret_type->type));
    }

    if (paramstr && builtin == BUILTIN_NONE)
        free(paramstr);

    return res ? res->reg : 0;
}

int gen_type(struct gen_context *ctx, struct node *node)
{
    const struct type *ot = __find_type_by(ctx, node->type, node->bits, node->sign, 0, node->type_name);
    // FIXME type
    struct type *t = (struct type*)ot;

    if ((!t || t->forward) && (node->type == V_STRUCT || node->type == V_UNION)) {
        struct gen_context *global_ctx = get_global_ctx(ctx);

        const char *typename = node->value_string;
        if (!typename) {
            if (node->parent && (node->parent->node == A_TYPEDEF) && node->parent->value_string) {
                typename = node->parent->value_string;
#if 1
                // TODO: Free this
                char *tmp = calloc(1, 4096);
                tmp = strcat(tmp, "__generated_struct_name_");
                tmp = strcat(tmp, typename);
                node->value_string = tmp;
                node->type_name = tmp;
                typename = tmp;
#else
                node->value_string = typename;
                node->type_name = typename;
#endif
            }
        }
        // We have most probably struct definition
        //t->type_name = node->value_string;
        struct buffer *struct_init = buffer_init();
        //stack_trace();

        struct struct_name *new_struct = calloc(1, sizeof(struct struct_name));
        new_struct->name = typename;
        struct_add(ctx, new_struct);

        char *sname = struct_name(ctx);
        if (!ot)
            t = register_type(global_ctx, sname, node->type, node->bits, TYPE_UNSIGNED);

        if (node->right) {
            node->type_name = sname;
            //t->type_name = sname;
            // FIXME This is a hack for now
            if (node->type == V_STRUCT)
                buffer_write(struct_init, "%%struct.%s = type { ", sname);
            else
                buffer_write(struct_init, "%%union.%s = type { ", sname);
            complete_struct_type(global_ctx, t, node->right, node->type == V_UNION, struct_init);
            buffer_write(struct_init, " } ; gen_type\n");
            buffer_append(ctx->init, buffer_read(struct_init));
            t->forward = 0;
        } else if (!t->forward) {
            // This is either forward or opaque
            node->type_name = typename;
            t->type_name = typename;
            t->forward = 1;
        }
        buffer_del(struct_init);
        struct_pop(ctx);
    }
    if (!t && node->type == V_ENUM) {
        struct gen_context *global_ctx = get_global_ctx(ctx);

        t = register_type(global_ctx, node->value_string, node->type, node->bits, TYPE_UNSIGNED);
        t->type_name = node->value_string;
        complete_enum_type(global_ctx, ctx, t, node->right);
    }

    FATALN(!t, node, "Couldn't find type: %s (%s, bits %d, %s)", node->value_string, type_str(node->type), node->bits, node->sign ? "signed" : "unsigned");

    int ptrval = node->ptr;
    ot = type_wrap_to(ctx, t, ptrval);
    ctx->pending_type = ot;

    return REF_CTX(ot->id);
}

const struct type *gen_type_list_simple(struct gen_context *ctx, struct node *node)
{
    if (!node)
        return NULL;
    if (node->node != A_TYPE_LIST)
        return NULL;
    if (!node->left)
        return NULL;
    if (node->left && node->right)
        return NULL;

    if (node->left && !node->right)
        if (node->left->left || node->left->right)
            return NULL;
    node = node->left;

    // Need to fix bits in case of int
    int search_bits = node->bits;
    if (node->type == V_INT && search_bits == 0)
        search_bits = 32;
    // FIXME Reverse sign already in TYPE_SPEC
    node->sign = !node->sign;

    const struct type *res = __find_type_by(ctx, node->type, search_bits, node->sign, 0, node->type_name);
    if (!res)
        return res;

    return type_wrap_to(ctx, res, node->ptr);
}

static const struct type *type_ret_validate(const struct type *res, struct node *node)
{
    FATALN(!res, node->parent, "Couldn't solve type");
    return res;
}

static struct type *type_fix_bits(struct type *tmp)
{
    if (tmp->type == V_INT && !tmp->bits)
        tmp->bits = 32;
    return tmp;
}

static inline struct type *type_assign(struct type *res, const struct type *src)
{
    return (struct type*)src;
}

const struct type *__gen_type_list_recurse(struct gen_context *ctx, struct node *node, struct type *res)
{
    if (!node)
        return res;

    if (node->node == A_TYPE_LIST) {
        const struct type *tl = __gen_type_list_recurse(ctx, node->left, res);
        const struct type *tr = __gen_type_list_recurse(ctx, node->right, res);
        if (!tl && !tr)
            return NULL;
        if (tl && !tr)
            return tl;
        if (!tl && tr)
            return tr;
#if 1
        if (!tr) {
            ERR("No TR!");
            return tl;
        }
#endif

        const struct type *to_free = NULL;
        if (tl->type != tr->type) {
            if ((tl->type == V_VOID && tr->type == V_INT) ||
                    tr->type == V_CUSTOM ||
                    tr->type == V_FUNCPTR ||
                    (tl->type == V_VOID && tr->type == V_FLOAT)) {
                res = type_assign(res, tr);
                to_free = tl;
            } else if ((tl->type == V_INT && tr->type == V_VOID) ||
                    tl->type == V_CUSTOM ||
                    tl->type == V_FUNCPTR ||
                    (tl->type == V_FLOAT && tr->type == V_INT) ||
                    (tl->type == V_FLOAT && tr->type == V_VOID)) {
                res = type_assign(res, tl);
                to_free = tr;
            } else if (tl->type == V_INT && tr->type == V_FLOAT) {
                res = type_assign(res, tr);
                if (tl->bits == 64 && tr->bits == 64)
                    res->bits = 128;
                to_free = tl;
            } else {
                node_walk(node);
                ERR("Invalid types in resolve: %s %s", type_str(tl->type), type_str(tr->type));
            }
        } else
            res = type_assign(res, tl);

        // FIXME This potentially changes the original type
        if (node->left->bits < node->right->bits)
            res->bits = tr->bits;
        if (node->left->array_size < node->right->array_size)
            res->array_size = tr->array_size;
        if (res->sign != tr->sign && !tr->sign)
            res->sign = tr->sign;
        if (!res->is_const && (tr->is_const || tl->is_const))
            res->is_const = 1;
        if (!res->is_extern && (tr->is_extern || tl->is_extern))
            res->is_extern = 1;
        if (!res->is_static && (tr->is_static || tl->is_static))
            res->is_static = 1;
        if (!res->is_inline && (tr->is_inline || tl->is_inline))
            res->is_inline = 1;
        //printf("PTRS: %d < %d, %d\n", res->ptr, tr->ptr, node->ptr);
        //printf("EXTS: %d < %d, %d, %s\n", res->is_extern, tr->is_extern, node->is_extern, stype_str(res));
        if (res->ptr < tr->ptr) {
            int diff = tr->ptr - res->ptr;
            if (res->temporary)
                res->ptr += diff;
            else
                // FIXME
                res = (struct type*)type_wrap_to(ctx, res, diff);
        }
#if 0
        (void)to_free;
        if (tr->temporary)
            free((void*)tr);
        if (tl->temporary)
            free((void*)tl);
#else
        if (to_free && to_free->temporary)
            free((void*)to_free);
#endif
    } else if (node->node == A_STRUCT || node->node == A_UNION) {
        enum var_type type = node->node == A_STRUCT ? V_STRUCT : V_UNION;
        const struct type *res2 = __find_type_by(ctx, type, node->bits, node->sign, node->ptr, node->type_name);
        if (res2)
            return res2;
        res2 = __find_type_by(ctx, type, node->bits, node->sign, 0, node->type_name);
        if (res2)
            return res2;

        struct gen_context *global_ctx = get_global_ctx(ctx);

        // We have most probably struct definition
        res = register_type(global_ctx, node->value_string, node->type, node->bits, TYPE_UNSIGNED);
        //res->type_name = node->value_string;
        struct buffer *struct_init = buffer_init();

        struct struct_name *new_struct = calloc(1, sizeof(struct struct_name));
        new_struct->name = node->value_string;
        struct_add(ctx, new_struct);

        char *sname = struct_name(ctx);
        node->type_name = sname;
        res->type_name = sname;

        // FIXME This is a hack for now
        if (node->type == V_STRUCT)
            //buffer_write(struct_init, "%%struct.%s = type { ", node->value_string);
            buffer_write(struct_init, "%%struct.%s = type { ", sname);
        else
            //buffer_write(struct_init, "%%union.%s = type { ", node->value_string);
            buffer_write(struct_init, "%%union.%s = type { ", sname);
        complete_struct_type(global_ctx, res, node->right, node->type == V_UNION, struct_init);

        buffer_write(struct_init, " }\n");
        buffer_append(ctx->init, buffer_read(struct_init));
        buffer_del(struct_init);
        struct_pop(ctx);
    } else if (node->node == A_ENUM) {
        const struct type *res2 = __find_type_by(ctx, node->type, node->bits, node->sign, node->ptr, node->type_name);
        if (res2)
            return res2;

        struct gen_context *global_ctx = get_global_ctx(ctx);
        res = register_type(global_ctx, node->value_string, node->type, node->bits, TYPE_UNSIGNED);
        res->type_name = node->value_string;
        complete_enum_type(global_ctx, ctx, res, node->right);
    } else if (node->node == A_TYPEDEF) {
        const struct type *res2 = __find_type_by(ctx, node->type, node->bits, node->sign, node->ptr, node->type_name);
        if (res2)
            return res2;
        res2 = __find_type_by(ctx, node->type, node->bits, node->sign, node->ptr, node->value_string);
        if (res2)
            return res2;

        const struct type *tmp = gen_type_list_type(ctx, node->left);
        FATALN(!tmp, node, "Invalid typedef, missing typedef define type");
        if (node->is_func) {
            /* This is function typedef */
            res = register_type(ctx, node->value_string, V_FUNCPTR, 64, TYPE_UNSIGNED);
            res->type_name = node->value_string;
            res->params = node->mid;
            res->retval = tmp;
            //res->ptr = node->ptr;
            return type_wrap_to(ctx, res, node->ptr);
            //printf("nnnPTRVVV: %d %d %s, id %d\n", node->ptr, res->ptr, res->type_name, res->id);
        } else {
            res = register_type(ctx, node->value_string, V_CUSTOM, tmp->bits, tmp->sign);
            res->custom_type = tmp;
            res->type_name = node->value_string;
        }
    } else if (node->node == A_TYPE) {
        if (node->type == V_STRUCT || node->type == V_UNION) {
#if 0
            if (!node->type_name && node->parent && node->parent->value_string)
                res = __find_type_by(ctx, node->type, node->bits, node->sign, 0, node->parent->value_string);
            else
#endif
            // FIXME might be inplace def, and not defined
            // earlier so should handle it now! Example:
            // struct tmp {
            //   struct {
            //      int a;
            //   } other;
            //   int b;
            // };
            // So "struct other" is defined only inside "tmp"
            // thus need to define it now there
            const struct type *res2 = __find_type_by(ctx, node->type, node->bits, node->sign, node->ptr, node->type_name);
            if (res2)
                return res2;
            // This might be in-place definition, parse it
            int type_id = REF_CTX(gen_type(ctx, node));
            res2 = find_type_by_id(ctx, type_id);
            node->type_name = res2->type_name;
            return type_ret_validate(__find_type_by(ctx, node->type, node->bits, node->sign, node->ptr, node->type_name), node);
#if 0
            printf("Gens: %s\n", node->name);
            res = __find_type_by(ctx, node->type, node->bits, node->sign, node->ptr, node->type_name);
#endif
            //FATALN(!res, node->parent, "Couldn't solve type in struct: %s, %s", node->type_name, node->parent->value_string);
        } else
            ERR("Should not get here, got: %s", type_str(node->type));
    } else if (node->node == A_TYPESPEC && node->type == V_CUSTOM) {
        const struct type *res2 = __find_type_by(ctx, node->type, node->bits, node->sign, 0, node->value_string);
        FATAL(!res2, "Invalid custom typespec: %s", node->value_string);
        return type_wrap_to(ctx, res2, node->ptr);
    } else if (node->node == A_TYPESPEC && node->type == V_FUNCPTR) {
        const struct type *res2 = __find_type_by(ctx, node->type, node->bits, node->sign, 0, node->value_string);
        FATAL(!res2, "Invalid funcptr typespec: %s", node->value_string);
        return type_wrap_to(ctx, res2, node->ptr);
    } else if (node->type == V_BUILTIN) {
        return type_ret_validate(__find_type_by(ctx, node->type, node->bits, node->sign, node->ptr, node->value_string), node);
    } else if (node->node == A_STORAGE_CLASS) {
        res = (struct type *)__gen_type_list_recurse(ctx, node->left, res);
        FATAL(!res, "Invalid storage class def: %s", node->value_string);
        res->is_const = node->is_const;
        res->is_extern = node->is_extern;
        res->is_static = node->is_static;
        res->is_inline = node->is_inline;
    } else if (node->node == A_TYPE_QUAL) {
        res = (struct type *)__gen_type_list_recurse(ctx, node->left, res);
        if (!res)
            goto fallback_type;
        res->is_const = node->is_const;
        res->is_extern = node->is_extern;
        res->is_static = node->is_static;
        res->is_inline = node->is_inline;
    } else if (node->node == A_INDEXDEF) {
        struct type *res2 = NULL;

        /* Special case for indexes like int[2] */
        res = (struct type *)__gen_type_list_recurse(ctx, node->left, res);
        res2 = (struct type *)__gen_type_list_recurse(ctx, node->right, res);
        if (!res)
            res = res2;
        if (!res)
            ERR("Invalid indexdef type");
        res->name = node->value_string;
        res->is_const = node->is_const;
        res->is_extern = node->is_extern;
        res->is_static = node->is_static;
        res->is_inline = node->is_inline;
        res->ptr = 1;
        if (node->right && node->right->value > 0) {
            /* This is most likely thrown away */
            res->array_size = node->right->value;
            /* Thus mark it in node */
            node->right->array_size = node->right->value;
            node->array_size = node->right->value;
        }
        return res;
    } else {
fallback_type:
        res = calloc(1, sizeof(struct type));
        res->type = node->type;
        res->bits = node->bits;
        /* FIXME utilize */
        res->array_size = node->array_size;
        res->sign = !node->sign;
        res->ptr = node->ptr;
        res->name = node->value_string;
        res->is_const = node->is_const;
        res->is_extern = node->is_extern;
        res->is_static = node->is_static;
        res->is_inline = node->is_inline;
        res->type_name = node->type_name;
        res->temporary = 1;
    }
    FATALN(!res, node->parent, "Couldn't solve type");

    // Void is special and need to hardcode these
    if (res->type == V_VOID) {
        res->bits = 0;
        res->sign = TYPE_UNSIGNED;
    }
    else if (res->type == V_FLOAT) {
        res->sign = TYPE_SIGNED;
    }

    res = type_fix_bits(res);
    return res;
}

const struct type *gen_type_list_recurse(struct gen_context *ctx, struct node *node)
{
    const struct type *tmp = __gen_type_list_recurse(ctx, node, NULL);

    if (!tmp)
        return NULL;
#if 0
    if (tmp->type == V_INT && !tmp->bits)
        tmp->bits = 32;
#else
    FATAL(tmp->type == V_INT && !tmp->bits, "Failed to update int bits");
#endif

    //printf("RECURS: %s, from %s\n", stype_str(tmp), tmp->type_name);
    //node_walk(node);

    const struct type *res = __find_type_by(ctx, tmp->type, tmp->bits, tmp->sign, 0, tmp->type_name);
    res = type_wrap_to(ctx, res, tmp->ptr);
    if (tmp->temporary)
        free((void*)tmp);
    return res;
}

const struct type *gen_type_list_type(struct gen_context *ctx, struct node *node)
{
    const struct type *res = NULL; //gen_type_list_simple(ctx, node);
    if (!res)
        res = gen_type_list_recurse(ctx, node);

    FATALN(!res, node, "Couldn't generate type from type list");
    ctx->pending_type = res;
#if 0
    if (res->id == 21 || res->id == 29) {
        printf("Pend is: %d\n", res->id);
        stack_trace();
        node_walk(node);
    }
#endif

    node->reg = REF_CTX(res->id);

    return res;
}

int gen_type_list(struct gen_context *ctx, struct node *node)
{
    //ctx->pending_ptr = 0;
    (void)gen_type_list_type(ctx, node);

    return node->reg;
}

int get_type_list(struct gen_context *ctx, struct node *node)
{
    if (!node->reg) {
        // For some reason this type is not handled yet, try now
        // This might for example be return type from function
        gen_type_list(ctx, node);
    }
    FATALN(!node->reg, node, "Invalid type");
    return node->reg;
}

int gen_cast_to(struct gen_context *ctx, struct node *node, int a, int b)
{
    // Pending type should be where we're casting to
    struct variable *orig = find_variable(ctx, b);
    struct variable *var = gen_load(ctx, orig);
    struct variable *res = NULL;

    FATALN(!var, node, "Invalid cast source");
    const struct type *target = find_type_by_id(ctx, REF_CTX(a));
    FATALN(!target, node, "Invalid cast target");
    int ptrval = target->ptr;
    if (var->type->type == V_INT && target->type == var->type->type) {
        if (target->bits == var->type->bits && target->ptr == var->type->ptr)
            return var->reg;
        if (var->type->ptr) {
            char *stars = get_stars(var->type->ptr);

            res = new_inst_variable(ctx, V_INT, target->bits, target->sign);
            buffer_write(ctx->data, "%%%d = ptrtoint i%d%s %%%d to i%d ; gen_cast_to\n",
                res->reg, var->bits, stars, var->reg, target->bits);
            if (stars)
                free(stars);
        } else if (target->bits > var->type->bits) {
            res = new_inst_variable(ctx, V_INT, target->bits, target->sign);
            if (target->sign || var->type->sign)
                buffer_write(ctx->data, "%%%d = sext i%d %%%d to i%d\n",
                    res->reg, var->bits, var->reg, target->bits);
            else
                buffer_write(ctx->data, "%%%d = zext i%d %%%d to i%d\n",
                    res->reg, var->bits, var->reg, target->bits);
        } else if (target->ptr != var->type->ptr && target->bits == var->type->bits) {
            literalnum arraysize = 0;

            if (node->left && node->left->right && node->left->right->array_size) {

                arraysize = node->left->right->array_size;
                res = new_variable_ext(ctx,
                    NULL,
                    target->type,
                    target->bits, target->sign,
                    0, 0, 0, target->type_name);
                res->array = arraysize;
                buffer_write(ctx->data, "%%%d = alloca [%d x i%d], align 16\n",
                    res->reg, arraysize, target->bits);
            }
            if (arraysize && node->right && node->right->node == A_LIST) {
                /*
                 * Casting list to array, thus most likely initializer
                 * list.
                 */
                struct node *val;
                unsigned int idx = 0;
                struct variable *res2;

                res2 = new_variable(ctx, NULL, V_INT, target->bits, target->sign, 1, 0, 0);
                buffer_write(ctx->data, "%%%u = bitcast [%u x i%u]* %%%u to i%u*\n",
                    res2->reg, arraysize, target->bits, res->reg, target->bits);
                val = node->right;
                while (val) {
                    if (val->left) {
                        struct node *vnode = val->left;
                        struct variable *tmp_val = new_variable(ctx, NULL, target->type, target->bits, target->sign, 0, 0, 0);
                        const char *vstars = get_stars(vnode->ptr);

                        buffer_write(ctx->data, "%%%u = getelementptr inbounds i%u, i%u* %%%u, i64 %u\n", tmp_val->reg, target->bits, target->bits, res2->reg, idx);
                        if (vnode->type == V_INT) {
                            buffer_write(ctx->data, "store i%u%s %u, i%u%s* %%%u, align %u\n", target->bits, vstars, vnode->value, target->bits, vstars, tmp_val->reg, align(vnode->bits));
                        }
                    }
                    idx++;
                    val = val->right;
                }
            } else
                ERR("same bits but diff ptr: %u != %u", target->ptr, var->type->ptr);
        } else {
            // This is truncate so warn
            WARN("Truncating from %d bits to %d bits, this may result lost of precision\n", var->bits, target->bits);
            res = new_inst_variable(ctx, V_INT, target->bits, target->sign);
            buffer_write(ctx->data, "%%%d = trunc i%d %%%d to i%d\n",
                res->reg, var->bits, var->reg, target->bits);
        }
    } else if (var->type->type == V_INT && target->type == V_FLOAT) {
        res = new_inst_variable(ctx, V_FLOAT, target->bits, target->sign);
        if (var->type->sign)
            buffer_write(ctx->data, "%%%d = sitofp i%d %%%d to %s ; gen_cast_to\n",
                res->reg, var->bits, var->reg, target->bits == 64 ? "double" : "float");
        else
            buffer_write(ctx->data, "%%%d = uitofp i%d %%%d to %s\n",
                res->reg, var->bits, var->reg, target->bits == 64 ? "double" : "float");
    } else if (var->type->type == V_FLOAT && target->type == V_INT) {
        res = new_inst_variable(ctx, V_INT, target->bits, target->sign);
        if (target->sign)
            buffer_write(ctx->data, "%%%d = fptosi %s %%%d to i%d\n",
                res->reg, var->type->bits == 64 ? "double" : "float", var->reg, target->bits);
        else
            buffer_write(ctx->data, "%%%d = fptoui %s %%%d to i%d\n",
                res->reg, var->type->bits == 64 ? "double" : "float", var->reg, target->bits);
    } else if (ptrval) {
            var = cast_int_to_ptr(ctx, var);
            char *stars = get_stars(var->type->ptr);
            char *stars2 = get_stars(ptrval);
            if (var->type->type == V_INT && target->type == V_VOID) {
                res = new_inst_variable(ctx, V_INT, 8, TYPE_UNSIGNED);
                //res = new_inst_variable(ctx, V_VOID, 0, TYPE_UNSIGNED);
                buffer_write(ctx->data, "%%%d = bitcast i%d%s %%%d to i%d%s ; gen_cast_to int -> ptr %d\n",
                    res->reg, var->bits, ESTR(stars), var->reg, 8, stars2, ptrval);
                res->type = type_wrap_to(ctx, res->type, ptrval);
            } else if (var->type->type == V_VOID && target->type == V_INT) {
                res = new_inst_variable(ctx, V_INT, target->bits, target->sign);
                buffer_write(ctx->data, "%%%d = bitcast i%d%s %%%d to i%d%s ; gen_cast_to void -> int\n",
                    res->reg, 8, ESTR(stars), var->reg, target->bits, ESTR(stars2));
                res->type = type_wrap_to(ctx, res->type, ptrval);
            } else if (ptrval && var->type->ptr) {
                /* Assign ptrval to ptr */
                if (var->type->type == V_STRUCT) {
                    res = new_inst_variable(ctx, V_VOID, 0, var->type->sign);
                    buffer_write(ctx->data, "%%%u = bitcast %%struct.%s%s %%%d to i8%s ; gen_cast_to struct -> void*\n",
                        res->reg,
                        orig->type->name,
                        ESTR(stars),
                        var->reg,
                        ESTR(stars)
                        );
                    res->type = type_wrap_to(ctx, res->type, ptrval);
                } else if (var->type->type == V_VOID) {
                        if (target->type == V_STRUCT) {
                            //res = new_inst_variable(ctx, V_STRUCT, target->, var->type->sign);
                            res = new_variable_ext(ctx, NULL, V_STRUCT, target->bits, TYPE_UNSIGNED, 0, 0, ctx->global, target->type_name);
                            res->direct = 1;
                            buffer_write(ctx->data, "%%%u = bitcast i8%s %%%u to %%struct.%s%s ; gen_cast_to void* -> struct\n",
                                res->reg,
                                ESTR(stars),
                                var->reg,
                                target->name,
                                ESTR(stars)
                                );
                            res->type = type_wrap_to(ctx, res->type, ptrval);
                        } else
                            ERR("Not supported void to %s!", get_type_str(ctx, target));
                } else {
                        ERR("Casting from %s to void not supported yet", get_type_str(ctx, var->type));
                }
            } else {
                printf("TMP: %d %d\n", var->type->ptr, ptrval);
                node_walk(node);
                ERR("Can't cast void to ptr");
            }
            if (stars)
                free(stars);
            if (stars2)
                free(stars2);
    } else if (target->type == V_VOID) {
        // Void cast is just reference
        //res = var;
        res = new_inst_variable(ctx, V_VOID, 0, TYPE_UNSIGNED);
        buffer_write(ctx->data, "%%%u = alloca i8, align 8; void cast\n", res->reg);
    } else if (target->type == V_STRUCT) {
        /* We have struct, handle it */
        if (node->right && node->right->node == A_LIST) {
            struct node *val;
            unsigned int idx = 0;
            char *stars = get_stars(target->ptr);

            res = new_variable_ext(ctx, NULL, V_STRUCT, target->bits, target->sign, target->ptr, 0, 0, target->type_name);
            buffer_write(ctx->data, "%%%u = alloca %%struct.%s, align 4; struct cast init\n", res->reg, target->type_name);

            /* This is initializer list (OR IS IT?) */
            val = node->right;
            while (val) {
                if (val->left) {
                    struct node *vnode = val->left;
                    const struct type *access_type = struct_get_by_index(res->type, idx);
                    struct variable *tmp_val = new_variable(ctx, NULL, access_type->type, access_type->bits, access_type->sign, 0, 0, 0);
                    const char *vstars = get_stars(vnode->ptr);

                    buffer_write(ctx->data, "%%%u = getelementptr inbounds %%struct.%s%s, %%struct.%s%s* %%%u, i32 0, i32 %u\n", tmp_val->reg, target->type_name, stars, target->type_name, stars, res->reg, idx);
                    if (vnode->type == V_INT) {
                        buffer_write(ctx->data, "store i%u%s %u, i%u%s* %%%u, align %u\n", vnode->bits, vstars, vnode->value, vnode->bits, vstars, tmp_val->reg, align(vnode->bits));
                    }
                }
                idx++;
                val = val->right;
            }
        } else
            ERR("Unimpemented struct cast!");
        //FATALN(1, node, "Invalid cast to struct %s from %d, %d reg %d, orig %d", type_str(var->type->type), a, b, var->reg, orig->reg);
    } else {
        FATALN(1, node, "Invalid cast to %s from %d, %d reg %d, orig %d", type_str(var->type->type), a, b, var->reg, orig->reg);
    }

    ctx->pending_type = NULL;
    FATALN(!res, node, "Fatal error in casting");
    return res->reg;
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

int gen_init_var(struct gen_context *ctx, struct node *node, int idx_value)
{
    struct variable *var = NULL;
    const struct type *t = custom_type_get(ctx, ctx->pending_type);
    int ptrval = 0;
    int addrval = 0;
    int res = 0;
    struct gen_context *global_ctx = get_global_ctx(ctx);

    FATALN(!t, node, "No type: %p", (void *)ctx->pending_type);

    //buffer_write(ctx->init, "; Variable: %s, type %s, ptr %d: %s\n", node->value_string, type_str(t->type), ptrval, stype_str(t));
    FATALN(strcmp(node->value_string, "add5") == 0, node, "Should not initialize function");

    switch (t->type) {
        case V_INT:
            ptrval = gen_use_ptr(ctx);
            if (!ptrval)
                ptrval = t->ptr;
            //buffer_write(ctx->init, "; ptrval %d, pend %d\n", ptrval, ctx->pending_type->ptr);
            node->ptr = ptrval;
            node->addr = addrval;
            var = new_variable(ctx, node->value_string, V_INT, t->bits, t->sign, ptrval, addrval, ctx->global);
            var->global = ctx->global;
            var->addr = addrval;
            var->array = idx_value;
            res = gen_allocate_int(ctx, var->reg, var->type->bits, var->type->ptr, idx_value, 0, node->value, node);
            break;
        case V_FLOAT:
            ptrval = gen_use_ptr(ctx);
            node->ptr = ptrval;
            node->addr = addrval;
            var = new_variable(ctx, node->value_string, V_FLOAT, t->bits, TYPE_SIGNED, ptrval, addrval, ctx->global);
            var->global = ctx->global;
            var->array = idx_value;
            //res = gen_allocate_double(ctx, var->reg, var->bits, var->type->ptr, 0, node->value, node->fraction);
            res = gen_allocate_double(ctx, var->reg, var->bits, var->type->ptr, 0, node->value, 0);
            break;
        case V_FUNCPTR:
            var = new_variable_ext(ctx, node->value_string, V_FUNCPTR, 64, TYPE_UNSIGNED, ptrval, addrval, ctx->global, t->type_name);
#if 0
            char *stars = get_stars(ptrval);
            // %2 = alloca i64 (i8*, i8*, i64)*, align 8
            // %2 = alloca i64 (i8*, i8*, i64)*, align 8
            // store i64 (i8*, i8*, i64)* @ff, i64 (i8*, i8*, i64)** %2, align 8
            //buffer_write(ctx->init, "%%%d = alloca %s (%s)%s, align 8\n", var->reg, retval, params, stars);
            buffer_write(ctx->init, "%%%d = alloca %s (%s)%s, align 8\n", var->reg, retval, params, stars);
#else
            char *stars = get_stars(ptrval + 1);
            char *types = get_type_str(ctx, t);
            buffer_write(ctx->init, "%%%d = alloca %s%s, align 8 ; alloc func\n", var->reg, types, ESTR(stars));
            if (stars)
                free(stars);
            free(types);
#endif
            break;
        case V_STRUCT:
            ptrval = gen_use_ptr(ctx) + t->ptr;

            //char *stars = get_stars(ptrval);

            var = new_variable_ext(ctx, node->value_string, V_STRUCT, t->bits, TYPE_UNSIGNED, ptrval, addrval, ctx->global, t->type_name);
            if (ctx->pending_type && strcmp(ctx->pending_type->name, "va_list") == 0)
                var->array += 1;
            res = gen_allocate_struct(ctx, var->reg, ctx->pending_type, t, var, ptrval);
            //buffer_write(ctx->init, "%%%d = alloca %%struct.%s%s, align 8\n", var->reg, t->name, stars);

            //var->ptr = ptrval;
            //var->type->ptr = ptrval;
            //node->ptr = ptrval;
            res = var->reg;
            //free(stars);
            break;
        case V_UNION:
            ptrval = gen_use_ptr(ctx) + t->ptr;
            var = new_variable_ext(ctx, node->value_string, V_UNION, t->bits, TYPE_UNSIGNED, ptrval, addrval, ctx->global, t->type_name);
            //buffer_write(ctx->init, "%%%d = alloca %%union.%s, align 8\n", var->reg, t->name);
            res = gen_allocate_union(ctx, var->reg, ctx->pending_type, t, var, ptrval);
            res = var->reg;
            break;
        case V_ENUM:
            if (node->left) {
                var = new_variable(global_ctx, node->value_string, V_INT, 32, TYPE_SIGNED, ptrval, addrval, global_ctx->global);
                res = gen_allocate_int(global_ctx, var->reg, var->type->bits, var->type->ptr, idx_value, 0, node->value, node);
            } else {
                var = find_variable_by_name(ctx, node->value_string);
                if (!var) {
                    var = new_variable(ctx, node->value_string, V_INT, 32, TYPE_SIGNED, ptrval, addrval, ctx->global);
                    res = gen_allocate_int(ctx, var->reg, var->type->bits, var->type->ptr, idx_value, 0, node->value, node);
                }
            }
            res = var->reg;
            break;
        case V_VOID:
            ptrval = gen_use_ptr(ctx);
            if (!ptrval)
                ptrval = t->ptr;
            if (!ptrval)
                ERR("'void' is not valid type for variable!\n");
            var = new_variable(ctx, node->value_string, V_VOID, 0, TYPE_UNSIGNED, ptrval, addrval, ctx->global);
            res = gen_allocate_void_ptr(ctx, var->reg, ptrval, ctx->global);
            // TODO
            break;
        default:
            node_walk(node);
            ERR("Invalid type for variable: %s", type_str(t->type));
            break;
    }

    return res;
}

int gen_sizeof(struct gen_context *ctx, struct node *node, int left)
{
    struct variable *var = find_variable(ctx, left);
    const struct type *type;

    if (left >= 0) {
        FATALN(!var, node, "Didn't get variable for sizeof: %d", left);
        type = var->type;
    } else
        type = find_type_by_id(ctx, REF_CTX(left));
    FATALN(!type, node, "Didn't get type for sizeof");
    type = custom_type_get(ctx, type);

    struct variable *res = new_variable(ctx, NULL, V_INT, 32, TYPE_SIGNED, 0, 0, 0);
    buffer_write(ctx->data, "%%%d = alloca i%d, align %d\n",
        res->reg,
        res->type->bits,
        align(res->type->bits));

    if (var && (var->array)) {
            buffer_write(ctx->data, "store i32 %d, i32* %%%d, align %d\n",
                var->array * type->bits / 8, res->reg, align(res->type->bits));
    } else if (type->ptr || (var && (var->type->ptr || var->addr))) {
            // FIXME ptr size hardcoded
            buffer_write(ctx->data, "store i32 %d, i32* %%%d, align %d\n",
                8, res->reg, align(res->type->bits));
    } else if (type->type == V_INT || type->type == V_FLOAT) {
            buffer_write(ctx->data, "store i32 %d, i32* %%%d, align %d\n",
                type->bits / 8, res->reg, align(res->type->bits));
    } else if (type->type == V_STRUCT || type->type == V_UNION) {
            buffer_write(ctx->data, "store i32 %d, i32* %%%d, align %d\n",
                type->bits / 8, res->reg, align(res->type->bits));
    } else
        ERR("Invalid variable for sizeof: %s", type_str(type->type));

    return res->reg;
}

int gen_identifier(struct gen_context *ctx, struct node *node)
{
    struct variable *all_var = find_variable_by_name(ctx, node->value_string);
    struct variable *var = find_variable_by_name_scope(ctx, node->value_string, 0, 1);
    int res;

    if (var == NULL) {
        if (all_var && !ctx->decl_name && !all_var->func && ctx->is_decl >= 100) {
            ERR("Redeclaring variable: %s (lvl %d) %u", node->value_string, ctx->is_decl, node->line);
        }
        if (all_var && (ctx->is_decl < 100 || ctx->decl_name)) {
            /* This is a function, return it's reference */
            if (all_var->func) {
                return all_var->reg;
            }
            /*
             * We have global variable but not local, thus if
             * this is declaration we can override it,
             * otherwise just return the global reference.
             */
            return all_var->reg;
        }
        if (ctx->is_decl >= 100 && ctx->decl_name == NULL)
            ctx->decl_name = node->value_string;
        // Utilize pending type from previous type def
        FATALN(!ctx->pending_type, node, "Can't determine type of variable %s", node->value_string);
        res = gen_init_var(ctx, node, 0);
    } else if (ctx->is_decl > 100) {
        /* We have the variable but this is declaration, check only this scope for redeclaraion */
        struct variable *var_scope = find_variable_by_name_scope(ctx, node->value_string, 0, 0);
#if 1
        if (var_scope)
            ERR("Redeclaring variable: %s (lvl %d)", node->value_string, ctx->is_decl);
#else
        FATAL(var_scope, "Redeclaring variable: %s (lvl %d)", node->value_string, ctx->is_decl);
#endif
        res = gen_init_var(ctx, node, 0);
    } else {
        // TODO FIXME Faulty check
#if 0
        FATAL(ctx->is_decl >= 100 && ctx->is_decl < 102, "Redeclaring variable: %s (lvl %d)", node->value_string, ctx->is_decl);
#endif
        res = var->reg;
    }
    return res;
}

int gen_index(struct gen_context *ctx, struct node *node)
{
    struct node *ident = node->left;
    struct variable *var = find_variable_by_name(ctx, ident->value_string);

    FATALN(!var, node, "Can't find variable in non-declr: %d, identifier \"%s\"\n", ctx->is_decl, ident->value_string);
    return var->reg;
}

int gen_indexdef(struct gen_context *ctx, struct node *node)
{
    struct node *ident = node->left;
    //struct node *idx = node->right;

    FATALN(!ident, node, "Invalid index without identifier");
    struct variable *var = find_variable_by_name(ctx, ident->value_string);

#if 0
    // FIXME
    if (ctx->is_decl < 100) {
        FATALN(!var, node, "Can't find variable in non-declr: %d, identifier \"%s\"\n", ctx->is_decl, ident->value_string);
        gen_recursive_allocs(ctx, node->right);
        return var->reg;
    }
#endif

    FATALN(var, node, "Variable already assigned");
    FATALN(!ctx->pending_type, node, "Can't determine type of variable %s", ident->value_string);
    /* FIXME Just getting the value, should ensure it's ok, etc.. */
    int idx_value = 0;
    if (node->right) {
        if (node->right->node == A_INT_LIT)
            idx_value = node->right->value;
        else {
            /*
             * TODO This should ensure we have right index in alloc.
             * Note that this also means we do not support dynamic
             * arrays for now.  Generating dynamic array would mean
             * alloc/realloc from heap instead of stack, thus not
             * supporting it.
             */
            //struct buffer *tmpinit = buffer_init();
            struct buffer *tmpdata = buffer_init();
            //struct buffer *tmpi = ctx->init;
            struct buffer *tmp = ctx->data;
            //ctx->init = tmpinit;
            ctx->data = tmpdata;

            gen_recursive_allocs(ctx, node->right);
            int idx_reg = gen_recursive(ctx, node->right);
            struct variable *idx = find_variable(ctx, idx_reg);
            FATALN(idx->type->type != V_INT, node, "Invalid index, should be int");

            //ctx->init = tmpi;
            ctx->data = tmp;
            buffer_append(ctx->init, buffer_read(tmpdata));
            buffer_del(tmpdata);
            idx_value = node->right->value;
            if (idx_value == 0) {
                idx_value = idx->value;
                FATALN(!idx_value, node->right, "Invalid array init");
            }
        }
    } else if (node->mid) {
        /* Detect list size by initializer size */
        struct node *val = node->mid->left;
        while (val) {
            if (val->left)
                idx_value++;
            val = val->right;
        }
    } else
        ERR("Array definition missing size or initializer: %s", ident->value_string);

    int res = gen_init_var(ctx, ident, idx_value);
    node->ptr = ident->ptr;
    node->addr = ident->addr;
    return res;
}

int get_index(struct gen_context *ctx, struct node *node, int a, int b)
{
    struct node *ident = node->left;

    FATALN(!ident, node, "Invalid index without identifier");
    FATALN(!node->right, node, "Invalid index without index");

    struct variable *var = find_variable(ctx, a);
    struct variable *idx = find_variable(ctx, b);
    FATALN(!idx, node, "Missing index");

    struct type idx_target;
    idx_target.type = V_INT;
    idx_target.bits = 64;
    idx_target.sign = TYPE_UNSIGNED;

    idx = load_and_cast_to(ctx, idx, &idx_target, CAST_NORMAL);
    int newptr = var->type->ptr;
    if (newptr) {
        var = gen_load(ctx, var);
        newptr--;
    }

    struct variable *res = new_variable(ctx, NULL, V_INT, var->type->bits, var->type->sign, newptr, var->addr, ctx->global);
    res = gen_access_ptr_item(ctx, var, res, idx, 0);

    return res->reg;
}

int get_indexdef(struct gen_context *ctx, struct node *node, int a)
{
    struct variable *var = find_variable(ctx, a);
    FATALN(!var, node, "Missing variable");

    return var->reg;
}

struct variable *gen_access_type_target(struct gen_context *ctx, const struct type *access_type)
{
    struct variable *ret = NULL;

    if (access_type->type == V_INT) {
        ret = new_variable(ctx, NULL, V_INT, access_type->bits, access_type->sign, access_type->ptr, 0, 0);
    } else if (access_type->type == V_FLOAT) {
        ret = new_variable(ctx, NULL, V_FLOAT, access_type->bits, access_type->sign, access_type->ptr, 0, 0);
    } else if (access_type->type == V_STRUCT) {
        ret = new_variable_ext(ctx, NULL, V_STRUCT, access_type->bits, access_type->sign, access_type->ptr, 0, 0, access_type->type_name);
    } else if (access_type->type == V_UNION) {
        ret = new_variable_ext(ctx, NULL, V_UNION, access_type->bits, access_type->sign, access_type->ptr, 0, 0, access_type->type_name);
    } else if (access_type->type == V_VOID && access_type->ptr) {
        ret = new_variable(ctx, NULL, V_INT, 8, TYPE_UNSIGNED, access_type->ptr, 0, 0);
    } else
        ERR("Can't access %s from struct", type_str(access_type->type));

    return ret;
}

int gen_access(struct gen_context *ctx, struct node *node, int a, int b)
{
    struct variable *var = find_variable(ctx, a);
    //struct variable *idx = find_variable(ctx, b);
    FATALN(!var, node, "Missing variable");
    //FATALN(!idx, node, "Missing index");
    FATALN(!node->right, node, "Missing index");
    if (var->type->ptr > 0)
        var = gen_load(ctx, var);
    const char *idx_name = node->right->value_string;

    FATALN(var->type->type != V_STRUCT && var->type->type != V_UNION, node, "Aceess from non-struct: %s", type_str(var->type->type));
    const struct type *access_type = NULL;
    int index_num = 0;
    index_num = struct_get_by_name(ctx, var->type, idx_name, &access_type);
#if 0
    if (var->type->type == V_UNION) {
        access_type = struct_get_by_index(var->type, 0);
    } else
        index_num = struct_get_by_name(var->type, idx_name, &access_type);
#endif
    FATALN(index_num < 0, node, "Couldn't find from struct \"%s\": %s", var->type->type_name, idx_name);
    FATALN(!access_type, node, "Can't find type of %s from struct", idx_name);

    const struct variable *ret = gen_access_type_target(ctx, access_type);

    FATALN(!ret, node, "Can't create return variable");
    if (var->type->type == V_STRUCT)
        buffer_write(ctx->data, "%%%d = getelementptr inbounds %%struct.%s, %%struct.%s* %%%d, i32 0, i32 %d\n",
            ret->reg, var->type->name, var->type->name, var->reg, index_num);
    else {
        if (access_type->type == V_INT)
            buffer_write(ctx->data, "%%%d = bitcast %%union.%s* %%%d to i%d*\n",
                ret->reg, var->type->name, var->reg, access_type->bits);
        else if (access_type->type == V_FLOAT)
            buffer_write(ctx->data, "%%%d = bitcast %%union.%s* %%%d to %s*\n",
                ret->reg, var->type->name, var->reg, float_str(access_type->bits));
        else
            ERR("Can't access from union");
#if 0
        struct type *alt_access_type = NULL;
        int alt_index_num = struct_get_by_name(var->type, idx_name, &alt_access_type);

        // Union always get first element
        buffer_write(ctx->data, "%%%d = getelementptr inbounds %%union.%s, %%union.%s* %%%d, i32 0, i32 0\n",
            ret->reg, var->type->name, var->type->name, var->reg, index_num);

        struct variable *alt_ret = gen_access_type_target(ctx, alt_access_type);
        buffer_write(ctx->data, "%%%d = bitcast i%d%s %%%d to i%d%s ; gen_assign cast ptr\n",
#endif
        //ret = gen_cast(ctx, ret, access_type, 1);
    }

    return ret->reg;
}

int gen_addr(struct gen_context *ctx, struct node *node, int reg)
{
    if (node->addr) {
        struct variable *var = find_variable(ctx, reg);
        FATALN(!var, node, "No variable to take address from!");

        char *dst = get_stars(var->type->ptr + node->addr + 1);
        char *src = get_stars(var->type->ptr + 1);
        struct variable *res = new_variable_ext(ctx,
            NULL,
            var->type->type,
            var->type->bits, var->type->sign,
            var->type->ptr + node->addr,
            0, 0, var->type->type_name);

        if (var->type->type == V_INT) {
            gen_allocate_int(ctx, res->reg, res->type->bits, res->type->ptr, 0, 1, node->value, node);
            buffer_write(ctx->data, "store i%d%s %%%d, i%d%s %s%d, align %d ; gen_addr\n",
                res->type->bits,
                src ? src : "",
                reg,
                res->type->bits,
                dst ? dst : "",
                REGP(res),
                res->reg, align(res->type->bits)
                );
        } else if (var->type->type == V_FLOAT) {
            //gen_allocate_double(ctx, res->reg, res->type->bits, res->type->ptr, 1, node->value, node->fraction);
            gen_allocate_double(ctx, res->reg, res->type->bits, res->type->ptr, 1, node->value, 0);
            buffer_write(ctx->data, "store %s%s %%%d, %s%s %s%d, align %d ; gen_addr\n",
                float_str(var->type->bits),
                src ? src : "",
                reg,
                float_str(var->type->bits),
                dst ? dst : "",
                REGP(res),
                res->reg, align(res->type->bits)
                );
        } else if (var->type->type == V_STRUCT) {
            buffer_write(ctx->data, "%%%d = alloca %%struct.%s%s, align 8 ; gen_addr\n", res->reg, var->type->type_name, src ? src : "");
            buffer_write(ctx->data, "store %%struct.%s%s %%%d, %%struct.%s%s %s%d, align %d ; gen_addr\n",
                var->type->type_name,
                src ? src : "",
                reg,
                var->type->type_name,
                dst ? dst : "",
                REGP(res), res->reg,
                8);
        } else if (var->type->type == V_UNION) {
            buffer_write(ctx->data, "%%%d = alloca %%union.%s%s, align 8 ; gen_addr\n", res->reg, var->type->type_name, src ? src : "");
            buffer_write(ctx->data, "store %%union.%s%s %%%d, %%union.%s%s %s%d, align %d ; gen_addr\n",
                var->type->type_name,
                src ? src : "",
                reg,
                var->type->type_name,
                dst ? dst : "",
                REGP(res), res->reg,
                8);
        } else
            ERR("Invalid type: %d", res->type->type);

        if (dst)
            free(dst);
        if (src)
            free(src);
        return res->reg;
    }
    return reg;
}

int gen_dereference(struct gen_context *ctx, struct node *node, int reg)
{
    struct variable *var = find_variable(ctx, reg);
    FATALN(!var, node, "Can't find dereference variable");
    FATALN(!var->type->ptr, node, "Dereference variable is not pointer");

    char *src = get_stars(var->type->ptr);
    struct variable *res = new_variable_ext(ctx,
        NULL,
        var->type->type,
        var->type->bits, var->type->sign,
        var->type->ptr ? var->type->ptr - 1 : 0,
        0, 0, var->type->type_name);
    if (var->type->type == V_INT) {
        buffer_write(ctx->data, "%%%d = load i%d%s, i%d%s* %%%d, align %d ; DEREF %d %d\n",
            res->reg,
            res->type->bits,
            src ? src : "",
            res->type->bits,
            src ? src : "",
            var->reg,
            align(res->type->bits), res->type->ptr, var->type->ptr
            );
    } else if (var->type->type == V_STRUCT) {
        buffer_write(ctx->data, "%%%d = load %%struct.%s%s, %%struct.%s%s* %%%d, align %d ; DEREF %d %d\n",
            res->reg,
            var->type->type_name,
            src ? src : "",
            var->type->type_name,
            src ? src : "",
            var->reg,
            8
            );
    } else if (var->type->type == V_UNION) {
        buffer_write(ctx->data, "%%%d = load %%union.%s%s, %%union.%s%s* %%%d, align %d ; DEREF %d %d\n",
            res->reg,
            var->type->type_name,
            src ? src : "",
            var->type->type_name,
            src ? src : "",
            var->reg,
            8
            );
    } else
        ERR("Invalid type for deference");
    if (src)
        free(src);

    return res->reg;
}

int get_identifier(struct gen_context *ctx, struct node *node)
{
    struct variable *var = find_variable_by_name(ctx, node->value_string);
    if (!var)
        return 0;
    FATALN(!var, node, "Variable not found in get_identitifier: %s", node->value_string);
    //printf("VVAR %s, %d, %s\n", var->name, var->reg, get_type_str(ctx, var->type));
    return var->reg;
}

int gen_assign(struct gen_context *ctx, struct node *node, int left, int mid, int right)
{
    /* In case it's index we have handled it already*/
    if (node && node->left && node->left->node == A_INDEXDEF)
        return 0;
    struct variable *src_val = find_variable(ctx, right);
    if (!src_val)
        src_val = find_variable(ctx, mid);
    FATALN(!src_val, node, "Can't assign from zero: %d to %d, %d", right, left, mid);
    struct variable *src = gen_load(ctx, src_val);
    struct variable *dst = find_variable(ctx, left);

    FATALN(!src, node, "No source in assign")
    FATALN(!dst, node, "No dest in assign: %d", left)

#if 0
    node_walk(node);
    printf("ASSIGNreg: %d = %d (%d)\n", dst->reg, src->reg, right);
    printf("ASSIGN: %s = %s\n", stype_str(dst->type), stype_str(src->type));
#endif

    if (src->type->type == V_STR) {
        char *stars = get_stars(src->type->ptr);

        buffer_write(ctx->data, "store i8%s getelementptr inbounds ([%d x i8], [%d x i8]* @.str.%d, i32 0, i32 0), i%d%s* %s%d, align %d ; gen_assign str\n",
                ESTR(stars),
                src->array, src->array,
                src->reg,
                dst->type->bits, ESTR(stars),
                REGP(dst), dst->reg,
                align(dst->type->bits));

        if (stars)
            free(stars);
        return dst->reg;
    }
    // FIXME Supports only integers
    if (src->type->ptr || src->addr || (dst->type->type == V_VOID && dst->type->ptr)) {
        char *dst_name = get_name(dst);
        char *stars = get_stars(src->type->ptr);
        if (src->type->type == V_STRUCT && dst->type->type == V_STRUCT) {
            buffer_write(ctx->data, "store %%struct.%s%s %%%d, %%struct.%s%s* %s, align 8 ; gen_assign ptr struct\n",
                    src->type->type_name, ESTR(stars), src->reg,
                    dst->type->type_name, ESTR(stars),
                    dst_name);
        } else if (src->type->type == V_UNION && dst->type->type == V_UNION) {
            buffer_write(ctx->data, "store %%union.%s%s %%%d, %%union.%s%s* %s, align 8 ; gen_assign ptr union\n",
                    src->type->type_name, ESTR(stars), src->reg,
                    dst->type->type_name, ESTR(stars),
                    dst_name);
        } else if (src->type->type == V_FLOAT) {
            buffer_write(ctx->data, "store %s%s %%%d, %s%s* %s, align %d ; gen_assign ptr float\n",
                    float_str(src->type->bits),
                    stars, src->reg,
                    float_str(dst->type->bits),
                    stars,
                    dst_name,
                    align(dst->type->bits));
        } else if (src->type->type == V_VOID) {
            int dbits = dst->type->bits;
            if (dst->type->type == V_VOID)
                dbits = 8;
            buffer_write(ctx->data, "store i%d%s %%%d, i%d%s* %s%d, align %d ; gen_assign ptr void\n",
                    8,
                    ESTR(stars), src->reg,
                    dbits, ESTR(stars),
                    REGP(dst), dst->reg,
                    align(dst->type->bits));
        } else {
        if (dst->type->type == V_INT && src->type->bits != dst->type->bits) {
            char *stars = get_stars(src->type->ptr);
            char *stars2 = get_stars(dst->type->ptr);

            struct variable *res = new_inst_variable(ctx, V_INT, dst->type->bits, dst->type->sign);
            buffer_write(ctx->data, "%%%d = bitcast i%d%s %%%d to i%d%s ; gen_assign cast ptr\n",
                    res->reg, ELVIS(src->bits, 8),
                    ESTR(stars),
                    src->reg, dst->type->bits, stars2);
            if (stars)
                free(stars);
            if (stars2)
                free(stars2);
            src = res;
        }

        /* Imn case dst bits is 0, it's void ptr */
        buffer_write(ctx->data, "store i%d%s %%%d, i%d%s* %s%d, align %d ; gen_assign ptr\n",
                src->type->bits, ESTR(stars), src->reg,
                dst->type->bits ? dst->type->bits : 8,
                ESTR(stars),
                REGP(dst), dst->reg,
                align(dst->type->bits));
        }
        free(dst_name);
        if (stars)
            free(stars);
        return dst->reg;
    }
    if (dst->type->ptr && right == ctx->null_var) {
        char *stars = get_stars(dst->type->ptr);
        if (dst->type->type == V_INT) {
            buffer_write(ctx->data, "store i%d%s null, i%d%s* %s%d, align %d\n",
                dst->type->bits, stars,
                dst->type->bits, stars,
                REGP(dst), dst->reg, align(dst->type->bits));
        } else
            ERR("Invalid assign from null");
        if (stars)
            free(stars);
       return dst->reg;
    }

    if (src->type->type == V_INT) {
        src = load_and_cast_to(ctx, src, dst->type, CAST_NORMAL);
        buffer_write(ctx->data, "store i%d %%%d, i%d* %s%d, align %d ; gen_assign\n",
                src->type->bits, src->reg, dst->type->bits, REGP(dst), dst->reg, align(dst->type->bits));
    } else if (src->type->type == V_FLOAT) {
        src = load_and_cast_to(ctx, src, dst->type, CAST_NORMAL);
        buffer_write(ctx->data, "store %s %%%d, %s* %s%d, align %d ; gen_assign\n",
            float_str(src->type->bits), src->reg, float_str(src->type->bits), REGP(dst), dst->reg, align(dst->type->bits));
    } else if (src->type->type == V_STR) {
        buffer_write(ctx->data, "store i8* getelementptr inbounds "
            "([%d x i8], [%d x i8]* @.str.%d, i32 0, i32 0), "
            "i8** %%%d, align 8\n",
        src_val->bits, src_val->bits, src->reg, dst->reg);
    } else if (src->type->type == V_VOID) {
        // TODO Void pointer
        return 0;
    } else if (src->type->type == V_NULL && dst->type->type == V_INT) {
        buffer_write(ctx->data, "store i%d 0, i%d* %s%d, align %d ; gen_assign NULL to int\n",
                dst->type->bits, dst->type->bits, REGP(dst), dst->reg, align(dst->type->bits));
    } else if (src->type->type == V_CUSTOM && src->func) {
        if (dst->type->type == V_FUNCPTR) {
            // FIXME Cast between types
            char *types = get_type_str(ctx, dst->type);
            buffer_write(ctx->data, "store %s @%s, %s* %%%d; Assign func to funcptr\n",
                types, src->name, types, dst->reg);
        } else
            ERR("Can't assign function ptr to %s from %d", stype_str(dst->type), src->reg);
    } else if (src->type->type == V_FUNCPTR && dst->type->type == V_FUNCPTR) {
        char *s_ret = get_type_str(ctx, src->type->retval);
        char *s_par = get_param_type_str(ctx, src->type->params);
        char *d_ret = get_type_str(ctx, dst->type->retval);
        char *d_par = get_param_type_str(ctx, dst->type->params);
        if (src->func)
            buffer_write(ctx->data, "store %s (%s)* @%s, %s (%s)** %%%u, align 8\n",
                s_ret, s_par, src->name,
                d_ret, d_par, dst->reg);
        else
            buffer_write(ctx->data, "store %s (%s)* %%%u, %s (%s)** %%%u, align 8\n",
                s_ret, s_par, src->reg,
                d_ret, d_par, dst->reg);
        // Copy parameter str
        dst->paramstr = strcopy(src_val->paramstr);
    } else {
        ERR("Invalid assign to reg %d from reg %d, to type %s from %s", left, right, type_str(dst->type->type), type_str(src->type->type));
    }
    return dst->reg;
}

int gen_op_assign(struct gen_context *ctx, struct node *node, int left, int right)
{
    struct variable *dst = find_variable(ctx, left);
    struct variable *src_val = NULL;

    if (node->node == A_ADD_ASSIGN) {
        int tmp = gen_add(ctx, node, left, right);
        src_val = find_variable(ctx, tmp);
    } else if (node->node == A_SUB_ASSIGN) {
        int tmp = gen_sub(ctx, node, left, right);
        src_val = find_variable(ctx, tmp);
    } else if (node->node == A_MUL_ASSIGN) {
        int tmp = gen_mul(ctx, node, left, right);
        src_val = find_variable(ctx, tmp);
    } else if (node->node == A_DIV_ASSIGN) {
        int tmp = gen_div(ctx, node, left, right);
        src_val = find_variable(ctx, tmp);
    } else if (node->node == A_MOD_ASSIGN) {
        int tmp = gen_mod(ctx, node, left, right);
        src_val = find_variable(ctx, tmp);
    } else if (node->node == A_LEFT_ASSIGN) {
        int tmp = gen_shift(ctx, node, A_LEFT, left, right);
        src_val = find_variable(ctx, tmp);
    } else if (node->node == A_RIGHT_ASSIGN) {
        int tmp = gen_shift(ctx, node, A_RIGHT, left, right);
        src_val = find_variable(ctx, tmp);
    } else if (node->node == A_OR_ASSIGN) {
        int tmp = gen_bitwise(ctx, node, A_OR, left, right);
        src_val = find_variable(ctx, tmp);
    } else if (node->node == A_XOR_ASSIGN) {
        int tmp = gen_bitwise(ctx, node, A_XOR, left, right);
        src_val = find_variable(ctx, tmp);
    } else if (node->node == A_AND_ASSIGN) {
        int tmp = gen_bitwise(ctx, node, A_AND, left, right);
        src_val = find_variable(ctx, tmp);
    }
    FATALN(!src_val, node, "Invalid assign op");

    int res = gen_store_var(ctx, dst, src_val);
    return res;
}

char *gen_func_params_with(struct gen_context *ctx, struct node *orig, int allocate_params)
{
    if (!orig)
        return NULL;

    struct node *node = orig->right;
    FATALN(!node, orig, "Invalid function");

    node = node->left;
    FATALN(!node, node, "Invalid function, no name");

    node = node->right;
    if (!node)
        return NULL;

    return __get_param_type_str(ctx, node, allocate_params);

#if 0
    FATALN(node->node != A_LIST && node->type != V_VOID, node, "Parameters is not list or void");

    struct node *paramnode = node;

    struct buffer *allocs = buffer_init();
    struct buffer *params = buffer_init();
    int paramcnt = 0;
    int ellipsis = 0;
    while (node && node->node == A_LIST) {
        struct node *pval = node;
        if (node->right && node->right->node == A_LIST)
            pval = node->left;
        pval = flatten_list(pval);

        struct node *ptype = pval->left;
        struct node *pname = pval->right;
        FATALN(!ptype, pval, "Invalid parameter");
        FATALN(ellipsis, pval, "Got elements after ellipsis \"...\"");
        if (ptype->node == A_ELLIPSIS) {
            ellipsis = 1;
            paramcnt++;
            buffer_write(params, "%s...",
                paramcnt > 1 ? ", " : "");
            node = node->right;
            continue;
        }
        int t = get_type_list(ctx, ptype);
        FATALN(t >= 0, pval, "Invalid parameter type: %s", node_type_str(ptype->node));
        struct type *par_type = custom_type_get(ctx, find_type_by_id(ctx, REF_CTX(t)));
        FATALN(!par_type, pval, "Invalid parameter type: %s", node_type_str(ptype->node));
        int pointer = 0;
        while (pname && pname->node == A_POINTER) {
            pointer += pname->ptr;
            pname = pname->left;
        }
        // Need to update pointer value only once when allocting
        if (allocate_params)
            ptype->ptr += pointer;
        pointer = ptype->ptr;

        char *stars = get_stars(pointer);
        paramcnt++;
        if (par_type->type == V_INT) {
            buffer_write(params, "%si%d%s",
                paramcnt > 1 ? ", " : "",
                par_type->bits,
                ESTR(stars));
        } else if (par_type->type == V_FLOAT) {
            if (par_type->bits == 32)
                buffer_write(params, "%sfloat%s",
                    paramcnt > 1 ? ", " : "",
                    ESTR(stars));
            else
                buffer_write(params, "%sdouble%s",
                    paramcnt > 1 ? ", " : "",
                    ESTR(stars));
        } else if (par_type->type == V_VOID && pointer) {
            buffer_write(params, "%si8%s",
                paramcnt > 1 ? ", " : "",
                ESTR(stars));
        } else if (par_type->type == V_STRUCT) {
            buffer_write(params, "%s%%struct.%s%s",
                paramcnt > 1 ? ", " : "",
                par_type->type_name,
                ESTR(stars));
        } else if (par_type->type == V_UNION) {
            buffer_write(params, "%s%%union.%s%s",
                paramcnt > 1 ? ", " : "",
                par_type->type_name,
                ESTR(stars));
        } else if (par_type->type == V_VOID && pointer) {
            buffer_write(params, "%si8%s*",
                paramcnt > 1 ? ", " : "",
                ESTR(stars));
        } else if (par_type->type == V_VOID && !pointer) {
        } else {
            stack_trace();
            ERR("Invalid parameter type: %s", type_str(par_type->type));
        }
        if (stars)
            free(stars);

        node = node->right;
    }

    if (allocate_params) {
        node = paramnode;
        int parami = 0;
        if (ellipsis) {
            if (paramcnt)
                ctx->regnum += paramcnt - 1;
        } else
            ctx->regnum += paramcnt;
        while (node && node->node == A_LIST) {
            struct node *pval = node;
            if (node->right && node->right->node == A_LIST)
                pval = node->left;
            pval = flatten_list(pval);

            struct node *ptype = pval->left;
            struct node *pname = pval->right;
            if (ptype->node == A_ELLIPSIS) {
                node = node->right;
                continue;
            }
            int t = get_type_list(ctx, ptype);
            FATALN(t >= 0, pval, "Invalid parameter type: %s", node_type_str(ptype->node));
            struct type *par_type = custom_type_get(ctx, find_type_by_id(ctx, REF_CTX(t)));
            // TODO: parse types properly, now just shortcutting
            while (pname && pname->node == A_POINTER)
                pname = pname->left;
            if (par_type->type == V_VOID && !ptype->ptr) {
                // This is just "void", skip and reduce it
                // from parameters
                node = node->right;
                ctx->regnum--;
                continue;
            }

            FATALN(!pname, paramnode->parent, "No name in");

            char *stars = get_stars(ptype->ptr);
            if (par_type->type == V_INT) {
                struct variable *res = new_variable(ctx, pname->value_string, par_type->type, par_type->bits, par_type->sign, ptype->ptr, ptype->addr, 0);
                FATALN(!res, pname, "Couldn't generate res");
                buffer_write(allocs, "%%%d = alloca i%d%s, align %d\n",
                    res->reg,
                    par_type->bits,
                    ESTR(stars),
                    align(par_type->bits));
                buffer_write(allocs, "store i%d%s %%%d, i%d%s* %%%d, align %d ; func_params\n",
                    par_type->bits,
                    ESTR(stars),
                    parami,
                    par_type->bits,
                    ESTR(stars),
                    res->reg,
                    align(par_type->bits));
                pname->reg = res->reg;
            } else if (par_type->type == V_FLOAT) {
                struct variable *res = new_variable(ctx, pname->value_string, par_type->type, par_type->bits, par_type->sign, ptype->ptr, ptype->addr, 0);
                FATALN(!res, pname, "Couldn't generate res");

                buffer_write(allocs, "%%%d = alloca %s%s, align %d\n",
                    res->reg,
                    float_str(par_type->bits),
                    ESTR(stars),
                    align(par_type->bits));
                buffer_write(allocs, "store %s%s %%%d, %s%s* %%%d, align %d\n",
                    float_str(par_type->bits),
                    ESTR(stars),
                    parami,
                    float_str(par_type->bits),
                    ESTR(stars),
                    res->reg,
                    align(par_type->bits));
                pname->reg = res->reg;
            } else if (par_type->type == V_VOID) {
                struct variable *res = new_variable(ctx, pname->value_string, par_type->type, par_type->bits, par_type->sign, ptype->ptr, ptype->addr, 0);
                FATALN(!res, pname, "Couldn't generate res");
                buffer_write(allocs, "%%%d = alloca i%d%s, align %d\n",
                    res->reg,
                    8,
                    ESTR(stars),
                    8);
                buffer_write(allocs, "store i%d%s %%%d, i%d%s* %%%d, align %d ; func_params\n",
                    8,
                    ESTR(stars),
                    parami,
                    8,
                    ESTR(stars),
                    res->reg,
                    8);
                pname->reg = res->reg;
            } else if (par_type->type == V_STRUCT) {
                struct variable *res = new_variable_ext(ctx, pname->value_string, par_type->type, par_type->bits, par_type->sign, ptype->ptr, ptype->addr, 0, par_type->type_name);

                buffer_write(ctx->init, "%%%u = alloca %%struct.%s%s, align 8\n", res->reg, par_type->type_name, ESTR(stars));
                buffer_write(allocs, "store %%struct.%s%s %%%d, %%struct.%s%s* %%%d, align %d; func param list cast\n",
                    par_type->type_name,
                    ESTR(stars),
                    parami,
                    par_type->type_name,
                    ESTR(stars),
                    res->reg,
                    8);
            } else if (par_type->type == V_UNION) {
                struct variable *res = new_variable_ext(ctx, pname->value_string, par_type->type, par_type->bits, par_type->sign, ptype->ptr, ptype->addr, 0, par_type->type_name);

                buffer_write(ctx->init, "%%%u = alloca %%union.%s%s, align 8\n", res->reg, par_type->type_name, ESTR(stars));
                buffer_write(allocs, "store %%union.%s%s %%%d, %%union.%s%s* %%%d, align %d\n",
                    par_type->type_name,
                    ESTR(stars),
                    parami,
                    par_type->type_name,
                    ESTR(stars),
                    res->reg,
                    8);
            } else
                ERR("Invalid parameter type: %s", type_str(par_type->type));
            if (stars)
                free(stars);
            parami++;

            node = node->right;
        }
    }
    const char *tmp = buffer_read(params);
    int tmplen = strlen(tmp) + 1;
    char *resbuf = calloc(1, tmplen);
    resbuf = memcpy(resbuf, tmp, tmplen);
    buffer_del(params);
    if (allocate_params)
        buffer_append(ctx->init, buffer_read(allocs));
    buffer_del(allocs);
    return resbuf;
#endif
}

char *gen_func_params(struct gen_context *ctx, struct node *orig)
{
    return gen_func_params_with(ctx, orig, 1);
}

void gen_pre(struct gen_context *ctx, struct node *node, struct node *func_node, const struct type *func_type)
{
    char *tmp = NULL;
    const char *type = NULL;
    char tmp_buf[1024]; // FIXME

    if (func_type) {
        type = var_str(func_type->type, func_type->bits, &tmp);
    } else if (ctx->main_type) {
        char *stars = get_stars(ctx->main_type->ptr);
        switch (ctx->main_type->type) {
        case V_STRUCT:
            snprintf(tmp_buf, 1024, "%%struct.%s%s", ctx->main_type->type_name, ESTR(stars));
            type = tmp_buf;
            break;
        case V_UNION:
            snprintf(tmp_buf, 1024, "%%union.%s%s", ctx->main_type->type_name, ESTR(stars));
            type = tmp_buf;
            break;
        default:
            type = var_str(ctx->main_type->type, ctx->main_type->bits, &tmp);
        }
        if (stars)
            free(stars);
    } else if (strcmp(ctx->name, "main") == 0 && func_type->type == V_VOID)
        type = var_str(V_INT, 32, &tmp);
    else {
        type = var_str(node->type, node->bits, &tmp);
    }

    char *params = NULL;
    // Global context can't have params
    if (!ctx->global && func_node)
        params = gen_func_params(ctx, func_node);

    if (strcmp(ctx->name, global_ctx_name) == 0) {
        buffer_write(ctx->pre, "@llvm.global_ctors = appending global [1 x { i32, void ()*, i8* }] [{ i32, void ()*, i8* } { i32 65535, void ()* @_GLOBAL_ctor, i8* null }]\n");
        buffer_write(ctx->pre, "define internal void @_GLOBAL_ctor() #0 {\n    call %s @%s()\n    ret void\n}\n", type, ctx->name);
        buffer_write(ctx->pre, "define internal %s @%s(%s) #0 {\n",
                type, ctx->name,
                params ? params : "");
    } else {
        buffer_write(ctx->pre, "define dso_local %s @%s(%s) #0 {\n",
                type, ctx->name,
                params ? params : "");
    }
    if (params)
        free(params);
    if (tmp)
        free(tmp);
}

void gen_post(struct gen_context *ctx, struct node *node, int res, const struct type *target, const struct type *functype)
{
    if (!target && functype)
        target = functype;

    if (strcmp(ctx->name, "main") == 0 && (!functype || functype->type == V_VOID)) {
        buffer_write(ctx->data, "ret i32 0 ; RET5\n");
    } else if (target && target->type != V_VOID) {
        struct variable *var = find_variable(ctx, res);
        char *stars = get_stars(target->ptr);
        if (var && var->type->type == V_VOID) {
            buffer_write(ctx->post, "ret i32 0 ; RET6\n");
        } else if (var && var->type->type != V_NULL) {
            var = load_and_cast_to(ctx, var, target, CAST_FLATTEN_PTR);
            res = var->reg;
            if (target->type == V_INT) {
                buffer_write(ctx->post, "ret i%d%s %%%d ; RET1\n", target->bits, ESTR(stars), res);
            } else if (target->type == V_FLOAT) {
                buffer_write(ctx->post, "ret %s%s %%%d ; RET1\n", float_str(target->bits), ESTR(stars), res);
            } else if (target->type == V_STRUCT) {
                buffer_write(ctx->data, "ret %%struct.%s%s %%%d ; RET1\n",
                        target->type_name, ESTR(stars), res);
            } else
                ERR("Invalid return type");

            ctx->rets++;
        } else {
            if (target->type == V_INT) {
                buffer_write(ctx->data, "ret i%d 0 ; RET2\n", target->bits, res);
            } else if (target->type == V_FLOAT) {
                buffer_write(ctx->data, "ret %s 0.0 ; RET2\n", float_str(target->bits), res);
            } else
                ERR("Invalid return type");
            ctx->rets++;
        }
        if (stars)
            free(stars);
    } else {
        buffer_write(ctx->post, "ret void ; RET4\n");
        ctx->rets++;
    }
    buffer_write(ctx->post, "}\n");
}

int gen_recursive_allocs(struct gen_context *ctx, struct node *node);
int gen_recursive(struct gen_context *ctx, struct node *node);
int gen_function(struct gen_context *ctx, struct node *node)
{
    struct gen_context *func_ctx = init_ctx(ctx->f, ctx);
    func_ctx->gen_flags = ctx->gen_flags;

    FATALN(!node->left, node, "Missing function definition");

    int func_proto = gen_recursive(func_ctx, node->left);
    (void)func_proto;

    struct node *r = node->right;
    FATALN(!r, node, "Function body missing");
    struct node *name = r->left;
    while ((name->node != A_IDENTIFIER || name->value_string == NULL) && name->left) {
        name = name->left;
    }
    FATALN(!name, r, "Function name missing");
    FATALN(name->node != A_IDENTIFIER, r, "Faulty function name");
    func_ctx->name = name->value_string;
    struct node *body = NULL;

    if (node && node->right && node->right->right)
        body = node->right->right;

    if (!body) {
        // This is prototype, it's declared earlier
        free_ctx(func_ctx);
        return 0;
    }

    // Find previously defined function
    struct variable *func_var = find_variable_by_name(ctx, func_ctx->name);
    const struct type *func_ret_type = custom_type_get(ctx, func_var->type->retval);
    // Need to tell return type
    if (func_ctx->main_type == NULL)
        func_ctx->main_type = func_ret_type;

    if (strcmp(func_ctx->name, "main") == 0 && func_ctx->main_type->type == V_VOID)
        func_ctx->main_type = find_type_by(ctx, V_INT, 32, TYPE_SIGNED, 0);

    FATALN(!func_var, node, "Function not found: %s", func_ctx->name);
    FATALN(!func_var->func, node, "Function variable already in use: %s", func_ctx->name);

    gen_pre(func_ctx, node->left, node, NULL);
    struct node *func_node = NULL;
    if (ctx->global && strcmp(func_ctx->name, "main") == 0) {
        func_node = ctx->node;
#if 0
        if (func_ret_type->type != V_VOID) {
            struct variable *ret = new_inst_variable(func_ctx, V_INT, 32, TYPE_SIGNED);
            buffer_write(func_ctx->init, "%%%d = call i32 @%s()\n", ret->reg, ctx->name);
        } else
            buffer_write(func_ctx->init, "call void @%s()\n", ctx->name);
#endif
    }

    FATALN(node->right->node != A_GLUE, node->right, "Invalid function");

    //func_ctx->debug = 1;
    int res = gen_recursive_allocs(func_ctx, body);
    res = gen_recursive(func_ctx, body);
    //func_ctx->debug = 0;

    gen_post(func_ctx, func_node, res, func_ret_type, func_ret_type);

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
    const struct type *target = custom_type_get(ctx, resolve_return_type(ctx, ctx->node, res));
    if (right)
        var = find_variable(ctx, right);
    else
        var = find_variable(ctx, left);

    var = load_and_cast_to(ctx, var, target, CAST_NORMAL);
    res = var->reg;
    char *stars = get_stars(target->ptr);

    if (target->type == V_INT) {
        buffer_write(ctx->data, "ret i%d%s %%%d ; RET3\n", target->bits, ESTR(stars), res);
    } else if (target->type == V_FLOAT) {
        buffer_write(ctx->data, "ret %s%s %%%d ; RET3\n", float_str(target->bits), ESTR(stars), res);
    } else if (target->type == V_STRUCT) {
        buffer_write(ctx->data, "ret %%struct.%s%s %%%d ; RET3\n",
                target->type_name, ESTR(stars), res);
    } else
        ERR("Invalid/unsupported return type");
    if (stars)
        free(stars);
    ctx->rets++;

    return res;
}

int gen_declaration(struct gen_context *ctx, struct node *node, int left, int right)
{
    FATALN(left >= 0, node, "Invalid type definition in declaration");
    ctx->pending_type = NULL;
    return right;
}

int gen_cmp_bool(struct gen_context *ctx, struct variable *src)
{
    struct variable *var = gen_load(ctx, src);
    FATAL(!var, "Invalid variable for bool comparison");

    struct variable *res = new_bool(ctx, VAR_DIRECT);
    if (var->type->ptr) {
        char *stars = get_stars(var->type->ptr);

        buffer_write(ctx->data, "%%%d = icmp ne i%d%s %%%d, null\n",
            res->reg, var->type->bits,
            stars,
            var->reg);
        if (stars)
            free(stars);
        return res->reg;
    } else if (var->type->type == V_INT) {
        buffer_write(ctx->data, "%%%d = icmp ne i%d %%%d, 0\n",
            res->reg, var->type->bits,
            var->reg);
        return res->reg;
    } else if (var->type->type == V_FLOAT) {
        buffer_write(ctx->data, "%%%d = fcmp une %s %%%d, 0.0e+00\n",
            res->reg,
            float_str(var->type->bits),
            var->reg);
        return res->reg;
    } else if (var->type->type == V_NULL) {
        ERR("NULL CMP\n");
    }

    ERR("Invalid cmp to bool");

    return -1;
}

int gen_reserve_label(struct gen_context *ctx)
{
    return ctx->labels++;
}

int gen_if(struct gen_context *ctx, struct node *node, int ternary)
{
    // Conditional clause on left
    FATALN(!node->left, node, "No conditional in if");
    buffer_write(ctx->data, "; if begin\n");

    int cond_reg = gen_recursive(ctx, node->left);
    struct variable *cond = find_variable(ctx, cond_reg);

    int cmp_reg = gen_cmp_bool(ctx, cond);

    struct buffer *cmpblock = buffer_init();
    struct buffer *ifblock = buffer_init();
    struct buffer *tmp = ctx->data;
    int inc = 0;
    int inc2 = 0;
    struct variable *res = NULL;
    int ifret = 0;
    /*
     * FIXME This is horrible hack to preserve register number
     * for ternary return value. If we don't do this hack
     * we might end up having invalid LLVM IR output causing
     * some register number being allocated in wrong order.
     */
    int ternary_save = 0;

    buffer_write(ctx->data, "; if branches\n");
    ctx->data = cmpblock;
    int label1 = gen_reserve_label(ctx);
    buffer_write(cmpblock, "L%d: ; True block\n", label1);
    if (node->mid) {
        // Reserve ternary regnum
        if (ternary)
            ternary_save = ctx->regnum++;
        int rets = ctx->rets;
        ifret = gen_recursive(ctx, node->mid);
        inc = rets < ctx->rets;
    } else
        FATALN(ternary, node, "Ternary missing true block!");

    /* Handle ternary return value */
    ctx->data = tmp;
    if (ternary) {
        // Save current regnum
        int ternary_post = ctx->regnum;

        // Restore to ternary number
        ctx->regnum = ternary_save;
        struct variable *tres = find_variable(ctx, ifret);
        FATALN(!tres, node, "Ternary return type invalid");
        buffer_write(cmpblock, "; TERNARY TRUE\n");
        res = new_variable(ctx, NULL, tres->type->type, tres->type->bits, tres->type->sign, tres->type->ptr, tres->addr, 0);
        gen_allocate_int(ctx, res->reg,
            ELVIS(tres->type->bits, 8), tres->type->ptr,
            0, 1, 0, NULL);

        // Restore where we were before the hack
        // We'll shoot ourselves in foot if we caused more than one regnum resevation above for ternary
        buffer_write(cmpblock, "; TR: %d %d\n", ctx->regnum, ternary_post);
        ctx->regnum = ternary_post;
        ctx->data = cmpblock;

        tres = var_cast_to(ctx, tres, res->type);

        gen_assign(ctx, NULL,  res->reg, 0, tres->reg);
    }

    /* Hack to handle "unnamed" and unreachable branch */
    if (inc)
        ctx->regnum++;

    ctx->data = ifblock;
    int label2 = gen_reserve_label(ctx);
    if (!inc && !node->right)
        buffer_write(ifblock, "br label %%L%d ; extra1\n", label2);
    buffer_write(ifblock, "L%d: ; False block\n", label2);
    if (node->right) {
        int rets = ctx->rets;
        ifret = gen_recursive(ctx, node->right);
        inc2 = rets < ctx->rets;
        if (ternary) {
            struct variable *tres = find_variable(ctx, ifret);
            buffer_write(ctx->data, "; TERNARY FALSE\n");
            FATALN(!tres, node->right, "Ternary return type invalid");
            FATALN(!res, node->right, "Invalid ternary");

            tres = var_cast_to(ctx, tres, res->type);
            gen_assign(ctx, NULL,  res->reg, 0, tres->reg);
        }
    } else {
        FATALN(ternary, node, "Ternary missing false block!");
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

    buffer_write(ctx->data, "; if end\n");

    return ternary ? res->reg : 0;
}

int set_breaklabel(struct gen_context *ctx, int label)
{
    int res = ctx->breaklabel;
    ctx->breaklabel = label;
    return res;
}

int set_continuelabel(struct gen_context *ctx, int label)
{
    int res = ctx->continuelabel;
    ctx->continuelabel = label;
    return res;
}

int gen_while(struct gen_context *ctx, struct node *node, enum looptype looptype)
{
    int looplabel = gen_reserve_label(ctx);
    int inclabel = gen_reserve_label(ctx);
    int cmplabel = gen_reserve_label(ctx);
    int outlabel = gen_reserve_label(ctx);
    int brklabel = set_breaklabel(ctx, outlabel);
    int contlabel = set_continuelabel(ctx, inclabel);

    buffer_write(ctx->data, "; Loop begin\n");
    if (looptype == LOOP_FOR) {
        FATALN(!node->left || node->left->node != A_GLUE, node, "Invalid for loop");
        if (node->left->left) {
            buffer_write(ctx->data, "; For init\n");
            gen_recursive(ctx, node->left->left);
        }
        buffer_write(ctx->data, "br label %%L%d\n", cmplabel);
    } else if (looptype == LOOP_DO) {
        buffer_write(ctx->data, "br label %%L%d\n", looplabel);
    } else {
        buffer_write(ctx->data, "br label %%L%d\n", cmplabel);
    }
    buffer_write(ctx->data, "L%d:\n", looplabel);

    int rets = ctx->rets;
    if (node->right)
        gen_recursive(ctx, node->right);
    if (rets != ctx->rets)
        ctx->regnum++;

    buffer_write(ctx->data, "br label %%L%d\n", inclabel);
    buffer_write(ctx->data, "L%d:\n", inclabel);
    if (looptype == LOOP_FOR) {
        buffer_write(ctx->data, "; Loop inc\n");
        if (node->left->right)
            gen_recursive(ctx, node->left->right);
    }
    buffer_write(ctx->data, "; Loop compare\n");
    buffer_write(ctx->data, "br label %%L%d\n", cmplabel);
    buffer_write(ctx->data, "L%d:\n", cmplabel);

    if (node->mid) {
        int cond_reg = gen_recursive(ctx, node->mid);
        struct variable *cond = find_variable(ctx, cond_reg);
        int cmp_reg = gen_cmp_bool(ctx, cond);

        buffer_write(ctx->data, "br i1 %%%d, label %%L%d, label %%L%d\n",
            cmp_reg, looplabel, outlabel);
    } else {
        // There's no compare, so loop forever
        buffer_write(ctx->data, "br label %%L%d\n", looplabel);
    }
    buffer_write(ctx->data, "; Exit loop\n");
    buffer_write(ctx->data, "L%d:\n", outlabel);

    set_breaklabel(ctx, brklabel);
    set_continuelabel(ctx, contlabel);

    return 0;
}

int gen_break(struct gen_context *ctx, struct node *node, int a)
{
    FATALN(!ctx->breaklabel, node, "No break label");
    buffer_write(ctx->data, "br label %%L%d ; break\n", ctx->breaklabel);
    ctx->regnum++;
    return ctx->breaklabel;
}

int gen_continue(struct gen_context *ctx, struct node *node, int a)
{
    FATALN(!ctx->continuelabel, node, "No continue label");
    buffer_write(ctx->data, "br label %%L%d ; continue\n", ctx->continuelabel);
    ctx->regnum++;
    return ctx->continuelabel;
}

int gen_label(struct gen_context *ctx, struct node *node)
{
    buffer_write(ctx->data, "br label %%LABEL_%s ; label goto\n", node->value_string);
    buffer_write(ctx->data, "LABEL_%s: ; label\n", node->value_string);
    return 0;
}

int gen_goto(struct gen_context *ctx, struct node *node)
{
    struct node *label = node->left;

    FATALN(!label, node, "Goto missing label");

    buffer_write(ctx->data, "br label %%LABEL_%s ; goto\n", label->value_string);
    ctx->regnum++;
    return 0;
}

int gen_pre_post_op(struct gen_context *ctx, struct node *node, int a)
{
    struct variable *orig = find_variable(ctx, a);
    struct variable *var = gen_load(ctx, orig);

    FATALN(!var, node, "No postinc/postdec variable");

    struct variable *res = new_inst_variable(ctx, var->type->type, var->type->bits, var->type->sign);

    if (node->node == A_PREINC || node->node == A_POSTINC) {
        if (var->type->ptr) {
            res = gen_access_ptr(ctx, var, res, NULL, 1);
            int ptrdiff = var->type->ptr - res->type->ptr;
            res->type = type_wrap_to(ctx, res->type, ptrdiff);
        } else if (res->type->type == V_INT) {
            buffer_write(ctx->data, "%%%d = add nsw i%d %%%d, 1\n",
                res->reg, var->type->bits, var->reg);
        } else if (res->type->type == V_FLOAT) {
            buffer_write(ctx->data, "%%%d = fadd %s %%%d, 1.0e+00\n",
                res->reg, float_str(res->type->bits), var->reg);
        } else ERR_TRACE("Invalid type: %d", node->type);
        gen_store_var(ctx, orig, res);
    } else if (node->node == A_PREDEC || node->node == A_POSTDEC) {
        if (var->type->ptr) {
            res = gen_access_ptr(ctx, var, res, NULL, -1);
            int ptrdiff = var->type->ptr - res->type->ptr;
            res->type = type_wrap_to(ctx, res->type, ptrdiff);
        } else if (res->type->type == V_INT) {
            buffer_write(ctx->data, "%%%d = sub i%d %%%d, 1\n",
                res->reg, var->type->bits, var->reg);
        } else if (res->type->type == V_FLOAT) {
            buffer_write(ctx->data, "%%%d = fsub %s %%%d, 1.0e+00\n",
                res->reg, float_str(res->type->bits), var->reg);
        } else ERR_TRACE("Invalid type");
        gen_store_var(ctx, orig, res);
    } else FATALN(1, node, "Invalid pre/post op");

    return (node->node == A_POSTINC || node->node == A_POSTDEC) ? var->reg : res->reg;
}

void gen_var_function(struct gen_context *ctx, const char *func_name)
{
    struct gen_context *global_ctx = get_global_ctx(ctx);
    struct buffer *pretty_id = buffer_init();
    buffer_write(pretty_id, "@__FUNCTION__.%s", func_name);
    int slen = strlen(func_name) + 1;
    struct variable *pretty_val = new_variable(global_ctx, buffer_read(pretty_id), V_STR, slen, TYPE_UNSIGNED, 0, 0, 1);

    if (!pretty_val->type->ptr)
        pretty_val->type = type_wrap(ctx, pretty_val->type);
    pretty_val->array = slen;
    pretty_val->literal = 1;

    buffer_write(ctx->init, "; __FUNCTION__.%s\n", func_name);
    buffer_write(global_ctx->init, "@.str.%d = private unnamed_addr constant [%u x i8] c\"%s\\00\", align 1\n",
        pretty_val->reg, slen, func_name);
    //buffer_del(pretty_id); // FIXME
}

void gen_var_pretty_function(struct gen_context *ctx, const char *func_name, const char *type, const char *params)
{
    struct gen_context *global_ctx = get_global_ctx(ctx);
    struct buffer *pretty = buffer_init();
    buffer_write(pretty, "%s %s(%s)", type, func_name, params ? params : "");
    const char *namestr = buffer_read(pretty);
    struct buffer *pretty_id = buffer_init();
    buffer_write(pretty_id, "@__PRETTY_FUNCTION__.%s", func_name);
    int slen = strlen(namestr) + 1;
    struct variable *pretty_val = new_variable(global_ctx, buffer_read(pretty_id), V_STR, slen, TYPE_UNSIGNED, 0, 0, 1);
    if (!pretty_val->type->ptr)
        pretty_val->type = type_wrap(ctx, pretty_val->type);
    pretty_val->array = slen;
    pretty_val->literal = 1;

    buffer_write(ctx->init, "; __PRETTY_FUNCTION__.%s\n", func_name);
    buffer_write(global_ctx->init, "@.str.%d = private unnamed_addr constant [%u x i8] c\"%s\\00\", align 1\n",
        pretty_val->reg, slen, namestr);
    buffer_del(pretty);
    //buffer_del(pretty_id); // FIXME
}

struct variable *gen_alloc_func(struct gen_context *ctx, struct node *node)
{
    struct node *body = node->right;
    FATALN(!body, node, "Function body missing");

    struct node *name = body->left;
    FATALN(!name, node, "Function name missing");

    struct gen_context *func_ctx = init_ctx(ctx->f, ctx);

    const char *func_name = name->value_string;
    struct variable *func_var = find_variable_by_name(ctx, func_name);
    const struct type *func_ret_type = gen_type_list_type(ctx, node->left);

    if (!func_var) {
        const struct type *func_type = register_type(ctx, func_name, V_FUNCPTR, 64, TYPE_UNSIGNED);

        ((struct type*)func_type)->retval = func_ret_type;
        ((struct type*)func_type)->params = node->right->left->right;

        func_var = new_variable_ext(ctx, func_name, V_FUNCPTR, 64, TYPE_UNSIGNED, 0, 0, 1, func_name);
    }

    func_ctx->context_ref = LLVMContextCreate();
    func_ctx->build_ref = LLVMCreateBuilderInContext(func_ctx->context_ref);
    LLVMTypeRef functype = LLVMFunctionType(
        sic_type_to_llvm_type(func_ret_type),
        NULL, 0, 0
        );


    func_var->val = LLVMAddFunction(ctx->mod_ref, func_name, functype);
    func_ctx->func_ref = func_var->val;
    func_ctx->block_ref = LLVMAppendBasicBlockInContext(func_ctx->context_ref, func_ctx->func_ref, "entry");

    LLVMPositionBuilderAtEnd(func_ctx->build_ref, func_ctx->block_ref);

    LLVMValueRef retval = LLVMConstInt(LLVMInt32TypeInContext(func_ctx->context_ref), 0, 0);

    if (node && node->right && node->right->right)
        body = node->right->right;
    else
        body = NULL;
    /* Recurse into function body */
    int resval = gen_recurse(func_ctx, body);
    (void)resval;

    if (!func_ctx->last_is_ret) {
        switch (func_ret_type->type) {
        case V_INT:
            LLVMBuildRet(func_ctx->build_ref, retval);
            break;
        default:
        case V_VOID:
            LLVMBuildRetVoid(func_ctx->build_ref);
            break;
        }
    }

    return func_var;

#if 0
    struct node *r = node->right;
    FATALN(!r, node, "Function body missing");
    struct node *name = r->left;
    FATALN(!name, node, "Function name missing");
    const char *func_name = name->value_string;
    struct node *func_node = node->left;
    const char *type = NULL;
    char *tmp = NULL;
    char *params = NULL;
    const struct type *func_ret_type = gen_type_list_type(ctx, node->left);
    while ((name->node != A_IDENTIFIER || func_name == NULL) && name->left) {
        name = name->left;
        func_name = name->value_string;
    }
    FATALN(!name, node, "Missing function name");
    if (strcmp(func_name, "main") == 0) {
        if (func_ret_type->type == V_VOID)
            func_ret_type = find_type_by(ctx, V_VOID, 0, TYPE_UNSIGNED, 0);
    }

    struct variable *func_var = find_variable_by_name(ctx, func_name);
    FATALN(func_var && func_var->prototype == 0, node, "Function name already in use: %s", func_name);

    if (!func_var) {
        const struct type *func_type = register_type(ctx, func_name, V_FUNCPTR, 64, TYPE_UNSIGNED);
        ((struct type*)func_type)->retval = func_ret_type;
        ((struct type*)func_type)->params = node->right->left->right;
        (void)func_node;

        func_var = new_variable_ext(ctx, func_name, V_FUNCPTR, 64, TYPE_UNSIGNED, 0, 0, 1, func_name);
    }
    func_var->func = 1;
    FATALN(!node->right, node, "Invalid function");
    FATALN(!node->right->left, node, "Invalid function, no name");
    func_var->params = node->right->left->right;

    if (strcmp(func_name, "main") == 0 && func_ret_type->type == V_VOID)
        type = var_str(V_INT, 32, &tmp);
    else
        type = var_str(func_ret_type->type, func_ret_type->bits, &tmp);

    if (func_var->prototype)
        params = func_var->paramstr;
    else {
        params = gen_func_params_with(ctx, node, 0);
        func_var->paramstr = params;
    }
    if (ctx->gen_flags & GEN_FUNCTION)
        gen_var_function(ctx, func_name);
    if (ctx->gen_flags & GEN_PRETTY_FUNCTION)
        gen_var_pretty_function(ctx, func_name, type, params);

    struct node *body = NULL;
    if (node && node->right && node->right->right)
        body = node->right->right;
    if (!body) {
        // This is prototype, just mark it.
        func_var->prototype = 1;
    } else {
        func_var->prototype = 0;
    }
    if (tmp)
        free(tmp);
    if (strcmp(func_name, "main") == 0)
        return func_var;

#endif
    return NULL;
}

// Scan all functions
struct variable *gen_scan_functions(struct gen_context *ctx, struct node *node)
{
    struct variable *res = NULL;
    if (node == NULL)
        return res;

    if (node->node == A_FUNCTION)
        res = gen_alloc_func(ctx, node);

    if (node->left) {
        struct variable *tmp = gen_scan_functions(ctx, node->left);
        if (!res)
            res = tmp;
    }
    if (node->right) {
        struct variable *tmp = gen_scan_functions(ctx, node->right);
        if (!res)
            res = tmp;
    }
    return res;
}

void __gen_func_declarations(struct gen_context *global_ctx, struct variable *var)
{
    while (var) {
        if (var->prototype) {
            FATAL(!var->func, "Got non-function prototype");

            const struct type *func_ret_type = custom_type_get(global_ctx, var->type->retval);
            const char *type = NULL;
            const char *func_name = var->name;
            char *tmp = NULL;
            if (strcmp(func_name, "main") == 0 && func_ret_type->type == V_VOID)
                type = var_str(V_INT, 32, &tmp);
            else if (func_ret_type->type == V_STRUCT) {
                tmp = calloc(1, 256);
                sprintf(tmp, "%%struct.%s", func_ret_type->type_name);
                type = tmp;
            } else if (func_ret_type->type == V_UNION) {
                tmp = calloc(1, 256);
                sprintf(tmp, "%%union.%s", func_ret_type->type_name);
                type = tmp;
            } else
                type = var_str(func_ret_type->type, func_ret_type->bits, &tmp);

            char *stars = get_stars(func_ret_type->ptr);
            buffer_write(global_ctx->pre, "declare %s%s @%s(%s);\n",
                type, stars, func_name,
                var->paramstr ? var->paramstr : "", type);
            free(stars);
            if (tmp)
                free(tmp);
        }
        var = var->next;
    }
}

void gen_func_declarations(struct gen_context *ctx)
{
    struct gen_context *global_ctx = get_global_ctx(ctx);

    __gen_func_declarations(global_ctx, ctx->globals);
    __gen_func_declarations(global_ctx, ctx->variables);

    if (ctx->parent)
        gen_func_declarations(ctx->parent);
}

void gen_scan_struct_typedef(struct gen_context *ctx, struct node *node)
{
    if (!node)
        return;

    if (node->node == A_TYPEDEF) {
        const struct type *tmp = gen_type_list_type(ctx, node->left);
        struct type *res = NULL;
        FATALN(!tmp, node, "Invalid typedef, missing result type");

        if (node->is_func) {
            res = register_type(ctx, node->value_string, V_FUNCPTR, 64, TYPE_UNSIGNED);
            res->type_name = node->value_string;
            res->params = node->mid;
            res->retval = tmp;
            // FIXME
            res = (struct type*)type_wrap_to(ctx, res, node->ptr);
            //res->ptr = node->ptr;
            //printf("PTRVVV: %d %d %s, id %d\n", node->ptr, res->ptr, res->type_name, res->id);
        } else {
            res = register_custom_type(ctx, node->value_string, V_CUSTOM, tmp->bits, tmp->sign, tmp);
            res->type_name = node->value_string;
        }
#if DEBUG
        printf("Reg type: %s\n", stype_str(res));
        printf("Custom  : %s\n", stype_str(tmp));
        printf("From node:\n");
        node_walk(node);
#endif
        return;
    } else if (node->node == A_TYPE && (node->type == V_STRUCT || node->type == V_UNION)) {
        gen_type(ctx, node);
        return;
    }

    gen_scan_struct_typedef(ctx, node->left);
    gen_scan_struct_typedef(ctx, node->right);
}

void gen_builtin_va_list(struct gen_context *ctx, struct node *node)
{
    struct type *res = register_type(ctx, node->value_string, V_STRUCT, 8, TYPE_UNSIGNED);
    res->type_name = node->value_string;

    // FIXME { i8* } now, shoulde be { i32, i32, i8*, i8* }
    buffer_write(ctx->init, "%%struct.%s = type { i32, i32, i8*, i8* } ; builtin va_list\n", node->value_string);
    res->itemcnt = 4;
    res->items = calloc(res->itemcnt, sizeof(struct type_item));

    const struct type *int32 = find_type_by(ctx, V_INT, 32, TYPE_UNSIGNED, 1);
    if (!int32) {
        int32 = find_type_by(ctx, V_INT, 32, TYPE_UNSIGNED, 0);
    }

    const struct type *int8 = find_type_by(ctx, V_INT, 8, TYPE_UNSIGNED, 1);
    if (!int8) {
        int8 = find_type_by(ctx, V_INT, 8, TYPE_UNSIGNED, 0);
        int8 = type_wrap(ctx, int8);
    }

    res->items[0].item = int32;
    res->items[0].name = "value1";
    res->items[1].item = int32;
    res->items[1].name = "value2";
    res->items[2].item = int8;
    res->items[2].name = "value3";
    res->items[3].item = int8;
    res->items[3].name = "value4";
}

void gen_builtin_va_start(struct gen_context *ctx, struct node *node)
{
    const struct type *func_ret_type = find_type_by_name(ctx, "void");
    FATALN(!func_ret_type, node, "Couldn't find void type");

    const struct type *func_type = register_type(ctx, node->value_string, V_FUNCPTR, 64, TYPE_UNSIGNED);

    ((struct type*)func_type)->retval = func_ret_type;
    struct variable *func_var = new_variable_ext(ctx, node->value_string, V_FUNCPTR, 64, TYPE_UNSIGNED, 0, 0, 1, node->value_string);
    func_var->func = 1;

    struct node *par1_def = make_node(NULL, A_TYPESPEC, NULL, NULL, NULL);
    par1_def->type = V_INT;
    par1_def->bits = 8;
    par1_def->value_string = "char";

    struct node *ptrname1 = make_node(NULL, A_IDENTIFIER, NULL, NULL, NULL);
    ptrname1->value_string = "__generated_parameter";

    struct node *ptr1 = make_node(NULL, A_POINTER, ptrname1, NULL, NULL);
    ptr1->ptr = 1;

    struct node *par1 = make_node(NULL, A_TYPE_LIST, par1_def, NULL, NULL);

    func_var->params = make_node(NULL, A_LIST, par1, NULL, ptr1);
    ((struct type*)func_type)->params = func_var->params ;

    buffer_write(ctx->init, "declare void @llvm.va_start(i8*)\n");
}

void gen_builtin_va_end(struct gen_context *ctx, struct node *node)
{
    const struct type *func_ret_type = find_type_by_name(ctx, "void");
    FATALN(!func_ret_type, node, "Couldn't find void type");

    const struct type *func_type = register_type(ctx, node->value_string, V_FUNCPTR, 64, TYPE_UNSIGNED);

    ((struct type*)func_type)->retval = func_ret_type;
    struct variable *func_var = new_variable_ext(ctx, node->value_string, V_FUNCPTR, 64, TYPE_UNSIGNED, 0, 0, 1, node->value_string);
    func_var->func = 1;

    struct node *par1_def = make_node(NULL, A_TYPESPEC, NULL, NULL, NULL);
    par1_def->type = V_INT;
    par1_def->bits = 8;
    par1_def->value_string = "char";

    struct node *ptrname1 = make_node(NULL, A_IDENTIFIER, NULL, NULL, NULL);
    ptrname1->value_string = "__generated_parameter";

    struct node *ptr1 = make_node(NULL, A_POINTER, ptrname1, NULL, NULL);
    ptr1->ptr = 1;

    struct node *par1 = make_node(NULL, A_TYPE_LIST, par1_def, NULL, NULL);

    func_var->params = make_node(NULL, A_LIST, par1, NULL, ptr1);
    ((struct type*)func_type)->params = func_var->params ;

    buffer_write(ctx->init, "declare void @llvm.va_end(i8*)\n");
}

void gen_builtin_va_arg(struct gen_context *ctx, struct node *node)
{
    const struct type *func_ret_type = find_type_by_name(ctx, "void");
    FATALN(!func_ret_type, node, "Couldn't find void type");

    const struct type *func_type = register_type(ctx, node->value_string, V_FUNCPTR, 64, TYPE_UNSIGNED);

    ((struct type*)func_type)->retval = func_ret_type;
    struct variable *func_var = new_variable_ext(ctx, node->value_string, V_FUNCPTR, 64, TYPE_UNSIGNED, 0, 0, 1, node->value_string);
    func_var->func = 1;

    struct node *par1_def = make_node(NULL, A_TYPESPEC, NULL, NULL, NULL);
    par1_def->type = V_INT;
    par1_def->bits = 8;
    par1_def->value_string = "char";

    struct node *ptrname1 = make_node(NULL, A_IDENTIFIER, NULL, NULL, NULL);
    ptrname1->value_string = "__generated_parameter";

    struct node *ptr1 = make_node(NULL, A_POINTER, ptrname1, NULL, NULL);
    ptr1->ptr = 1;

    struct node *par1 = make_node(NULL, A_TYPE_LIST, par1_def, NULL, NULL);

    func_var->params = make_node(NULL, A_LIST, par1, NULL, ptr1);
    ((struct type*)func_type)->params = func_var->params ;
}

void gen_builtin_bswap(struct gen_context *ctx, struct node *node, int bits)
{
    const struct type *func_ret_type;
    switch (bits) {
    case 16:
        func_ret_type = find_type_by_name(ctx, "short");
        break;
    case 32:
        func_ret_type = find_type_by_name(ctx, "int");
        break;
    case 64:
        func_ret_type = find_type_by_name(ctx, "long");
        break;
    default:
        func_ret_type = NULL;
    }
    FATALN(!func_ret_type, node, "Couldn't find bswap type");

    const struct type *func_type = register_type(ctx, node->value_string, V_FUNCPTR, 64, TYPE_UNSIGNED);

    ((struct type*)func_type)->retval = func_ret_type;
    struct variable *func_var = new_variable_ext(ctx, node->value_string, V_FUNCPTR, 64, TYPE_UNSIGNED, 0, 0, 1, node->value_string);
    func_var->func = 1;

    struct node *par1_def = make_node(NULL, A_TYPESPEC, NULL, NULL, NULL);
    par1_def->type = V_INT;
    par1_def->bits = bits;
    par1_def->value_string = "short";
    switch (bits) {
    case 16:
        par1_def->value_string = "short";
        break;
    case 32:
        par1_def->value_string = "int";
        break;
    case 64:
        par1_def->value_string = "long";
        break;
    }

    struct node *ptrname1 = make_node(NULL, A_IDENTIFIER, NULL, NULL, NULL);
    ptrname1->value_string = "__generated_parameter";

    struct node *par1 = make_node(NULL, A_TYPE_LIST, par1_def, NULL, NULL);

    func_var->params = make_node(NULL, A_LIST, par1, NULL,  NULL);
    ((struct type*)func_type)->params = func_var->params ;

    switch (bits) {
    case 16:
        buffer_write(ctx->init, "declare i16 @llvm.bswap.16(i16)\n");
        break;
    case 32:
        buffer_write(ctx->init, "declare i32 @llvm.bswap.32(i32)\n");
        break;
    case 64:
        buffer_write(ctx->init, "declare i64 @llvm.bswap.64(i64)\n");
        break;
    }
}

int gen_null(struct gen_context *ctx, struct node *node)
{
    return ctx->null_var;
}

LLVMValueRef gen_llvm_int_const_ref(int bits, literalnum val, int signext)
{
    switch (bits) {
    case 1:
        return LLVMConstInt(LLVMInt1Type(), val, signext);
    case 8:
        return LLVMConstInt(LLVMInt8Type(), val, signext);
    case 16:
        return LLVMConstInt(LLVMInt16Type(), val, signext);
    default:
    case 32:
        return  LLVMConstInt(LLVMInt32Type(), val, signext);
    case 64:
        return LLVMConstInt(LLVMInt64Type(), val, signext);
    case 128:
        return LLVMConstInt(LLVMInt128Type(), val, signext);
    }
    return NULL;
}

LLVMValueRef gen_llvm_real_const_ref(int bits, double val)
{
    switch (bits) {
    case 32:
        return  LLVMConstReal(LLVMFloatType(), val);
    default:
    case 64:
        return LLVMConstReal(LLVMDoubleType(), val);
    case 128:
        return LLVMConstReal(LLVMFP128Type(), val);
    }
    return NULL;
}

LLVMValueRef sic_cast_llvm(struct gen_context *ctx, struct variable *var, const struct type *type)
{
    switch (type->type) {
    case V_FLOAT:
        return LLVMBuildFPCast(ctx->build_ref, var->val, sic_type_to_llvm_type(type), llvm_gen_name());
    default:
        ERR("Invalid cast");
    }
}

void gen_scan_builtin(struct gen_context *ctx, struct node *node)
{
    if (!node)
        return;

    if (node->node == A_TYPESPEC && node->type == V_BUILTIN) {
        if (strcmp(node->value_string, "__builtin_va_list") == 0) {
            const struct type *res = __find_type_by(ctx, V_STRUCT, 0, TYPE_UNSIGNED, 0, node->value_string);
            if (!res)
                gen_builtin_va_list(ctx, node);
        }
    } else if (node->node == A_IDENTIFIER && strcmp(node->value_string, "__builtin_va_start") == 0) {
        struct variable *func_var = find_variable_by_name(ctx, node->value_string);
        if (!func_var)
            gen_builtin_va_start(ctx, node);
    } else if (node->node == A_IDENTIFIER && strcmp(node->value_string, "__builtin_va_end") == 0) {
        struct variable *func_var = find_variable_by_name(ctx, node->value_string);
        if (!func_var)
            gen_builtin_va_end(ctx, node);
    } else if (node->node == A_IDENTIFIER && strcmp(node->value_string, "__builtin_va_arg") == 0) {
        struct variable *func_var = find_variable_by_name(ctx, node->value_string);
        if (!func_var)
            gen_builtin_va_arg(ctx, node);
    } else if (node->node == A_IDENTIFIER && strcmp(node->value_string, "__builtin_bswap16") == 0) {
        struct variable *func_var = find_variable_by_name(ctx, node->value_string);
        if (!func_var)
            gen_builtin_bswap(ctx, node, 16);
    } else if (node->node == A_IDENTIFIER && strcmp(node->value_string, "__builtin_bswap32") == 0) {
        struct variable *func_var = find_variable_by_name(ctx, node->value_string);
        if (!func_var)
            gen_builtin_bswap(ctx, node, 32);
    } else if (node->node == A_IDENTIFIER && strcmp(node->value_string, "__builtin_bswap64") == 0) {
        struct variable *func_var = find_variable_by_name(ctx, node->value_string);
        if (!func_var)
            gen_builtin_bswap(ctx, node, 64);
    }

    gen_scan_builtin(ctx, node->left);
    gen_scan_builtin(ctx, node->right);
}

int gen_llvm_assign(struct gen_context *ctx, struct node *node)
{
    int a, b = 0;

    a = gen_recurse(ctx, node->left);
    b = gen_recurse(ctx, node->right);

    struct variable *vara = find_variable(ctx, a);
    struct variable *varb = find_variable(ctx, b);

    LLVMValueRef src = varb->val;

    if (vara->type->type != varb->type->type)
        src = sic_cast_llvm(ctx, varb, vara->type);

    LLVMBuildStore(ctx->build_ref, src, vara->val);
    return vara->reg;
}

int gen_llvm_declaration(struct gen_context *ctx, struct node *node)
{
    /*
     * In simple form type is on left, and right has name.
     * More complex form right hand has ASSIGN
     */
    int a, b = 0;
    int is_assign = 0;

    a = gen_recurse(ctx, node->left);
    if (node->right && node->right->node != A_ASSIGN) {
        b = gen_recurse(ctx, node->right);
    } else if (node->right && node->right->node == A_ASSIGN &&
            node->right->left) {
        /* Name is on node->right->left */
        b = gen_recurse(ctx, node->right->left);
        is_assign = 1;
    }
    if (!a || ! b)
        return 0;

    const struct type *type = find_type_by_id(ctx, REF_CTX(a));
    struct variable *var = find_variable(ctx, b);
    struct variable *res = NULL;
    if (type && var) {
        LLVMTypeRef llt = sic_type_to_llvm_type(type);

        res = new_variable(ctx, var->name, type->type, type->bits, type->sign, type->ptr + 1, 0, 0);

        res->val = LLVMBuildAlloca(ctx->build_ref, llt, var->name);
        if (!is_assign) {
            LLVMValueRef zeroval = llvm_zero_from_sic_type(type);
            if (zeroval)
                LLVMBuildStore(ctx->build_ref, zeroval, res->val);
            else
                ERR("Unsupported zero for type: %s", stype_str(type));
        }
    } else
        ERR("Unsupported declaration");

    if (is_assign) {
        /* Recurse separately for the assign after declaration */
        gen_recurse(ctx, node->right);
    }

    return res ? res->reg : 0;
}

LLVMValueRef gen_llvm_cast_to(struct gen_context *ctx, struct variable *var, const struct type *t)
{
    LLVMValueRef res = var->val;

    if (t->type != var->type->type) {
        if (t->type == V_FLOAT && var->type->type == V_INT) {
            if (var->type->sign)
                res = LLVMBuildSIToFP(ctx->build_ref, var->val,
                    sic_type_to_llvm_type(t), llvm_gen_name());
            else
                res = LLVMBuildSIToFP(ctx->build_ref, var->val,
                    sic_type_to_llvm_type(t), llvm_gen_name());
        } else if (t->type == V_INT && var->type->type == V_FLOAT) {
            if (t->sign)
                res = LLVMBuildFPToSI(ctx->build_ref, var->val,
                    sic_type_to_llvm_type(t), llvm_gen_name());
            else
                res = LLVMBuildFPToUI(ctx->build_ref, var->val,
                    sic_type_to_llvm_type(t), llvm_gen_name());
        } else if (var->type->type == V_NULL && t->ptr) {
            /* Null can be casted to anything as long as target is ptr */
            res = LLVMConstNull(sic_type_to_llvm_type(t));
        } else
            ERR("Unknown cast: %s to %s", stype_str(var->type), stype_str(t));
    } else if (t->type == var->type->type && t->bits > var->type->bits) {
        res = LLVMBuildBitCast(ctx->build_ref,
                var->val, sic_type_to_llvm_type(t), llvm_gen_name());
    }
    return res;
}

LLVMValueRef sic_cast_load_pointer(struct gen_context *ctx, struct variable *var, const struct type *type)
{
        LLVMValueRef vref = gen_llvm_cast_to(ctx, var, type);
        LLVMValueRef vr_ref = vref;
        if (var->type->ptr)
            vr_ref = LLVMBuildLoad2(ctx->build_ref,
                sic_type_to_llvm_type(type),
                vref, llvm_gen_name());
        return vr_ref;
}

int gen_llvm_eq(struct gen_context *ctx, struct node *node)
{
    int a, b;

    a = gen_recurse(ctx, node->left);
    b = gen_recurse(ctx, node->right);

    struct variable *vara = find_variable(ctx, a);
    struct variable *varb = find_variable(ctx, b);

    if (!vara || !varb)
        ERR("Invalid eq, can't solve items");

    if (vara->type->type != varb->type->type && vara->type->type != V_NULL && varb->type->type != V_NULL)
        ERR("Not same type");

    const struct type *restype = sic_solve_type(ctx, vara->type, varb->type);
    if (!restype)
        ERR("Can't solve type");

    struct variable *res = new_inst_variable(ctx, V_INT, 1, 0);
    if (restype->type == V_INT) {
        LLVMValueRef va = sic_cast_load_pointer(ctx, vara, restype);
        LLVMValueRef vb = sic_cast_load_pointer(ctx, varb, restype);

        res->val = LLVMBuildICmp(ctx->build_ref,
            node->node == A_EQ_OP ? LLVMIntEQ : LLVMIntNE,
            va, vb, llvm_gen_name());
    } else if (restype->type == V_FLOAT) {
        LLVMValueRef va = sic_cast_load_pointer(ctx, vara, restype);
        LLVMValueRef vb = sic_cast_load_pointer(ctx, varb, restype);

        res->val = LLVMBuildFCmp(ctx->build_ref,
            node->node == A_EQ_OP ? LLVMRealOEQ : LLVMRealUNE,
            va, vb, llvm_gen_name());
    } else
        ERR("Invalid compare");

    return res->reg;
}

int gen_llvm_op(struct gen_context *ctx, struct node *node, int op)
{
    int a, b;

    a = gen_recurse(ctx, node->left);
    b = gen_recurse(ctx, node->right);

    struct variable *vara = find_variable(ctx, a);
    struct variable *varb = find_variable(ctx, b);
    struct variable *res = NULL;

    if (!vara || !varb)
        ERR("Invalid addition, can't solve items");

    const struct type *restype = sic_solve_type(ctx, vara->type, varb->type);
    if (!restype)
        ERR("Can't solve type");

    res = new_variable_from_type(ctx, NULL, restype, 0, 0, 0);
    LLVMValueRef va = sic_cast_load_pointer(ctx, vara, restype);
    LLVMValueRef vb = sic_cast_load_pointer(ctx, varb, restype);
    if (!va || !vb)
        ERR("Cast failed");

    switch (restype->type) {
    case V_INT:
        switch (op) {
        case A_ADD:
            res->val = LLVMBuildNSWAdd(ctx->build_ref, va, vb,
                llvm_gen_name());
            break;
        case A_MINUS:
            res->val = LLVMBuildNSWSub(ctx->build_ref, va, vb,
                llvm_gen_name());
            break;
        case A_MUL:
            res->val = LLVMBuildNSWMul(ctx->build_ref, va, vb,
                llvm_gen_name());
            break;
        case A_DIV:
            if (restype->sign)
                res->val = LLVMBuildSDiv(ctx->build_ref, va, vb,
                    llvm_gen_name());
            else
                res->val = LLVMBuildUDiv(ctx->build_ref, va, vb,
                    llvm_gen_name());
            break;
        case A_MOD:
            if (restype->sign)
                res->val = LLVMBuildSRem(ctx->build_ref, va, vb,
                    llvm_gen_name());
            else
                res->val = LLVMBuildURem(ctx->build_ref, va, vb,
                    llvm_gen_name());
            break;
        case A_OR:
            res->val = LLVMBuildOr(ctx->build_ref, va, vb,
                llvm_gen_name());
            break;
        case A_XOR:
            res->val = LLVMBuildXor(ctx->build_ref, va, vb,
                llvm_gen_name());
            break;
        case A_AND:
            res->val = LLVMBuildAnd(ctx->build_ref, va, vb,
                llvm_gen_name());
            break;
        default:
            ERR("Invalid integer arithmetic operation: %s", node_str(node));
        }
        break;
    case V_FLOAT:
        switch (op) {
        case A_ADD:
            res->val = LLVMBuildFAdd(ctx->build_ref, va, vb,
                llvm_gen_name());
            break;
        case A_MINUS:
            res->val = LLVMBuildFSub(ctx->build_ref, va, vb,
                llvm_gen_name());
            break;
        case A_MUL:
            res->val = LLVMBuildFMul(ctx->build_ref, va, vb,
                llvm_gen_name());
            break;
        case A_DIV:
            res->val = LLVMBuildFDiv(ctx->build_ref, va, vb,
                llvm_gen_name());
            break;
        case A_MOD:
            res->val = LLVMBuildFRem(ctx->build_ref, va, vb,
                llvm_gen_name());
            break;
        case A_OR:
        case A_XOR:
        case A_AND:
            ERR("Invalid %s, bitwise operations supported only for integer types", node_str(node));
            break;
        default:
            ERR("Invalid floating arithmetic operation: %s", node_str(node));
        }
        break;
    default:
        ERR("Addition not supported for %s", stype_str(restype));
    }
    return res->reg;
}

int gen_llvm_negate(struct gen_context *ctx, struct node *node)
{
    struct variable *res = NULL;
    int a;

    a = gen_recurse(ctx, node->left);
    struct variable *vara = find_variable(ctx, a);
    LLVMValueRef va = sic_cast_load_pointer(ctx, vara, vara->type);

    LLVMValueRef zero;

    res = new_variable_from_type(ctx, NULL, vara->type, 0, 0, 0);
    switch (vara->type->type) {
    case V_INT:
        zero = gen_llvm_int_const_ref(vara->type->bits, 0, 0);
        res->val = LLVMBuildNSWSub(ctx->build_ref, zero, va,
                llvm_gen_name());
        break;
    case V_FLOAT:
        zero = gen_llvm_real_const_ref(vara->type->bits, 0.0);
        res->val = LLVMBuildFSub(ctx->build_ref, zero, va,
                llvm_gen_name());
        break;
    default:
        ERR("Invalid negate");
    }

    return res->reg;
}

int gen_llvm_pre_post_op(struct gen_context *ctx, struct node *node)
{
    struct variable *res = NULL;
    struct variable *res2 = NULL;
    int a;

    a = gen_recurse(ctx, node->left);
    struct variable *vara = find_variable(ctx, a);
    if (!vara)
        ERR("Invalid pre/post inc/dec");

    res = new_inst_variable(ctx, vara->type->type, vara->type->bits, vara->type->sign);
    res2 = new_inst_variable(ctx, vara->type->type, vara->type->bits, vara->type->sign);
    LLVMValueRef va = sic_cast_load_pointer(ctx, vara, vara->type);
    LLVMValueRef one;
    res2->val = va;

    if (vara->type->type == V_INT)
        one = gen_llvm_int_const_ref(vara->type->bits, 1, 0);
    else if (vara->type->type == V_FLOAT)
        one = gen_llvm_real_const_ref(vara->type->bits, 1.0);
    else
        ERR("INC/DEC not supported: %s", stype_str(vara->type));

    switch (node->node) {
    case A_PREINC:
    case A_POSTINC:
        if (vara->type->type == V_INT) {
            res->val = LLVMBuildNSWAdd(ctx->build_ref, va, one,
                    llvm_gen_name());
        } else if (vara->type->type == V_FLOAT) {
            res->val = LLVMBuildFAdd(ctx->build_ref, va, one,
                    llvm_gen_name());
        }
        LLVMBuildStore(ctx->build_ref, res->val, vara->val);
        break;
    case A_PREDEC:
    case A_POSTDEC:
        if (vara->type->type == V_INT) {
            res->val = LLVMBuildNSWSub(ctx->build_ref, va, one,
                    llvm_gen_name());
        } else if (vara->type->type == V_FLOAT) {
            res->val = LLVMBuildFSub(ctx->build_ref, va, one,
                    llvm_gen_name());
        }
        LLVMBuildStore(ctx->build_ref, res->val, vara->val);
        break;
    default:
        ERR("Invaliad inc/dec op");
    }

    return (node->node == A_POSTINC || node->node == A_POSTDEC) ? res2->reg : res->reg;
}

int gen_llvm_op_assign(struct gen_context *ctx, struct node *node)
{
    struct variable *res;
    int a, b;

    a = gen_recurse(ctx, node->left);
    b = gen_recurse(ctx, node->right);

    struct variable *vara = find_variable(ctx, a);
    struct variable *varb = find_variable(ctx, b);

    const struct type *restype = sic_solve_type(ctx, vara->type, varb->type);
    if (!restype)
        ERR("Can't solve type: %s %s", stype_str(vara->type), stype_str(varb->type));

    LLVMValueRef va = sic_cast_load_pointer(ctx, vara, restype);
    LLVMValueRef vb = sic_cast_load_pointer(ctx, varb, restype);

    if (!(restype->type == V_INT || restype->type == V_FLOAT))
        ERR("Invalid op assign type");

    res = new_variable_from_type(ctx, NULL, restype, 0, 0, 0);
    switch (node->node) {
    case A_ADD_ASSIGN:
        if (restype->type == V_INT)
            res->val = LLVMBuildNSWAdd(ctx->build_ref, va, vb,
                    llvm_gen_name());
        else
            res->val = LLVMBuildFAdd(ctx->build_ref, va, vb,
                    llvm_gen_name());
        break;
    case A_SUB_ASSIGN:
        if (restype->type == V_INT)
            res->val = LLVMBuildNSWSub(ctx->build_ref, va, vb,
                    llvm_gen_name());
        else
            res->val = LLVMBuildFSub(ctx->build_ref, va, vb,
                    llvm_gen_name());
        break;
    case A_MUL_ASSIGN:
        if (restype->type == V_INT)
            res->val = LLVMBuildNSWMul(ctx->build_ref, va, vb,
                    llvm_gen_name());
        else
            res->val = LLVMBuildFMul(ctx->build_ref, va, vb,
                    llvm_gen_name());
        break;
    case A_DIV_ASSIGN:
        if (restype->type == V_FLOAT)
            res->val = LLVMBuildFDiv(ctx->build_ref, va, vb,
                    llvm_gen_name());
        else if (restype->sign)
            res->val = LLVMBuildSDiv(ctx->build_ref, va, vb,
                    llvm_gen_name());
        else
            res->val = LLVMBuildUDiv(ctx->build_ref, va, vb,
                    llvm_gen_name());
        break;
    case A_MOD_ASSIGN:
        if (restype->type == V_FLOAT)
            res->val = LLVMBuildFRem(ctx->build_ref, va, vb,
                    llvm_gen_name());
        else if (restype->sign)
            res->val = LLVMBuildSRem(ctx->build_ref, va, vb,
                    llvm_gen_name());
        else
            res->val = LLVMBuildURem(ctx->build_ref, va, vb,
                    llvm_gen_name());
        break;
    case A_OR_ASSIGN:
        if (restype->type != V_INT)
            ERR("Invalid OR, bitwise operations supported only for integer types");
        res->val = LLVMBuildOr(ctx->build_ref, va, vb,
                llvm_gen_name());
        break;
    case A_XOR_ASSIGN:
        if (restype->type != V_INT)
            ERR("Invalid XOR, bitwise operations supported only for integer types");
        res->val = LLVMBuildXor(ctx->build_ref, va, vb,
                llvm_gen_name());
        break;
    case A_AND_ASSIGN:
        if (restype->type != V_INT)
            ERR("Invalid XOR, bitwise operations supported only for integer types");
        res->val = LLVMBuildAnd(ctx->build_ref, va, vb,
                llvm_gen_name());
        break;
    default:
        ERR("Invalid op assign: %s", node_str(node));
    }
    LLVMBuildStore(ctx->build_ref, res->val, vara->val);

    return res->reg;
}

int gen_llvm_if(struct gen_context *ctx, struct node *node)
{
    /*
     * On left hand we have the condition, and true block in mid,
     * and else on right.
     */
    int a, b;
    a = gen_recurse(ctx, node->left);

    LLVMBasicBlockRef true_block = LLVMAppendBasicBlockInContext(ctx->context_ref, ctx->func_ref, llvm_gen_name());
    LLVMBasicBlockRef false_block = LLVMAppendBasicBlockInContext(ctx->context_ref, ctx->func_ref, llvm_gen_name());
    LLVMBasicBlockRef out_block = NULL;
#if 1
    if (!node->right)
        out_block = false_block;
    else
        out_block = LLVMAppendBasicBlockInContext(ctx->context_ref, ctx->func_ref, llvm_gen_name());
#endif

    struct variable *cond_var = find_variable(ctx, a);
    if (!cond_var || !cond_var->val)
        ERR("Missing conditional variable");

    LLVMValueRef zeroval = llvm_zero_from_sic_type(cond_var->type);
    if (!zeroval)
        ERR("Invalid if zero")

    /* Condition */
    LLVMValueRef cond_val_ref = sic_cast_load_pointer(ctx, cond_var, cond_var->type);
    LLVMValueRef cond;
    if (cond_var->type->type == V_INT)
        cond = LLVMBuildICmp(ctx->build_ref, LLVMIntNE,
            cond_val_ref, zeroval, llvm_gen_name());
    else if (cond_var->type->type == V_FLOAT)
        cond = LLVMBuildFCmp(ctx->build_ref, LLVMRealUNE,
            cond_val_ref, zeroval, llvm_gen_name());
    else
        ERR("Invalid compare");
    LLVMBuildCondBr(ctx->build_ref, cond, true_block, false_block);

    /* True */
    LLVMPositionBuilderAtEnd(ctx->build_ref, true_block);
    int rets = ctx->rets;
    b = gen_recurse(ctx, node->mid);
    (void)b;
    if (rets == ctx->rets)
        LLVMBuildBr(ctx->build_ref, out_block);

    /* Else */
    if (node->right) {
        LLVMPositionBuilderAtEnd(ctx->build_ref, false_block);
        rets = ctx->rets;
        b = gen_recurse(ctx, node->right);
        if (rets == ctx->rets)
            LLVMBuildBr(ctx->build_ref, out_block);
    }

    /* Out */
    LLVMPositionBuilderAtEnd(ctx->build_ref, out_block);
    LLVMBasicBlockRef last_block = LLVMGetLastBasicBlock(ctx->func_ref);
    if (last_block != out_block) {
        LLVMBuildBr(ctx->build_ref, last_block);
        LLVMPositionBuilderAtEnd(ctx->build_ref, last_block);
    }

    return 0;
}

int gen_llvm_return(struct gen_context *ctx, struct node *node)
{
    int a = gen_recurse(ctx, node->left);
    struct variable *var = find_variable(ctx, a);

    if (!var)
        ERR("Failed return");
    if (!var->val)
        ERR("No val in ret");

    LLVMBuildRet(ctx->build_ref, var->val);
    ctx->rets++;
    ctx->last_is_ret = 1;
    return 0;
}

int gen_llvm_int_const(struct gen_context *ctx, struct node *n)
{
    int signext;

    struct variable *var = new_variable(ctx, NULL, V_INT, n->bits, n->value < 0 ? TYPE_SIGNED : TYPE_UNSIGNED, 0, 0, ctx->global);
    signext = n->value < 0 ? 1 : 0;

    var->val = gen_llvm_int_const_ref(n->bits, n->value, signext);

    return var->reg;
}

int gen_llvm_null(struct gen_context *ctx, struct node *n)
{
    struct variable *null_var = new_variable(ctx, "NULL", V_NULL, 0, TYPE_UNSIGNED, 0, 0, 1);
    // FIXME
    null_var->val = LLVMConstNull(LLVMInt32Type());

    return null_var->reg;
}

int gen_llvm_real_const(struct gen_context *ctx, struct node *n)
{
    struct variable *var = new_variable(ctx, NULL, V_FLOAT, n->bits, 1, 0, 0, ctx->global);
    double val = n->value + n->fraction;

    switch (n->bits) {
    case 32:
        var->val = LLVMConstReal(LLVMFloatType(), val);
        break;
    default:
    case 64:
        var->val = LLVMConstReal(LLVMDoubleType(), val);
        break;
    case 128:
        var->val = LLVMConstReal(LLVMFP128Type(), val);
        break;
    }

    return var->reg;
}

// First pass to scan types and alloc
int gen_recursive_allocs(struct gen_context *ctx, struct node *node)
{
    if (node == NULL)
        return 0;

    if (node->node == A_FUNCTION)
        return 0;
    if (node->node == A_LABEL)
        return 0;
    if (node->node == A_GOTO)
        return 0;

    FATALN(node->node == A_TYPESPEC, node, "Got type spec, this is compiler errorand should not happen");

    int res = 0;
    switch (node->node) {
        case A_TYPE:
            res = gen_type(ctx, node);
            if (node->type == V_ENUM) {
                return res;
            }
            break;
        case A_TYPE_LIST:
            return gen_type_list(ctx, node);
        case A_POINTER:
            res = gen_pointer(ctx, node);
            break;
        case A_INDEX:
            res = gen_index(ctx, node);
            break;
        case A_INDEXDEF:
            res = gen_indexdef(ctx, node);
            break;
        case A_ARRAYDEF:
            break;
        case A_IDENTIFIER:
            res = gen_identifier(ctx, node);
            break;
        case A_ARRAY_INITIALIZER:
            break;
        case A_INT_LIT:
            res = gen_prepare_store_int(ctx, node);
            break;
        case A_DEC_LIT:
            res = gen_prepare_store_double(ctx, node);
            break;
        case A_STR_LIT:
            res = gen_prepare_store_str(ctx, node);
            break;
        case A_DECLARATION:
            ctx->decl_name = NULL;
            ctx->is_decl += 100;
            break;
        case A_ASSIGN:
            /* If It's declaration, and assign increase is_decl since we're declaring a variable. */
            if (ctx->is_decl)
                ctx->is_decl++;
        default:
            break;
    }

    int left = 0;
    int right = 0;

    if (node->node != A_INDEX && node->node != A_INDEXDEF && node->node != A_FUNC_CALL && node->left)
        left = gen_recursive_allocs(ctx, node->left);
    /* After handling left side of assign we need to stop checking for variables since right side can't be declaration */
    if (node->node == A_ASSIGN)
            ctx->is_decl--;
    if (node->node != A_INDEXDEF && node->mid)
        gen_recursive_allocs(ctx, node->mid);
    if (node->node != A_INDEXDEF && node->node != A_ACCESS && node->right)
        right = gen_recursive_allocs(ctx, node->right);
    if (node->node == A_DECLARATION) {
        ctx->is_decl = 0;
        ctx->decl_name = NULL;
    }
        //ctx->is_decl -= 100;
    if (node->node == A_ASSIGN && left > 0 && right > 0) {
        /* Need to handle assign values */
        struct variable *v1 = find_variable(ctx, left);
        struct variable *v2 = find_variable(ctx, right);
        FATALN(!v1, node, "Invalid assign lvalue");
        FATALN(!v2, node, "Invalid assign rvalue");
        v1->value = v2->value;
    }

    return res;
}

int gen_recursive(struct gen_context *ctx, struct node *node)
{
    int resleft = 0, resright = 0, resmid = 0;
    if (node == NULL)
        return 0;

    if (ctx && ctx->debug)
        printf("DEBUG: gen_recursive(), node %s\n", node_str(node));

    /* Special cases */
    if (node->node == A_ARRAY_INITIALIZER)
        return 0;
    if (node->node == A_FUNCTION)
        return gen_function(ctx, node);
    if (node->node == A_FUNC_CALL)
        return gen_func_call(ctx, node);
    if (node->node == A_IF)
        return gen_if(ctx, node, 0);
    if (node->node == A_TERNARY)
        return gen_if(ctx, node, 1);
    if (node->node == A_LOG_AND)
        return gen_logical_and(ctx, node);
    if (node->node == A_LOG_OR)
        return gen_logical_or(ctx, node);
    if (node->node == A_WHILE)
        return gen_while(ctx, node, LOOP_WHILE);
    if (node->node == A_DO)
        return gen_while(ctx, node, LOOP_DO);
    if (node->node == A_FOR)
        return gen_while(ctx, node, LOOP_FOR);
    if (node->node == A_LABEL)
        return gen_label(ctx, node);
    if (node->node == A_GOTO)
        return gen_goto(ctx, node);
    if (node->node == A_TYPE_LIST)
        return get_type_list(ctx, node);

    /* Recurse first to get children solved */
    if (node->node == A_TYPE && node->type == V_ENUM) {
        // Skip enums, since it could cause invalid interpretions
    } else {
        if (node->left)
            resleft = gen_recursive(ctx, node->left);
        if (node->node != A_ACCESS && node->node != A_INDEXDEF && node->right)
            resright = gen_recursive(ctx, node->right);
        else
            resright = 0;
    }

    if (ctx && ctx->debug)
        printf("DEBUG: gen_recursive(), node %s, left %d, right %d\n", node_str(node), resleft, resright);

    /* Then generate this node */
    switch (node->node) {
        case A_INDEX:
            ctx->last_label = 0;
            return get_index(ctx, node, resleft, resright);
        case A_INDEXDEF:
            ctx->last_label = 0;
            return get_indexdef(ctx, node, resleft);
        case A_ACCESS:
            ctx->last_label = 0;
            return gen_access(ctx, node, resleft, resright);
        case A_ADD:
            ctx->last_label = 0;
            return gen_add(ctx, node, resleft, resright);
        case A_MINUS:
            ctx->last_label = 0;
            return gen_sub(ctx, node, resleft, resright);
        case A_NEGATE:
            ctx->last_label = 0;
            return gen_negate(ctx, node, resleft);
        case A_TILDE:
            ctx->last_label = 0;
            return gen_tilde(ctx, node, resleft);
        case A_NOT:
            ctx->last_label = 0;
            return gen_not(ctx, node, resleft);
        case A_MUL:
            ctx->last_label = 0;
            return gen_mul(ctx, node, resleft, resright);
        case A_DIV:
            ctx->last_label = 0;
            return gen_div(ctx, node, resleft, resright);
        case A_MOD:
            ctx->last_label = 0;
            return gen_mod(ctx, node, resleft, resright);
        case A_RIGHT:
        case A_LEFT:
            ctx->last_label = 0;
            return gen_shift(ctx, node, node->node, resleft, resright);
        case A_OR:
        case A_XOR:
        case A_AND:
            ctx->last_label = 0;
            return gen_bitwise(ctx, node, node->node, resleft, resright);
        case A_LOG_OR:
        case A_LOG_AND:
            ERR("Should not get here");
        case A_EQ_OP:
        case A_NE_OP:
            ctx->last_label = 0;
            return gen_eq(ctx, node, resleft, resright);
        case A_LT:
        case A_GT:
        case A_LT_EQ:
        case A_GT_EQ:
            ctx->last_label = 0;
            return gen_lt_gt(ctx, node, resleft, resright);
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
        case A_CAST:
            return gen_cast_to(ctx, node, resleft, resright);
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
            if (node->mid)
                resmid = gen_recursive(ctx, node->mid);
            return gen_assign(ctx, node, resleft, resmid, resright);
        case A_DEREFERENCE:
            ctx->last_label = 0;
            return gen_dereference(ctx, node, resleft);
        case A_SIZEOF:
            ctx->last_label = 0;
            return gen_sizeof(ctx, node, resleft);
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
            ctx->last_label = 0;
            return gen_op_assign(ctx, node, resleft, resright);
        case A_DECLARATION:
            return gen_declaration(ctx, node, resleft, resright);
        case A_NULL:
            ctx->last_label = 0;
            return gen_null(ctx, node);
        case A_PREINC:
        case A_PREDEC:
        case A_POSTINC:
        case A_POSTDEC:
            return gen_pre_post_op(ctx, node, resleft);
        case A_BREAK:
            return gen_break(ctx, node, resleft);
        case A_CONTINUE:
            return gen_continue(ctx, node, resleft);
        default:
            ERR("Unknown node in code gen: %s", node_str(node));
    }
    return 0;
}

#define return_one(a, b) \
    if (a) return a;\
    if (b) return b;

int gen_recurse(struct gen_context *ctx, struct node *node)
{
    int resleft;
    int resright;
    int res = 0;

    if (node == NULL)
        return 0;

#if 0
    if (node->left)
        resleft = gen_recurse(ctx, node->left);
    if (node->node != A_ACCESS && node->node != A_INDEXDEF && node->right)
        resright = gen_recurse(ctx, node->right);
    else
        resright = 0;
#endif
    (void)resright;

    ctx->last_is_ret = 0;
    switch (node->node) {
    case A_FUNCTION:
        return 0;
    case A_INT_LIT:
        return gen_llvm_int_const(ctx, node);
    case A_DEC_LIT:
        return gen_llvm_real_const(ctx, node);
    case A_NULL:
        return gen_llvm_null(ctx, node);
    case A_TYPE_LIST:
        return get_type_list(ctx, node);
    case A_ASSIGN:
        gen_llvm_assign(ctx, node);
        break;
    case A_DECLARATION:
        gen_llvm_declaration(ctx, node);
        break;
    case A_IDENTIFIER:
        res = gen_identifier(ctx, node);
        break;
    case A_LIST:
    case A_GLUE:
        resleft = gen_recurse(ctx, node->left);
        resright = gen_recurse(ctx, node->right);
        return_one(resright, resleft);
        break;
    case A_IF:
        res = gen_llvm_if(ctx, node);
        break;
    case A_RETURN:
        res = gen_llvm_return(ctx, node);
        break;
    case A_EQ_OP:
    case A_NE_OP:
        res = gen_llvm_eq(ctx, node);
        break;
    case A_ADD:
    case A_MINUS:
    case A_MUL:
    case A_DIV:
    case A_MOD:
    case A_OR:
    case A_XOR:
    case A_AND:
        res = gen_llvm_op(ctx, node, node->node);
        break;
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
        return gen_llvm_op_assign(ctx, node);
    case A_PREINC:
    case A_PREDEC:
    case A_POSTINC:
    case A_POSTDEC:
        return gen_llvm_pre_post_op(ctx, node);
    case A_NEGATE:
        return gen_llvm_negate(ctx, node);
    default:
        ERR("Unknown node in code gen: %s", node_str(node));
        break;
    }

    return res;
}

struct gen_context *fake_main(struct gen_context *ctx, struct node *node, int res)
{
    struct gen_context *main_ctx = init_ctx(ctx->f, ctx);
    struct node main_node;

    main_ctx->name = "main";
    main_ctx->gen_flags = ctx->gen_flags;
    main_node.type = V_INT;
    main_node.bits = 32;
    const struct type *main_type = find_type_by(main_ctx, V_INT, 32, TYPE_SIGNED, 0);

    gen_pre(main_ctx, &main_node, NULL, main_type);
    if (node && node->type != V_VOID) {
        char *tmp;
        struct variable *var = find_variable(ctx, res);
        FATALN(!var, node, "Invalid return variable (fake): %d", res);
        if (!var->direct) {
            var = gen_load(ctx, var);
            FATALN(!var, node, "Invalid indirect return variable: %d", res);
            res = var->reg;
        }
        struct variable *ret = new_inst_variable(main_ctx, var->type->type, var->type->bits, var->type->sign);

        const char *type = var_str(main_type->type, main_type->bits, &tmp);
        buffer_write(main_ctx->data, "%%%d = call %s @%s()\n", ret->reg, type, ctx->name);
        buffer_write(main_ctx->data, "ret i32 %%%d ; faked\n", ret->reg);
        if (tmp)
            free(tmp);
    } else {
        buffer_write(main_ctx->data, "call void @%s()\n", ctx->name);
        buffer_write(main_ctx->data, "ret i32 0 \n");
    }
    buffer_write(main_ctx->post, "}\n");

    main_ctx->next = ctx->child;
    ctx->child = main_ctx;
    return main_ctx;
}

const struct type *resolve_return_type(struct gen_context *ctx, struct node *node, int reg)
{
    const struct type *res = NULL;
    if (ctx->main_type) {
        res = __find_type_by(ctx, ctx->main_type->type, ctx->main_type->bits, ctx->main_type->sign, ctx->main_type->ptr, ctx->main_type->type_name);
    } else if (node && node->type != V_VOID) {
        res = __find_type_by(ctx, node->type, node->bits, node->sign, node->ptr, node->value_string);
    } else {
        res = __find_type_by(ctx, V_INT, 32, TYPE_SIGNED, 0, NULL);
    }
    return res;
}

int scan_gens(struct node *node)
{
    if (node == NULL)
        return 0;

    int res = 0;
    if (node->node == A_STR_LIT) {
        if (strcmp(node->value_string, "__FUNCTION__") == 0)
            res |= GEN_FUNCTION;
        else if (strcmp(node->value_string, "__PRETTY_FUNCTION__") == 0)
            res |= GEN_PRETTY_FUNCTION;
    }

    if (node->left)
        res |= scan_gens(node->left);
    if (node->mid)
        res |= scan_gens(node->mid);
    if (node->right)
        res |= scan_gens(node->right);

    return res;
}

void gen_opaque(struct gen_context *ctx)
{
    struct type *res = ctx->types;
    while (res) {
            // This is opaque struct/union
            if (res->forward && (res->type == V_STRUCT || res->type == V_UNION)) {
                buffer_write(ctx->init, "%%%s.%s = type opaque\n", res->type == V_UNION ? "union" : "struct", res->type_name);
            }
            res = res->next;
    }
    if (ctx->parent)
        gen_opaque(ctx->parent);
}

void free_ctx(struct gen_context *ctx)
{
    struct variable *var = ctx->variables;
    while (var) {
        struct variable *next = var->next;
        if (var->paramstr)
            free(var->paramstr);
        free(var);
        var = next;
    }

    var = ctx->globals;
    while (var) {
        struct variable *next = var->next;
        if (var->paramstr)
            free(var->paramstr);
        free(var);
        var = next;
    }

    struct type *typ = ctx->types;
    while (typ) {
        struct type *next = typ->next;
        if (typ->items)
            free(typ->items);
        free(typ);
        typ = next;
    }

    struct struct_name *str = ctx->structs;
    while (str) {
        struct struct_name *next = str->next;
        free(str);
        str = next;
    }
#if 0
    if (ctx->parent)
        free_ctx(ctx->parent);
#endif
    struct gen_context *child = ctx->child;
    while (child) {
        struct gen_context *next = child->next;
        free_ctx(child);
        child = next;
    }

    if (ctx->struct_names) {
        unsigned int i;
        for (i = 0; i < ctx->struct_names_cnt; i++) {
            free(ctx->struct_names[i]);
        }
        free(ctx->struct_names);
    }
    buffer_del(ctx->pre);
    buffer_del(ctx->init);
    buffer_del(ctx->data);
    buffer_del(ctx->post);
    free(ctx);
}

int codegen(FILE *outfile, struct node *node, const struct codegen_config *conf)
{
    int res = 0;
    int got_main = 0;
    char *error = NULL;


    FATAL(!node, "Didn't get a node, most probably parse error!");

    struct gen_context *ctx = init_ctx(outfile, NULL);

    ctx->mod_ref = LLVMModuleCreateWithName(conf->name_in);
    ctx->context_ref = LLVMContextCreate();
    ctx->build_ref = LLVMCreateBuilderInContext(ctx->context_ref);

    ctx->conf = conf;
    ctx->global = 1;
    ctx->node = node;

    ctx->gen_flags = scan_gens(node);

#if 0
    if (ctx->gen_flags & GEN_FUNCTION)
        // Generate __FUNCTION__
    if (ctx->gen_flags & GEN_PRETTY_FUNCTION)
        // Generate __PRETTY_FUNCTION__
#endif

    struct variable *main_var = gen_scan_functions(ctx, node);
    (void)main_var;
    (void)got_main;



    /* Gen bytecode */
    if (conf->dump)
        LLVMDumpModule(ctx->mod_ref);
#if 1
    LLVMVerifyModule(ctx->mod_ref, LLVMPrintMessageAction, &error);
    LLVMDisposeMessage(error);
    printf("\n");
#else
    (void)error;
#endif
    LLVMWriteBitcodeToFile(ctx->mod_ref, conf->name_out);

    return res;

#if 0
    FATAL(!node, "Didn't get a node, most probably parse error!");
    struct gen_context *ctx = init_ctx(outfile, NULL);
    int res;
    int got_main = 0;

    ctx->conf = conf;
    ctx->global = 1;
    ctx->node = node;

    ctx->gen_flags = scan_gens(node);

    if (ctx->gen_flags & GEN_FUNCTION)
        gen_var_function(ctx, global_ctx_name);
    if (ctx->gen_flags & GEN_PRETTY_FUNCTION)
        gen_var_pretty_function(ctx, global_ctx_name, "void", NULL);

    gen_scan_builtin(ctx, node);
    gen_scan_struct_typedef(ctx, node);
    gen_opaque(ctx);
    struct variable *main_var = gen_scan_functions(ctx, node);
    if (main_var)
        ctx->main_type = main_var->type->retval;
    else
        ctx->main_type = find_type_by(ctx, V_INT, 32, TYPE_SIGNED, 0);
    gen_func_declarations(ctx);

    gen_pre(ctx, node, node, ctx->main_type);
    res = gen_recursive_allocs(ctx, node);
    res = gen_recursive(ctx, node);

    const struct type *target = custom_type_get(ctx, resolve_return_type(ctx, node, res));
    char *stype = stype_str(target);
    buffer_write(ctx->post, "; F2 %s, %d\n", stype, target->type);
    free(stype);

    gen_post(ctx, node, res, target, ctx->main_type);

    output_res(ctx, &got_main);
    if (!conf->no_link && !got_main) {
        struct gen_context *main_ctx = fake_main(ctx, node, res);
        output_ctx(main_ctx);
    }

    free_ctx(ctx);
    return res;
#endif
}
