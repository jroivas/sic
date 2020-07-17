#include "parse.h"
#include <string.h>

#define PARSE_SIGNED   0
#define PARSE_UNSIGNED 1

struct node *additive_expression(struct scanfile *f, struct token *token);
struct node *compound_statement(struct scanfile *f, struct token *token);
struct node *statement(struct scanfile *f, struct token *token);
struct node *unary_expression(struct scanfile *f, struct token *token);
struct node *constant_expression(struct scanfile *f, struct token *token);
struct node *expression(struct scanfile *f, struct token *token);
struct node *abstract_declarator(struct scanfile *f, struct token *token);
struct node *declarator(struct scanfile *f, struct token *token);
struct node *type_name(struct scanfile *f, struct token *token);


static const char *nodestr[] = {
    "+", "-", "*", "/", "%",
    "<<", ">>", "&", "|", "^",
    "&&", "||",
    "IDENTIFIER",
    "NEGATE",
    "NOT",
    "INT_LIT", "DEC_LIT",
    "STR_LIT",
    "ASSIGN",
    "+=",
    "-=",
    "*=",
    "/=",
    "%=",
    "<<=",
    ">>=",
    "&=",
    "|=",
    "^=",
    "GLUE",
    "TYPE", "TYPESPEC", "TYPE_QUAL",
    "TYPE_LIST",
    "DECLARATION",
    "PARAMS",
    "FUNCTION",
    "RETURN",
    "POINTER",
    "ADDR",
    "DEREFERENCE",
    "IF",
    "TERNARY",
    "==",
    "!=",
    "<",
    ">",
    "<=",
    ">=",
    "NULL",
    "FUNC_CALL",
    "POSTINC",
    "PREINC",
    "POSTDEC",
    "PREDEC",
    "~",
    "CAST",
    "WHILE",
    "DO",
    "FOR",
    "INDEX",
    "SIZEOF",
    "STRUCT",
    "UNION",
    "ENUM",
    "ACCESS",
    "LIST"
};

const char *node_type_str(enum nodetype t)
{
    FATAL(t >= sizeof(nodestr) / sizeof (char*),
            "Node string table overflow with %d", t);
    return nodestr[t];
}

const char *node_str(struct node *n)
{
    return node_type_str(n->node);
}

enum nodetype oper(enum tokentype t)
{
    switch (t) {
        case T_PLUS:
            return A_ADD;
        case T_MINUS:
            return A_MINUS;
        case T_STAR:
            return A_MUL;
        case T_SLASH:
            return A_DIV;
        case T_MOD:
            return A_MOD;
        default:
            ERR("Unexpected arithmetic: %s", token_val_str(t));
    }
}

enum var_type resolve_var_type(struct node *n)
{
    enum var_type v1 = V_VOID;
    enum var_type v2 = V_VOID;
    int b1 = 0;
    int b2 = 0;
    int s1 = 0;
    int s2 = 0;
    int ptr1 = 0;
    int ptr2 = 0;
    int addr1 = 0;
    int addr2 = 0;
    if (!n)
        return V_VOID;

    if (n->left) {
#if 1
        if (n->left->type == V_VOID)
            v1 = resolve_var_type(n->left);
        else
            v1 = n->left->type;
#else
        v1 = resolve_var_type(n->left);
#endif
        b1 = n->left->bits;
        s1 = n->left->sign;
        ptr1 = n->left->ptr;
        addr1 = n->left->addr;
    }
    if (n->right) {
#if 1
        if (n->right->type == V_VOID)
            v2 = resolve_var_type(n->right);
        else
            v2 = n->right->type;
#else
        v2 = resolve_var_type(n->right);
#endif
        b2 = n->right->bits;
        s2 = n->right->sign;
        ptr2 = n->right->ptr;
        addr2 = n->right->addr;
    }

    if (v1 == V_VOID && v2 != V_VOID)
        v1 = v2;
    if (v1 == V_INT && v2 == V_FLOAT)
        v1 = v2;
    if (v1 == V_VOID && n->type != V_VOID)
        v1 = n->type;
    if (v1 == V_INT && n->type == V_FLOAT)
        v1 = n->type;

    if (b1 < b2)
        b1 = b2;
    if (b1 < n->bits)
        b1 = n->bits;

    if (s1 < s2)
        s1 = s2;
    if (s1 < s2)
        s1 = n->sign;

    if (ptr1 < ptr2)
        ptr1 = ptr2;
    if (ptr1 < n->ptr)
        ptr1 = n->ptr;

    if (addr1 < addr2)
        addr1 = addr2;
    if (addr1 < n->addr)
        addr1 = n->addr;

    n->type = v1;
    n->bits = b1;
    //printf("SIGN: type %d, bits %d,  %d, %d -> %d @%s %s\n", v1, b1, s1, s2, n->sign, node_str(n), n->value_string);
    n->sign = s1;
    n->ptr = ptr1;
    n->addr = addr1;
    return v1;
}

struct node *make_node(struct token *t, enum nodetype node, struct node *left, struct node *mid, struct node *right)
{
    struct node *res = calloc(1, sizeof(struct node));
    if (res == NULL)
        ERR("Can't create new node, out of memory?");

    res->node = node;
    res->left = left;
    res->mid = mid;
    res->right = right;

    if (t) {
        res->filename = t->filename;
        res->line = t->line;
        res->linepos = t->linepos;
        res->token = t;
    }

    if (left != NULL || mid != NULL || right != NULL)
        res->type = resolve_var_type(res);
    else
        res->type = V_VOID;
#if DEBUG
    printf("MAKE: %d, %s\n", node, node_str(res));
    //printf("MAKE: %d, %s (val %lld) in %s:%d@%d\n", node, node_str(res), t->value, res->filename, res->line, res->linepos);
#endif

    return res;
}

struct node *make_leaf(struct token *t, enum nodetype node)
{
    struct node *n = make_node(t, node, NULL, NULL, NULL);

    if (t->token == T_INT_LIT) {
#if DEBUG
        printf("  INT: %llu\n", t->value);
#endif
        n->value = t->value;
        n->type = V_INT;
        // Width be determined later on
        n->bits = 0;
    } else if (t->token == T_DEC_LIT) {
#if DEBUG
        printf("  DEC: %llu.%llu\n", t->value, t->fraction);
#endif
        n->value = t->value;
        n->fraction = t->fraction;
        n->bits = 8;
        n->type = V_FLOAT;
    } else if (t->token == T_STR_LIT) {
        n->value_string = t->value_string;
        n->bits = 0;
        n->type = V_STR;
    } else if (t->token == T_NULL) {
        n->value = 0;
        n->type = V_NULL;
        // Width be determined later on
        n->bits = 0;
    } else
        ERR("Invalid leaf: %s", node_str(n));
    return n;
}

struct node *make_type(struct token *t, enum nodetype node, enum var_type type, int bits, int sign, const char *name)
{
    struct node *n = make_node(t, node, NULL, NULL, NULL);
    n->type = type;
    n->bits = bits;
    n->sign = sign;
    n->value_string = name;
    return n;
}

struct node *make_type_spec(struct token *t, enum var_type type, int bits, int sign, const char *name)
{
    struct node *n = make_node(t, A_TYPESPEC, NULL, NULL, NULL);
    n->type = type;
    n->bits = bits;
    n->sign = sign;
    n->value_string = name;
    return n;
}

struct node *make_type_qual(struct token *t, const char *name)
{
    struct node *n = make_node(t, A_TYPE_QUAL, NULL, NULL, NULL);
    n->value_string = name;
    return n;
}

int scan_const(struct node *node)
{
    int res = 0;
    if (node == NULL)
        return res;
    if (scan_const(node->left))
        res = 1;
    if (scan_const(node->right))
        res = 1;
    if (node->node == A_TYPE_QUAL) {
        if (strcmp(node->value_string, "const") == 0)
            res = 1;
    }
    return res;
}

struct node *type_resolve(struct token *t, struct node *node, int d);

int __parse_struct(struct node *res, struct node *node, int pos)
{
    if (!node)
        return 0;

    int bits = 0;
    int extra = 0;

    if (node->node == A_TYPE_LIST) {
        struct node *tmp = res;
        while (tmp->right)
            tmp = tmp->right;
        tmp->right = make_node(NULL, A_LIST, NULL, NULL, NULL);
        tmp->right->left = type_resolve(NULL, node, 0);

        if (tmp->right->bits == 0 && tmp->right->left->type != V_STRUCT && tmp->right->left->type != V_UNION)
            bits = 32;
        else
            bits = tmp->right->bits;

        /*
         * In case of non-packed, do alignment
         * TODO: packed structs and unions
         */
        while (bits >= 32 && (pos + bits + extra) % 64 != 0)
            extra++;

        // Solve name of the element
        struct node *namenode = node->right;
        while (namenode->right)
            namenode = namenode->right;
        if (namenode)
            tmp->right->left->value_string = namenode->value_string;
        return bits + extra;
    }

    if (node->left)
        bits +=  __parse_struct(res, node->left, bits);
    if (node->right)
        bits +=  __parse_struct(res, node->right, bits);

    return bits;
}

int parse_struct(struct node *res, struct node *node)
{
    return __parse_struct(res, node->right, 0);
}

void __parse_enum(struct node *res, struct node *node, int val)
{
    struct node *valnode = NULL;
    if (!node)
        return;
    //if (node->node == A_ASSIGN && node->left && node->left->node == A_IDENTIFIER && node->right && node->right->node == A_ASSIGN) {
    if (node->node == A_ASSIGN) {
        valnode = node->right;
        node = node->left;
    }

    if (node->node == A_IDENTIFIER) {
        struct node *tmp = res;
        while (tmp->right)
            tmp = tmp->right;
        tmp->right = make_node(NULL, A_LIST, NULL, NULL, NULL);

#if 0
        if (!valnode) {
            valnode = make_node(NULL, A_INT_LIT, NULL, NULL, NULL);
            valnode->value = val;
            val++;
        }
#endif

        tmp->right->left = make_node(NULL, A_IDENTIFIER, valnode, NULL, NULL);
        tmp->right->left->value_string = node->value_string;
    }

    if (node->left)
        __parse_enum(res, node->left, val);
    if (node->right)
        __parse_enum(res, node->right, val);
}

void parse_enum(struct node *res, struct node *node)
{
    __parse_enum(res, node, 0);
}

struct node *type_resolve(struct token *t, struct node *node, int d)
{
    // Need to flatten struct from A_TYPE_LIST
    if (node->left && (node->left->node == A_STRUCT || node->left->node == A_UNION || node->left->node == A_ENUM))
        node = node->left;
    if (node->node == A_STRUCT || node->node == A_UNION) {
        // FIXME
        struct node *name = node->left;
        FATALN(!name, node, "Struct has no name");

        struct node *res = make_node(t, A_TYPE, NULL, NULL, NULL);
        if (node->node == A_STRUCT)
            res->type = V_STRUCT;
        else
            res->type = V_UNION;

        res->value_string = name->value_string;
        res->type_name = name->value_string;
        res->ptr = node->ptr;
        res->addr = node->addr;

        res->bits = parse_struct(res, node);

        res = type_resolve(NULL, res, 0);

        return res;
    }
    if (node->node == A_ENUM) {
        struct node *name = node->left;
        struct node *res = make_node(t, A_TYPE, NULL, NULL, NULL);

        res->type = V_ENUM;
        if (name) {
            res->value_string = name->value_string;
            res->type_name = name->value_string;
        }
        res->ptr = node->ptr;
        res->addr = node->addr;

        res->bits = 32;
        parse_enum(res, node->right);

        return res;
    }

    if (node->node == A_TYPE && (node->type == V_STRUCT || node->type == V_UNION || node->type == V_ENUM))
        return node;
    struct node *res = make_node(t, A_TYPE, NULL, NULL, NULL);
    enum var_type type = node->type;
    type = resolve_var_type(node);
    int bits = node->bits;
    int sign = node->sign;
    int ptr = node->ptr;
    int addr = node->addr;

    if (type == V_INT && bits == 0) {
        // Default for 32 bits
        bits = 32;
    }
    res->bits = bits;
    // Typesign marks unsigned, and default is signed
    // so reverse it
    res->sign = !sign;
    res->type = type;
    res->ptr = ptr;
    res->addr = addr;
    res->is_const = scan_const(node);

    node_free(node);
    return res;
}

struct node *primary_expression(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;

    switch (token->token) {
        case T_INT_LIT:
            res = make_leaf(token, A_INT_LIT);
            break;
        case T_DEC_LIT:
            res = make_leaf(token, A_DEC_LIT);
            break;
        case T_STR_LIT:
            res = make_leaf(token, A_STR_LIT);
            break;
        case T_IDENTIFIER:
            res = type_name(f, token);
            if (res) {
                res = type_resolve(token, res, 0);
                return res;
            }

            res = make_node(token, A_IDENTIFIER, NULL, NULL, NULL);
            res->value_string = token->value_string;
            break;
        case T_NULL:
            res = make_leaf(token, A_NULL);
            break;
        case T_KEYWORD:
            return NULL;
        case T_CURLY_CLOSE:
            return NULL;
        case T_ROUND_OPEN:
            save_point(f, token);
            scan(f, token);
            res = expression(f, token);
            if (!(accept(f, token, T_ROUND_CLOSE))) {
                node_free(res);
                load_point(f, token);
                return NULL;
            }
            remove_save_point(f, token);
            return res;
        default:
            return res;
    }
    scan(f, token);

    return res;
}

struct node *iter_list(struct scanfile *f, struct token *token, list_iter_handler handler, enum comma_type comma, int force_list)
{
    struct node *res = NULL;
#if 1
    int first = 1;
    
    while (1) {
        if (!first) {
            if (accept(f, token, T_COMMA)) {
                FATALN(comma == COMMA_NONE, res, "Expected no comma, got one");
            } else if (comma == COMMA_MANDATORY)
                break;
                //FATALN(comma == COMMA_MANDATORY, res, "Expected comma, didn't get one");
        }
        struct node *tmp = handler(f, token);
        if (!tmp)
            break;
        first = 0;
        if (!res) {
            if (force_list)
                res = make_node(token, A_LIST, tmp, NULL, NULL);
            else
                res = tmp;
        } else
            res = make_node(token, A_LIST, res, NULL, tmp);
    }
#else
    struct node *prev = NULL;
    int first = 1;
    
    while (1) {
        if (!first) {
            if (accept(f, token, T_COMMA)) {
                FATALN(comma == COMMA_NONE, res, "Expected no comma, got one");
            } else if (comma == COMMA_MANDATORY)
                break;
                //FATALN(comma == COMMA_MANDATORY, res, "Expected comma, didn't get one");
        }
        struct node *tmp = handler(f, token);
        if (!tmp)
            break;
        tmp = make_node(token, A_LIST, tmp, NULL, NULL);
        first = 0;
        if (!res)
            res = tmp;
        else
            prev->right = tmp;
        prev = tmp;
    }
#endif
    return res;
}

struct node *struct_declarator(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;

    res = declarator(f, token);
    // TODO bitfields
#if 0
    if (accept(f, token, T_COLON)) {
        struct node *tmp = NULL;
        tmp = constant_expression(f, token);
        if (!res)
            res = tmp;
        else
            res->right = tmp;
    }
#endif
    return res;
}

struct node *struct_declarator_list(struct scanfile *f, struct token *token)
{
    return iter_list(f, token, struct_declarator, COMMA_MANDATORY, 0);
}


struct node *specifier_qualifier_list(struct scanfile *f, struct token *token);
struct node *struct_declaration(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;

    res = specifier_qualifier_list(f, token);
    if (!res)
        return res;

    struct node *tmp = res;
    while (tmp->right != NULL)
        tmp = tmp->right;

    tmp->right = struct_declarator_list(f, token);
    semi(f, token);

    return res;
}

struct node *struct_declaration_list(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    res = iter_list(f, token, struct_declaration, COMMA_NONE, 0);
    return res;
}

struct node *struct_or_union_specifier(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;

    if (accept_keyword(f, token, K_STRUCT)) {
        res = make_node(token, A_STRUCT, NULL, NULL, NULL);
    } else if (accept_keyword(f, token, K_UNION)) {
        res = make_node(token, A_UNION, NULL, NULL, NULL);
    } else
        return NULL;

    if (token->token == T_IDENTIFIER) {
        struct node *tmp = make_node(token, A_IDENTIFIER, NULL, NULL, NULL);
        tmp->value_string = token->value_string;
        scan(f, token);
        res->left = tmp;
    }

    if (accept(f, token, T_CURLY_OPEN)) {
        res->right = struct_declaration_list(f, token);
        expect(f, token, T_CURLY_CLOSE, "}");
    }
#if 0
    node_walk(res);
    stack_trace();
#endif

    return res;
}

struct node *enumerator(struct scanfile *f, struct token *token)
{
    if (token->token != T_IDENTIFIER)
        return NULL;

    struct node *ident = NULL;
    ident = make_node(token, A_IDENTIFIER, NULL, NULL, NULL);
    ident->value_string = token->value_string;
    scan(f, token);

    if (accept(f, token, T_EQ)) {
        struct node *constexpr = constant_expression(f, token);
        ident = make_node(token, A_ASSIGN, ident, NULL, constexpr);
    }
    return ident;
}

struct node *enumerator_list(struct scanfile *f, struct token *token)
{
    return iter_list(f, token, enumerator, COMMA_MANDATORY, 0);
}

struct node *enum_specifier(struct scanfile *f, struct token *token)
{
    if (!accept_keyword(f, token, K_ENUM))
        return NULL;

    struct node *ident = NULL;
    struct node *list = NULL;

    if (token->token == T_IDENTIFIER) {
        ident = make_node(token, A_IDENTIFIER, NULL, NULL, NULL);
        ident->value_string = token->value_string;
        scan(f, token);
    }
    if (accept(f, token, T_CURLY_OPEN)) {
        list = enumerator_list(f, token);
        expect(f, token, T_CURLY_CLOSE, "}");
    }

    if (!ident && !list)
        return NULL;

    return make_node(token, A_ENUM, ident, NULL, list);
}

struct node *type_specifier(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    if (token->token == T_KEYWORD && (token->keyword == K_STRUCT || token->keyword == K_STRUCT))
        return struct_or_union_specifier(f, token);
    if (token->token == T_KEYWORD && token->keyword == K_ENUM)
        return enum_specifier(f, token);
    if (token->token != T_IDENTIFIER)
        return res;

    if (strcmp(token->value_string, "void") == 0)
        res = make_type_spec(token, V_VOID, 0, PARSE_SIGNED, token->value_string);
    else if (strcmp(token->value_string, "char") == 0)
        res = make_type_spec(token, V_INT, 8, PARSE_SIGNED, token->value_string);
    else if (strcmp(token->value_string, "int") == 0)
        res = make_type_spec(token, V_INT, 0, PARSE_SIGNED, token->value_string);
    else if (strcmp(token->value_string, "unsigned") == 0)
        res = make_type_spec(token, V_INT, 0, PARSE_UNSIGNED, token->value_string);
    else if (strcmp(token->value_string, "signed") == 0)
        res = make_type_spec(token, V_INT, 0, PARSE_SIGNED, token->value_string);
    else if (strcmp(token->value_string, "short") == 0)
        res = make_type_spec(token, V_INT, 16, PARSE_SIGNED, token->value_string);
    else if (strcmp(token->value_string, "long") == 0)
        res = make_type_spec(token, V_INT, 64, PARSE_SIGNED, token->value_string);
    else if (strcmp(token->value_string, "double") == 0)
        res = make_type_spec(token, V_FLOAT, 64, PARSE_SIGNED, token->value_string);

    // FIXME More types

    if (res)
        scan(f, token);

    return res;
}

struct node *type_qualifier(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;

    if (token->token != T_IDENTIFIER)
        return res;

    if (strcmp(token->value_string, "const") == 0 || strcmp(token->value_string, "volatile") == 0) {
        res = make_type_qual(token, token->value_string);
        scan(f, token);
    }

    return res;
}

struct node *type_qualifier_list(struct scanfile *f, struct token *token)
{
    return iter_list(f, token, type_qualifier, COMMA_NONE, 0);
}

struct node *declaration_specifiers(struct scanfile *f, struct token *token)
{
    struct node *type = type_specifier(f, token);
    //TODO storage_class_specifier
    if (type == NULL) {
        type = type_qualifier(f, token);

        if (type == NULL)
            return type;
    }
    type = type_resolve(token, type, 0);

    struct node *res = type;
    while (1) {
        struct node *tmp = declaration_specifiers(f, token);
        if (tmp == NULL)
            break;
        res = make_node(token, A_GLUE, res, NULL, tmp);
    }

    return res;
}

struct node *parameter_declaration(struct scanfile *f, struct token *token)
{
    struct node *spec = declaration_specifiers(f, token);
    if (!spec)
        return NULL;

    struct node *decl = declarator(f, token);
    if (!decl)
        decl = abstract_declarator(f, token);
    if (decl)
        return make_node(token, A_LIST, spec, NULL, decl);

    return spec;
}

struct node *parameter_list(struct scanfile *f, struct token *token)
{
    return iter_list(f, token, parameter_declaration, COMMA_MANDATORY, 0);
}

struct node *parameter_type_list(struct scanfile *f, struct token *token)
{
    struct node *res = parameter_list(f, token);
    // TODO ellipsis
    return res;
}

struct node *identifier_list(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    while(accept(f, token, T_IDENTIFIER)) {
        struct node *tmp = make_node(token, A_IDENTIFIER, NULL, NULL, NULL);
        tmp->value_string = token->value_string;
        if (!res)
            tmp = res;
        else
            res = make_node(token, A_LIST, res, NULL, tmp);
        if (token->token != T_COMMA)
            break;
        scan(f, token);
    }
    return res;
}

struct node *direct_declarator(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    save_point(f, token);
    if (token->token == T_IDENTIFIER) {
        res = make_node(token, A_IDENTIFIER, NULL, NULL, NULL);
        res->value_string = token->value_string;
        scan(f, token);
    }
    else if (accept(f, token, T_ROUND_OPEN)) {
        struct node *decl = declarator(f, token);
        if (decl)
            res = make_node(token, A_GLUE, res, NULL, decl);
        if (!accept(f, token, T_ROUND_CLOSE)) {
            node_free(res);
            load_point(f, token);
            return NULL;
        }
    }
    remove_save_point(f, token);
    // TODO Rest of cases
    if (res) {
        if (accept(f, token, T_ROUND_OPEN)) {
            struct node *params = parameter_type_list(f, token);
            if (!params)
                params = identifier_list(f, token);
            res->right = params;
            expect(f, token, T_ROUND_CLOSE, ")");
        } else if (accept(f, token, T_SQUARE_OPEN)) {
            struct node *index = constant_expression(f, token);
            expect(f, token, T_SQUARE_CLOSE, "]");
            res = make_node(token, A_INDEX, res, NULL, index);
        }

    }
    // TODO other cases
    return res;
}

struct node *pointer(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    while (token->token == T_STAR) {
        struct node *qual = type_qualifier_list(f, token);
        if (qual) {
            if (res)
                res->right = qual;
            else
                res = make_node(token, A_POINTER, qual, NULL, NULL);
        } else {
            if (!res)
                res = make_node(token, A_POINTER, NULL, NULL, NULL);
            if (!res)
                break;
            res->ptr++;
            scan(f, token);
        }
    }

    return res;
}

struct node *declarator(struct scanfile *f, struct token *token)
{
    struct node *ptr = pointer(f, token);
    struct node *res = direct_declarator(f, token);
    if (ptr) {
        ptr->left = res;
        res = ptr;
    }
    return res;
}

struct node *shift_expression(struct scanfile *f, struct token *token)
{
    struct node *res = additive_expression(f, token);
    if (!res)
        return res;

    if (accept(f, token, T_LEFT)) {
        struct node *tmp = shift_expression(f, token);
        FATAL(!tmp, "Right side missing on <<");
        res = make_node(token, A_LEFT, res, NULL, tmp);
    } else if (accept(f, token, T_RIGHT)) {
        struct node *tmp = shift_expression(f, token);
        FATAL(!tmp, "Right side missing on >>");
        res = make_node(token, A_RIGHT, res, NULL, tmp);
    }
    return res;
}

struct node *relational_expression(struct scanfile *f, struct token *token)
{
    struct node *res = shift_expression(f, token);
    if (!res)
        return NULL;

    if (accept(f, token, T_LT)) {
        enum nodetype type = A_LT;
        if (accept(f, token, T_EQ))
            type = A_LT_EQ;
        
        struct node *right = relational_expression(f, token);
        FATAL(!right, "Invalid relational expression");
        return make_node(token, type, res, NULL, right);
    } else if (accept(f, token, T_GT)) {
        enum nodetype type = A_GT;
        if (accept(f, token, T_EQ))
            type = A_GT_EQ;
        
        struct node *right = relational_expression(f, token);
        FATAL(!right, "Invalid relational expression");
        return make_node(token, type, res, NULL, right);
    }
    return res;
}

struct node *equality_expression(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;

    res = relational_expression(f, token);
    if (!res)
        return NULL;

    if (accept(f, token, T_EQ_NE)) {
        struct node *tmp = relational_expression(f, token);
        FATAL(!tmp, "Right side missing on !=");
        return make_node(token, A_NE_OP, res, NULL, tmp);
    } else if (accept(f, token, T_EQ_EQ)) {
        struct node *tmp = relational_expression(f, token);
        FATAL(!tmp, "Right side missing on ==");
        return make_node(token, A_EQ_OP, res, NULL, tmp);
    }

    return res;
}

struct node *and_expression(struct scanfile *f, struct token *token)
{
    struct node *res = equality_expression(f, token);
    if (!res)
        return NULL;

    if (accept(f, token, T_AMP)) {
        struct node *tmp = and_expression(f, token);
        FATAL(!tmp, "Right side missing on AND");
        res = make_node(token, A_AND, res, NULL, tmp);
    }

    return res;
}

struct node *exclusive_or_expression(struct scanfile *f, struct token *token)
{
    struct node *res = and_expression(f, token);
    if (!res)
        return res;

    if (accept(f, token, T_XOR)) {
        struct node *tmp = exclusive_or_expression(f, token);
        FATAL(!tmp, "Right side missing on XOR");
        res = make_node(token, A_XOR, res, NULL, tmp);
    }
    return res;
}

struct node *inclusive_or_expression(struct scanfile *f, struct token *token)
{
    struct node *res = exclusive_or_expression(f, token);
    if (!res)
        return res;

    if (accept(f, token, T_OR)) {
        struct node *tmp = inclusive_or_expression(f, token);
        FATAL(!tmp, "Right side missing on OR");
        res = make_node(token, A_OR, res, NULL, tmp);
    }
    return res;
}

struct node *logical_and_expression(struct scanfile *f, struct token *token)
{
    struct node *res = inclusive_or_expression(f, token);
    if (!res)
        return res;

    if (accept(f, token, T_LOG_AND)) {
        struct node *tmp = logical_and_expression(f, token);
        FATAL(!tmp, "Right side missing on logical AND");
        res = make_node(token, A_LOG_AND, res, NULL, tmp);
    }
    return res;
}

struct node *logical_or_expression(struct scanfile *f, struct token *token)
{
    struct node *res = logical_and_expression(f, token);
    if (!res)
        return res;

    if (accept(f, token, T_LOG_OR)) {
        struct node *tmp = logical_or_expression(f, token);
        FATAL(!tmp, "Right side missing on logical OR");
        res = make_node(token, A_LOG_OR, res, NULL, tmp);
    }
    return res;
}

struct node *conditional_expression(struct scanfile *f, struct token *token)
{
    struct node *res = logical_or_expression(f, token);
    if (!res)
        return res;

    // Ternary operator
    if (accept(f, token, T_QUESTION)) {
        struct node *exp = expression(f, token);
        if (!accept(f, token, T_COLON))
            ERR("Expected ':' in ternary operation");
        struct node *cond = conditional_expression(f, token);
        res = make_node(token, A_TERNARY, res, exp, cond);
    }

    return res;
}
struct node *constant_expression(struct scanfile *f, struct token *token)
{
    return conditional_expression(f, token);
}

struct node *assignment_expression(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    enum nodetype nodetype = A_ASSIGN;

    save_point(f, token);
    struct node *unary = unary_expression(f, token);
    if (!unary) {
        load_point(f, token);
        res = conditional_expression(f, token);
        return res;
    }

    if (accept(f, token, T_PLUS))
        nodetype = A_ADD_ASSIGN;
    else if (accept(f, token, T_MINUS))
        nodetype = A_SUB_ASSIGN;
    else if (accept(f, token, T_STAR))
        nodetype = A_MUL_ASSIGN;
    else if (accept(f, token, T_SLASH))
        nodetype = A_DIV_ASSIGN;
    else if (accept(f, token, T_MOD))
        nodetype = A_MOD_ASSIGN;
    else if (accept(f, token, T_LEFT))
        nodetype = A_LEFT_ASSIGN;
    else if (accept(f, token, T_RIGHT))
        nodetype = A_RIGHT_ASSIGN;
    else if (accept(f, token, T_AMP))
        nodetype = A_AND_ASSIGN;
    else if (accept(f, token, T_OR))
        nodetype = A_OR_ASSIGN;
    else if (accept(f, token, T_XOR))
        nodetype = A_XOR_ASSIGN;

    if (accept(f, token, T_EQ)) {
        if (nodetype != A_ASSIGN || token->token != T_EQ) {
            remove_save_point(f, token);
            struct node *expr = assignment_expression(f, token);
            FATAL(!expr, "Invalid assignment");
            res = make_node(token, nodetype, unary, NULL, expr);
            return res;
        }
    }
    load_point(f, token);

    res = conditional_expression(f, token);

    return res;
}

struct node *initializer(struct scanfile *f, struct token *token)
{
    struct node *res = assignment_expression(f, token);
    if (res)
        return res;
    return NULL;
}

struct node *init_declarator(struct scanfile *f, struct token *token)
{
    save_point(f, token);
    struct node *res = declarator(f, token);
    if (!res)
        return NULL;
    if (accept(f, token, T_EQ)) {
        struct node *tmp = initializer(f, token);
        if (!tmp) {
            ERR("Expected initializer after '='");
            return NULL;
        }
        res = make_node(token, A_ASSIGN, res, NULL, tmp);
    }

    return res;
}

struct node *init_declarator_list(struct scanfile *f, struct token *token)
{
    return iter_list(f, token, init_declarator, COMMA_MANDATORY, 0);
}

struct node *declaration(struct scanfile *f, struct token *token)
{
    save_point(f, token);
    struct node *res = declaration_specifiers(f, token);
    if (!res) {
        load_point(f, token);
        return NULL;
    }
    res = type_resolve(token, res, 0);

    struct node *decl = init_declarator_list(f, token);
    if (decl) {
        res = make_node(token, A_DECLARATION, res, NULL, decl);
    }
#if 0
    else {
        match(f, token, T_IDENTIFIER, "identifier");

        struct node *tmp = make_node(token, A_IDENTIFIER, NULL, NULL);
        tmp->value_string = token->value_string;
        res = make_node(token, A_DECLARATION, res, tmp);

        scan(f, token);
    }
#endif

    if (!accept(f, token, T_SEMI)) {
        node_free(res);
        load_point(f, token);
        return NULL;
    }
    remove_save_point(f, token);
    return res;
}

struct node *argument_expression_list(struct scanfile *f, struct token *token)
{
    // FIXME: Make to use iter_list
#if 1
    struct node *res = NULL;
    struct node *prev = NULL;

    while (1) {
        struct node *tmp = assignment_expression(f, token);
        if (!tmp)
            break;
        tmp = make_node(token, A_LIST, tmp, NULL, NULL);
        if (res == NULL)
            res = tmp;
        else {
            FATAL(prev->right, "Compiler error!")
            prev->right = tmp;
        }
        prev = tmp;
        if (!accept(f, token, T_COMMA))
            break;
    }
    return res;

#else
    return iter_list(f, token, assignment_expression, COMMA_MANDATORY, 1);
#endif
}

struct node *postfix_expression(struct scanfile *f, struct token *token)
{
    struct node *res = primary_expression(f, token);

    if (!res)
        return NULL;

    // TODO  "[..]", pointers, elements, etc.
    while (1) {
        if (accept(f, token, T_ROUND_OPEN)) {
            struct node *args = argument_expression_list(f, token);

            res = make_node(token, A_FUNC_CALL, res, NULL, args);
            expect(f, token, T_ROUND_CLOSE, ")");
        } else if (accept(f, token, T_SQUARE_OPEN)) {
            struct node *index = expression(f, token);
            expect(f, token, T_SQUARE_CLOSE, "]");
            res = make_node(token, A_INDEX, res, NULL, index);
        } else if (accept(f, token, T_PLUSPLUS)) {
            res = make_node(token, A_POSTINC, res, NULL, NULL);
        } else if (accept(f, token, T_MINUSMINUS)) {
            res = make_node(token, A_POSTDEC, res, NULL, NULL);
        } else if (accept(f, token, T_DOT)) {
            if (token->token != T_IDENTIFIER)
                ERR("Invalid element access after dot");
            struct node *post = make_node(token, A_IDENTIFIER, NULL, NULL, NULL);
            post->value_string = token->value_string;
            scan(f, token);

            res = make_node(token, A_ACCESS, res, NULL, post);
        } else
            break;
    }

    return res;
}

struct node *cast_expression(struct scanfile *f, struct token *token);

struct node *unary_expression(struct scanfile *f, struct token *token)
{
    struct node *left;

    if (accept(f, token, T_PLUS)) {
        return cast_expression(f, token);
    } else if (accept(f, token, T_MINUS)) {
        left = cast_expression(f, token);
        if (!left)
            ERR("Invalid cast: %s", token_dump(token));
        return make_node(token, A_NEGATE, left, NULL, NULL);
    } else if (accept(f, token, T_EXCLAM)) {
        left = cast_expression(f, token);
        if (!left)
            ERR("Invalid cast!");
        return make_node(token, A_NOT, left, NULL, NULL);
    } else if (accept(f, token, T_TILDE)) {
        left = cast_expression(f, token);
        if (!left)
            ERR("Invalid cast!");
        return make_node(token, A_TILDE, left, NULL, NULL);
    } else if (accept(f, token, T_PLUSPLUS)) {
        left = unary_expression(f, token);
        FATAL(!left, "Invalid preinc");
        left = make_node(token, A_PREINC, left, NULL, NULL);
        return left;
    } else if (accept(f, token, T_MINUSMINUS)) {
        left = unary_expression(f, token);
        FATAL(!left, "Invalid preinc");
        left = make_node(token, A_PREDEC, left, NULL, NULL);
        return left;
    } else if (accept(f, token, T_STAR)) {
        left = cast_expression(f, token);
        if (!left)
            ERR("Required lvalue for unary '*' operator");
        if (left->node != A_IDENTIFIER)
            ERR("Expected identifier lvalue for unary '*' operator");
        left = make_node(token, A_DEREFERENCE, left, NULL, NULL);
        return left;
    } else if (accept(f, token, T_AMP)) {
        int addr = 1;
        while (accept(f, token, T_AMP))
            addr += 1;
        left = cast_expression(f, token);
        if (!left)
            ERR("Required lvalue for unary '&' operator");
        if (left->node != A_IDENTIFIER)
            ERR("Expected identifier lvalue for unary '&' operator");
        left = make_node(token, A_ADDR, left, NULL, NULL);
        left->addr = addr;
        return left;
    } else if (accept_keyword(f, token, K_SIZEOF)) {
        left = NULL;
        save_point(f, token);
        if (accept(f, token, T_ROUND_OPEN)) {
            left = type_name(f, token);
            if (left) {
                remove_save_point(f, token);
                left = type_resolve(token, left, 0);
                expect(f, token, T_ROUND_CLOSE, ")");
            } else
                load_point(f, token);
        } else
            remove_save_point(f, token);
        if (!left)
            left = unary_expression(f, token);
        FATAL(!left, "Didn't get type name for sizeof");
        left = make_node(token, A_SIZEOF, left, NULL, NULL);
        return left;
    }
    left = postfix_expression(f, token);
    return left;
}

struct node *specifier_qualifier_list(struct scanfile *f, struct token *token)
{
    struct node *type = type_specifier(f, token);

    if (type == NULL)
        type = type_qualifier(f, token);

    if (type == NULL)
        return NULL;

    struct node *rest = specifier_qualifier_list(f, token);
    type = make_node(token, A_TYPE_LIST, type, NULL, rest);

    return type;
}

struct node *direct_abstract_declarator(struct scanfile *f, struct token *token)
{
    // TODO
    return NULL;
}

struct node *abstract_declarator(struct scanfile *f, struct token *token)
{
    struct node *res = pointer(f, token);
    struct node *dir = direct_abstract_declarator(f, token);
    if (res && dir)
        res = make_node(token, A_LIST, res, NULL, dir);
    else if (!res)
        res = dir;

    return res;
}

struct node *type_name(struct scanfile *f, struct token *token)
{
    struct node *res = specifier_qualifier_list(f, token);
    if (!res)
        return res;

    struct node *rest = abstract_declarator(f, token);
    if (rest)
        res = make_node(token, A_LIST, res, NULL, rest);

    return res;
}

struct node *cast_expression(struct scanfile *f, struct token *token)
{
    save_point(f, token);
    if (accept(f, token, T_ROUND_OPEN)) {
        struct node *cast_to = type_name(f, token);
        if (cast_to) {
            remove_save_point(f, token);
            //FATAL(!cast_to, "No cast type name");
            cast_to = type_resolve(token, cast_to, 0);
            expect(f, token, T_ROUND_CLOSE, ")");
            struct node *src = cast_expression(f, token);
            FATAL(!src, "No cast source");
            return make_node(token, A_CAST, cast_to, NULL, src);
        }
    }
    load_point(f, token);

    return unary_expression(f, token);
}

struct node *multiplicative_expression(struct scanfile *f, struct token *token)
{
    struct node *left, *right, *castres;
    enum tokentype type;
    int remove = 1;

    left = cast_expression(f, token);
    if (!left || token->token == T_EOF)
        return left;

    castres = left;
    save_point(f, token);
    type = token->token;
    while (type == T_STAR || type == T_SLASH || type == T_MOD) {
        if (!scan(f, token))
            ERR("Couldn't scan next in multiplicative_expression");
        right = cast_expression(f, token);
        if (!right) {
            load_point(f, token);
            left = castres;
            remove = 0;
            break;
        }
            //return NULL;
        left = make_node(token, oper(type), left, NULL, right);
        type = token->token;
    }

    if (remove)
        remove_save_point(f, token);
    return left;
}

struct node *additive_expression(struct scanfile *f, struct token *token)
{
    struct node *left, *right, *castres;
    enum tokentype type;
    int remove = 1;

    left = multiplicative_expression(f, token);
    if (!left || token->token == T_EOF)
        return left;

    castres = left;
    save_point(f, token);
    type = token->token;
    while (type == T_PLUS || type == T_MINUS) {
        if (!scan(f, token))
            ERR("Couldn't scan next in additive_expression");
        right = multiplicative_expression(f, token);
        if (!right) {
            load_point(f, token);
            left = castres;
            remove = 0;
            break;
        }
        left = make_node(token, oper(type), left, NULL, right);
        type = token->token;
    }

    if (remove)
        remove_save_point(f, token);
    return left;
}

struct node *expression(struct scanfile *f, struct token *token)
{
    if (token->token == T_EOF)
        return NULL;
    struct node *res = NULL;
    res = assignment_expression(f, token);
    // TODO comma
    return res;
}

struct node *expression_statement(struct scanfile *f, struct token *token)
{
    while (accept(f, token, T_SEMI));

    save_point(f, token);
    struct node *res = expression(f, token);
    if (res && !accept(f, token, T_SEMI)) {
        load_point(f, token);
        return NULL;
    }
    remove_save_point(f, token);

    return res;
}

struct node *jump_statement(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    if (token->token != T_KEYWORD)
        return NULL;
    if (strcmp(token->value_string, "return") == 0) {
        scan(f, token);
        res = expression(f, token);
        res = make_node(token, A_RETURN, res, NULL, NULL);
    }
    if (res)
        semi(f, token);
    return res;
}

struct node *if_statement(struct scanfile *f, struct token *token)
{
    struct node *cond = NULL;
    struct node *true_ast = NULL;
    struct node *false_ast = NULL;

    if (!accept_keyword(f, token, K_IF))
        return NULL;

    expect(f, token, T_ROUND_OPEN, "(");

    cond = expression(f, token);
    FATAL(!cond, "If missing condition");

    expect(f, token, T_ROUND_CLOSE, ")");

    true_ast = statement(f, token);

    if (accept_keyword(f, token, K_ELSE))
        false_ast = statement(f, token);

    return make_node(token, A_IF, cond, true_ast, false_ast);
}

struct node *selection_statement(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;

    if (token->token != T_KEYWORD)
        return NULL;

    res = if_statement(f, token);

    // TODO: switch ...

    return res;
}

struct node *iteration_statement(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;

    if (token->token != T_KEYWORD)
        return NULL;

    if (accept_keyword(f, token, K_WHILE)) {
        expect(f, token, T_ROUND_OPEN, "(");
        res = expression(f, token);
        expect(f, token, T_ROUND_CLOSE, ")");

        struct node *body = statement(f, token);
        res = make_node(token, A_WHILE, res, NULL, body);
    } else if (accept_keyword(f, token, K_DO)) {
        struct node *body = statement(f, token);
        FATAL(!accept_keyword(f, token, K_WHILE), "Do missing while");
        expect(f, token, T_ROUND_OPEN, "(");
        res = expression(f, token);
        expect(f, token, T_ROUND_CLOSE, ")");
        res = make_node(token, A_DO, res, NULL, body);
        semi(f, token);
    } else if (accept_keyword(f, token, K_FOR)) {
        expect(f, token, T_ROUND_OPEN, "(");
        save_point(f, token);
        struct node *init = expression_statement(f, token);
        if (!init) {
            load_point(f, token);
            init = declaration(f, token);
        } else
            remove_save_point(f, token);
        FATAL(!init, "Missing FOR initializer");
        struct node *comp = expression_statement(f, token);
        FATAL(!init, "Missing FOR test");

        struct node *post = NULL;
        if (token->token != T_ROUND_CLOSE)
            post = expression(f, token);
        expect(f, token, T_ROUND_CLOSE, ")");

        struct node *body = statement(f, token);
        init = make_node(token, A_GLUE, init, NULL, post);
        res = make_node(token, A_FOR, comp, init, body);
    }

    return res;
}

struct node *statement(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;

    // TODO: labeled_statement

    save_point(f, token);
    res = compound_statement(f, token);
    if (res) {
        remove_save_point(f, token);
        return res;
    }
    load_point(f, token);

    save_point(f, token);
    res = expression_statement(f, token);
    if (res) {
        remove_save_point(f, token);
        return res;
    }
    load_point(f, token);

    res = selection_statement(f, token);
    if (res)
        return res;

    res = iteration_statement(f, token);
    if (res)
        return res;

    res = jump_statement(f, token);

    return res;
}

struct node *statement_list(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    struct node *prev = NULL;
    while (1) {
        struct node *tmp = statement(f, token);
        if (!tmp)
            tmp = declaration(f, token);
        if (!tmp)
            break;
        tmp = make_node(token, A_LIST, tmp, NULL, NULL);
        if (res == NULL)
            res = tmp;
        else {
            FATAL(prev->right, "Compiler error!")
            prev->right = tmp;
        }
        prev = tmp;
    }
    return res;
}

struct node *declaration_list(struct scanfile *f, struct token *token)
{
    return iter_list(f, token, declaration, COMMA_NONE, 0);
}

struct node *compound_statement(struct scanfile *f, struct token *token)
{
    struct node *decl = NULL;
    struct node *res = NULL;

    if (!accept(f, token, T_CURLY_OPEN))
        return NULL;

    decl = declaration_list(f, token);
    res = statement_list(f, token);
    expect(f, token, T_CURLY_CLOSE, "}");

    // We parsed body, always return it
    res = make_node(token, A_GLUE, decl, NULL, res);
    return res;
}

struct node *function_definition(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    struct node *spec = declaration_specifiers(f, token);
    if (!spec)
        return NULL;
    spec = type_resolve(token, spec, 0);
    struct node *decl = declarator(f, token);
    if (!decl)
        return NULL;
    //FATALN(!decl, spec, "Invalid function definition");
#if 0
    if (!decl)
        ERR("Invalid function definition");
#endif
    struct node *comp = compound_statement(f, token);
    if (!comp) {
        // If no compound, this is most probably variable decls
        // This is handled by save points.
        return NULL;
    }


    //decl = type_resolve(token, decl, 0);
    res = make_node(token, A_GLUE, decl, NULL, comp);
    res = make_node(token, A_FUNCTION, spec, NULL, res);

    return res;
}

struct node *external_declaration(struct scanfile *f, struct token *token)
{
    struct node *res;

    save_point(f, token);
    res = function_definition(f, token);
    if (res) {
        remove_save_point(f, token);
        return res;
    }
    load_point(f, token);

    save_point(f, token);
    res = declaration(f, token);
    if (res) {
        remove_save_point(f, token);
        return res;
    }
    load_point(f, token);

    res = statement_list(f, token);
    return res;
}

struct node *translation_unit(struct scanfile *f, struct token *token)
{
    struct node *decl = external_declaration(f, token);
    if (!decl)
        return NULL;
    struct node *res = decl;

    while (1) {
        struct node *tmp = translation_unit(f, token);
        if (!tmp)
            break;
        /*
         * GLUE and LIST work alike, however LIST is always a list,
         * GLUE can be anything
         */
        res = make_node(token, A_GLUE, res, NULL, tmp);
    }
    return res;
}

struct node *parse(struct scanfile *f)
{
    struct token token;
    memset(&token, 0, sizeof(struct token));
    scan(f, &token);
    struct node *res = translation_unit(f, &token);
    FATAL(!res, "Can't parse source, didn't detect token: %s", token_dump(&token));
    return res;
}
