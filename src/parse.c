#include "parse.h"
#include <string.h>

#define PARSE_SIGNED   0
#define PARSE_UNSIGNED 1

struct node *additive_expression(struct scanfile *f, struct token *token);

static const char *nodestr[] = {
    "+", "-", "*", "/", "%",
    "IDENTIFIER",
    "-",
    "INT_LIT", "DEC_LIT",
    "STR_LIT",
    "ASSIGN", "GLUE", "TYPE", "TYPESPEC", "TYPE_QUAL",
    "DECLARATION",
    "PARAMS",
    "FUNCTION",
    "RETURN",
    "POINTER",
    "ADDR",
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

    n->type = v1;
    n->bits = b1;
    //printf("SIGN: v1 %d, bits %d,  %d, %d -> %d @%s\n", v1, b1, s1, s2, n->sign, node_str(n));
    n->sign = s1;
    n->ptr = ptr1;
    return v1;
}

struct node *make_node(enum nodetype node, struct node *left,
        struct node *right)
{
    struct node *res = calloc(1, sizeof(struct node));
    if (res == NULL)
        ERR("Can't create new node, out of memory?");

    res->node = node;
    res->left = left;
    res->right = right;
    if (left != NULL || right != NULL)
        res->type = resolve_var_type(res);
    else
        res->type = V_VOID;
#if DEBUG
    printf("MAKE: %d, %s\n", node, node_str(res));
#endif

    return res;
}

struct node *make_leaf(enum nodetype node, struct token *t)
{
    struct node *n = make_node(node, NULL, NULL);

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
    } else
        ERR("Invalid leaf: %s", node_str(n));
    return n;
}

struct node *make_type(enum nodetype node, struct token *t, enum var_type type, int bits, int sign, const char *name)
{
    struct node *n = make_node(node, NULL, NULL);
    n->type = type;
    n->bits = bits;
    n->sign = sign;
    n->value_string = name;
    return n;
}

struct node *make_type_spec(struct token *t, enum var_type type, int bits, int sign, const char *name)
{
    struct node *n = make_node(A_TYPESPEC, NULL, NULL);
    n->type = type;
    n->bits = bits;
    n->sign = sign;
    n->value_string = name;
    return n;
}

struct node *make_type_qual(const char *name)
{
    struct node *n = make_node(A_TYPE_QUAL, NULL, NULL);
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

struct node *type_resolve(struct node *node, int d)
{
    struct node *res = make_node(A_TYPE, NULL, NULL);
    enum var_type type = node->type;
    type = resolve_var_type(node);
    int bits = node->bits;
    int sign = node->sign;
    int ptr = node->ptr;

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
    res->is_const = scan_const(node);
    return res;
}

struct node *primary_expression(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;

    switch (token->token) {
        case T_INT_LIT:
            res = make_leaf(A_INT_LIT, token);
            break;
        case T_DEC_LIT:
            res = make_leaf(A_DEC_LIT, token);
            break;
        case T_STR_LIT:
            res = make_leaf(A_STR_LIT, token);
            break;
        case T_IDENTIFIER:
            res = make_node(A_IDENTIFIER, NULL, NULL);
            res->value_string = token->value_string;
            break;
        case T_KEYWORD:
            return NULL;
        case T_CURLY_CLOSE:
            return NULL;
        default:
            ERR("Unexpected token: %s", token_str(token));
    }
    scan(f, token);

    return res;
}

struct node *type_specifier(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    if (token->token != T_IDENTIFIER)
        return res;

    if (strcmp(token->value_string, "void") == 0)
        res = make_type_spec(token, V_VOID, 0, PARSE_SIGNED, token->value_string);
    else if (strcmp(token->value_string, "char") == 0)
        res = make_type_spec(token, V_INT, 8, PARSE_SIGNED, token->value_string);
    else if (strcmp(token->value_string, "int") == 0)
        res = make_type_spec(token, V_INT, 0, PARSE_SIGNED, token->value_string);
    else if (strcmp(token->value_string, "unsigned") == 0)
        res = make_type_spec( token, V_INT, 0, PARSE_UNSIGNED, token->value_string);
    else if (strcmp(token->value_string, "signed") == 0)
        res = make_type_spec( token, V_INT, 0, PARSE_SIGNED, token->value_string);
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
        res = make_type_qual(token->value_string);
        scan(f, token);
    }

    return res;
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

    struct node *res = NULL;
    res = type;
    while (1) {
        struct node *tmp = declaration_specifiers(f, token);
        if (tmp == NULL)
            break;
        res = make_node(A_GLUE, res, tmp);
    }

    return res;
}

struct node *declarator(struct scanfile *f, struct token *token);
struct node *direct_declarator(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    if (token->token == T_IDENTIFIER) {
        res = make_node(A_IDENTIFIER, NULL, NULL);
        res->value_string = token->value_string;
        scan(f, token);
    }
    if (token->token == T_ROUND_OPEN) {
        scan(f, token);
        struct node *decl = declarator(f, token);
        if (decl)
            res = make_node(A_GLUE, res, decl);
        expect(f, token, T_ROUND_CLOSE, ")");
    }
    if (res) {
        //if (token->token == T_SQUARE_OPEN) {
        //}
        if (token->token == T_ROUND_OPEN) {
            scan(f, token);
            // TODO parameter_type_list
            // TODO identifier_list
            res = make_node(A_PARAMS, res, NULL);
            expect(f, token, T_ROUND_CLOSE, ")");
        }

    }
    // TODO other cases
    return res;
}

struct node *pointer(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    while (token->token == T_STAR) {
        if (!res)
            res = make_node(A_POINTER, NULL, NULL);
        if (!res)
            break;
        res->ptr++;
        scan(f, token);
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

struct node *conditional_expression(struct scanfile *f, struct token *token)
{
    struct node *res = additive_expression(f, token);

    // TODO ternary
    return res;
}

struct node *assignment_expression(struct scanfile *f, struct token *token)
{
    // FIXME unary_expression assignment_operator
    return conditional_expression(f, token);
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
    struct node *res = declarator(f, token);
    if (!res)
        return NULL;
    if (token->token == T_EQ) {
        scan(f, token);
        struct node *tmp = initializer(f, token);
        if (!tmp)
            return NULL;
        res = make_node(A_ASSIGN, res, tmp);
    }

    return res;
}

struct node *init_declarator_list(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    struct node *prev = NULL;
    while (1) {
        struct node *tmp = init_declarator(f, token);
        if (!tmp)
            break;
        tmp = make_node(A_LIST, tmp, NULL);
        if (res == NULL)
            res = tmp;
        else {
            FATAL(prev->right, "Compiler error!")
            prev->right = tmp;
        }
        prev = tmp;
        if (token->token != T_COMMA)
            break;
        scan(f, token);
    }
    return res;
}

struct node *declaration(struct scanfile *f, struct token *token)
{
    struct node *res = declaration_specifiers(f, token);
    if (!res)
        return NULL;
    res = type_resolve(res, 0);

    struct node *decl = init_declarator_list(f, token);
    if (decl)
        res = make_node(A_DECLARATION, res, decl);
#if 0
    else {
        match(f, token, T_IDENTIFIER, "identifier");

        struct node *tmp = make_node(A_IDENTIFIER, NULL, NULL);
        tmp->value_string = token->value_string;
        res = make_node(A_DECLARATION, res, tmp);

        scan(f, token);
    }
#endif

    semi(f, token);
    return res;
}

struct node *postfix_expression(struct scanfile *f, struct token *token)
{
    // TODO
    return primary_expression(f, token);
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
            ERR("Invalid cast!");
        return make_node(A_NEGATE, left, NULL);
    } else if (accept(f, token, T_AMP)) {
        left = cast_expression(f, token);
        if (!left)
            ERR("Required lvalue for unary '&' operator");
        if (left->node != A_IDENTIFIER)
            ERR("Expected identifier lvalue for unary '&' operator");
        return make_node(A_ADDR, left, NULL);
    }

    left = postfix_expression(f, token);
    return left;
}

struct node *cast_expression(struct scanfile *f, struct token *token)
{
    // TODO
    return unary_expression(f, token);
}

struct node *multiplicative_expression(struct scanfile *f, struct token *token)
{
    struct node *left, *right;
    enum tokentype type;

    left = cast_expression(f, token);
    if (token->token == T_EOF)
        return left;

    type = token->token;
    while (type == T_STAR || type == T_SLASH || type == T_MOD) {
        if (!scan(f, token))
            ERR("Couldn't scan next in multiplicative_expression");
        right = cast_expression(f, token);
        if (!right)
            return NULL;
        left = make_node(oper(type), left, right);
        type = token->token;
    }

    return left;
}

struct node *additive_expression(struct scanfile *f, struct token *token)
{
    struct node *left, *right;
    enum tokentype type;

    left = multiplicative_expression(f, token);
    if (token->token == T_EOF)
        return left;

    type = token->token;
    while (type == T_PLUS || type == T_MINUS) {
        if (!scan(f, token))
            ERR("Couldn't scan next in additive_expression");
        right = multiplicative_expression(f, token);
        if (!right)
            return NULL;
        left = make_node(oper(type), left, right);
        type = token->token;
    }
    return left;
}

struct node *expression(struct scanfile *f, struct token *token)
{
    if (token->token == T_EOF)
        return NULL;
    struct node *res = NULL;
    res = additive_expression(f, token);
    return res;
    //assignment_expression(f);
}

struct node *expression_statement(struct scanfile *f, struct token *token)
{
    struct node *res = expression(f, token);
    if (res)
        semi(f, token);
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
        res = make_node(A_RETURN, res, NULL);
    }
    if (res)
        semi(f, token);
    return res;
}

struct node *statement(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    save_point(f, token);
    res = expression_statement(f, token);
    if (res) {
        remove_save_point(f, token);
        return res;
    }
    load_point(f, token);
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
            break;
        tmp = make_node(A_LIST, tmp, NULL);
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
    struct node *res = NULL;
    struct node *prev = NULL;
    while (1) {
        struct node *tmp = declaration(f, token);
        if (!tmp)
            break;
        tmp = make_node(A_LIST, tmp, NULL);
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

struct node *compound_statement(struct scanfile *f, struct token *token)
{
    struct node *decl = NULL;
    struct node *res = NULL;
    if (token->token != T_CURLY_OPEN)
        return NULL;
    scan(f, token);

    decl = declaration_list(f, token);

    res = statement_list(f, token);
    if (!res) {
        // TODO other cases
    }

    expect(f, token, T_CURLY_CLOSE, "}");
    if (decl)
        res = make_node(A_GLUE, decl, res);
    return res;
}

struct node *function_definition(struct scanfile *f, struct token *token)
{
    struct node *res = NULL;
    struct node *spec = declaration_specifiers(f, token);
    if (!spec)
        return NULL;
    spec = type_resolve(spec, 0);
    struct node *decl = declarator(f, token);
    if (!decl)
        ERR("Invalid function definition");
    struct node *comp = compound_statement(f, token);
    if (!comp) {
        // If no compound, this is most probably variable decls
        // This is handled by save points.
        return NULL;
    }

    res = make_node(A_GLUE, decl, comp);
    res = make_node(A_FUNCTION, spec, res);

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
        res = make_node(A_GLUE, res, tmp);
    }
    return res;
}

struct node *parse(struct scanfile *f)
{
    struct token token;
    memset(&token, 0, sizeof(struct token));
    scan(f, &token);
    return translation_unit(f, &token);
}
