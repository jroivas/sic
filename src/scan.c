#include "sic.h"
#include "scan.h"
#include <string.h>
#include <ctype.h>

static const char *tokenstr[] = {
    "<INVALID>",
    "+", "-", "*", "/", "%",
    "=",
    "IDENTIFIER",
    "INT_LIT", "DEC_LIT",
    "SEMI", "EOF"
};

void open_input_file(struct scanfile *f, const char *name)
{
    memset(f, 0, sizeof(struct scanfile));
    f->infile = fopen(name, "r");
    f->line = 1;
}

void close_input_file(struct scanfile *f)
{
    fclose(f->infile);
}

const char *token_val_str(enum tokentype t)
{
    FATAL(t >= sizeof(tokenstr) / sizeof (char*),
            "Token string table overflow with %d", t);
    return tokenstr[t];
}

const char *token_str(struct token *t)
{
    return token_val_str(t->token);
}

char *token_dump(struct token *t)
{
    static size_t MAX_LEN = 128;
    char *tmp = calloc(1, MAX_LEN);
    switch (t->token) {
        case T_INT_LIT:
            snprintf(tmp, MAX_LEN, "%s (%llu)", token_str(t), t->value);
            break;
        case T_DEC_LIT:
            snprintf(tmp, MAX_LEN, "%s (%llu.%llu)", token_str(t), t->value, t->fraction);
            break;
        default:
            snprintf(tmp, MAX_LEN, "%s", token_str(t));
            break;
    }
    return tmp;
}

static int next(struct scanfile *f)
{
    int c;

    if (f->putback) {
        c = f->putback;
        f->putback = 0;
    } else {
        c = fgetc(f->infile);
        if (c == '\n')
            f->line++;
    }

    return c;
}

static int skip(struct scanfile *f)
{
    int c = next(f);

    while (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f')
        c = next(f);

    return c;
}

int accept(struct scanfile *f, struct token *t, enum tokentype token)
{
    if (t->token == token) {
        scan(f, t);
        return 1;
    }
    return 0;
}

int expect(struct scanfile *f, struct token *t, enum tokentype token, const char *expect)
{
    if (accept(f, t, token))
       return 1;

    ERR("Expected %s on line %d", expect, f->line);
    return 0;
}

void semi(struct scanfile *f, struct token *t)
{
    expect(f, t, T_SEMI, ";");
}

static void putback(struct scanfile *f, int c)
{
    f->putback = c;
}

literalnum scan_number(struct scanfile *f, int c)
{
    const char *numbers = "0123456789abcdef";
    int radix = 10;
    char *p;
    int d = 0;
    literalnum res = 0;

    if (c == '0') {
        c = next(f);
        if (c == 'x') {
            radix = 16;
            c = next(f);
        } else {
            radix = 8;
        }
    }

    while ((p = strchr(numbers, tolower(c))) != NULL) {
        d = (int)(p - numbers);
        if (d >= radix)
            ERR("Invalid digit in number: %c, radix %d", c, radix);
        res = res * radix + d;
        c = next(f);
    }
    putback(f, c);

    return res;
}

char *scan_identifier(struct scanfile *f, int c)
{
    char *buf = calloc(1, MAX_STR_LEN);
    char *ptr = buf;
    while (isalpha(c) || isdigit(c) || c == '_') {
        if (ptr - buf - 1 >= MAX_STR_LEN)
            ERR("Identifier too long: %s", buf);
        *ptr = c;
        ptr++;
        c = next(f);
    }
    putback(f, c);
    return buf;
}

int scan(struct scanfile *f, struct token *t)
{
    int c = skip(f);
    int ok = 0;
    memset(t, 0, sizeof(struct token));

    if (f->peek.token != T_INVALID) {
        memcpy(t, &f->peek, sizeof(struct token));
        f->peek.token = T_INVALID;
        return 1;
    }

    switch (c) {
        case EOF:
            t->token = T_EOF;
            return 0;
        case '+':
            t->token = T_PLUS;
            break;
        case '-':
            t->token = T_MINUS;
            break;
        case '*':
            t->token = T_STAR;
            break;
        case '/':
            t->token = T_SLASH;
            break;
        case '%':
            t->token = T_MOD;
            break;
        case '=':
            t->token = T_EQ;
            break;
        case ';':
            t->token = T_SEMI;
            break;
        default:
            if (isdigit(c)) {
                t->token = T_INT_LIT;
                t->value = scan_number(f, c);
                c = next(f);
                ok = 1;
            }
            if (c == '.') {
                c = next(f);
                t->token = T_DEC_LIT;
                t->fraction = scan_number(f, c);
                ok = 1;
            } else if (!ok && (isalpha(c) || c == '_')) {
                t->value_string = scan_identifier(f, c);
                t->token = T_IDENTIFIER;
                ok = 1;
            } else {
                putback(f, c);
            }
            if (!ok)
                ERR("Invalid token: %c", c);
    }
    return 1;
}

int peek(struct scanfile *f, struct token **t)
{
    int res = scan(f, &f->peek);
    *t = &f->peek;
    return res;
}
