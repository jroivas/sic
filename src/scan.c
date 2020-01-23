#include "sic.h"
#include "scan.h"
#include <string.h>
#include <ctype.h>

static const char *tokenstr[] = {
    "+", "-",
    "INT_LIT", "DEC_LIT"
};

inline const char *token_str(struct token *t)
{
    return tokenstr[t->token];
}

char *token_dump(struct token *t)
{
    static const int MAX_LEN = 128;
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

int scan(struct scanfile *f, struct token *t)
{
    int c = skip(f);
    int ok = 0;
    memset(t, 0, sizeof(struct token));

    switch (c) {
        case EOF:
            return 0;
        case '+':
            t->token = T_PLUS;
            break;
        case '-':
            t->token = T_MINUS;
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
            } else {
                putback(f, c);
            }
            if (!ok)
                ERR("Invalid token: %c", c);
    }
    return 1;
}
