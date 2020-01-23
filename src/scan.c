#include "scan.h"

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

int scan(struct scanfile *f, struct token *t)
{
    int c = skip(f);

    switch (c) {
        case EOF:
            return 0;
        case '+':
            t->token = T_PLUS;
            break;
        case '-':
            t->token = T_MINUS;
            break;
    }
    return 1;
}
