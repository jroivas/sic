#include "sic.h"
#include "scan.h"
#include <string.h>
#include <ctype.h>

static const char *tokenstr[] = {
    "<INVALID>",
    "+", "-", "*", "/", "%",
    "<<", ">>", "|", "^",
    "++", "--",
    "&&", "||",
    "<", ">",
    "=",
    "==",
    "!",
    "!=",
    "KEYWORD",
    "IDENTIFIER",
    "INT_LIT", "DEC_LIT",
    "STR_LIT",
    "(", ")",
    "{", "}",
    ",", "SEMI",
    "&",
    "NULL",
    "~",
    "?",
    ":",
    "EOF"
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
        case T_IDENTIFIER:
            snprintf(tmp, MAX_LEN, "%s (%s)", token_str(t), t->value_string);
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

    //printf("Scanned: %c (%d)\n", c, c);
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

int accept_keyword(struct scanfile *f, struct token *t, enum keyword_type keyword)
{
    if (t->token == T_KEYWORD && t->keyword == keyword) {
        scan(f, t);
        return 1;
    }
    return 0;
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

char *scan_string(struct scanfile *f, int c, char end_char)
{
    char *buf = calloc(1, MAX_STR_LEN);
    char *ptr = buf;
    int escape = 0;

    while (ptr - buf < MAX_STR_LEN - 2) {
        *ptr = c;
        ptr++;
        c = next(f);
        if (escape && c == end_char)
            ;
        else if (c == end_char)
            break;
        // TODO: Check escape validity
        escape = (!escape && c == '\\');
    }
    return buf;
}

char *scan_identifier(struct scanfile *f, int c)
{
    char *buf = calloc(1, MAX_STR_LEN);
    char *ptr = buf;
    while (isalpha(c) || isdigit(c) || c == '_') {
        if (ptr - buf >= MAX_STR_LEN - 1)
            ERR("Identifier too long: %s", buf);
        *ptr = c;
        ptr++;
        c = next(f);
    }
    putback(f, c);
    return buf;
}

int keyword(struct token *t)
{
    const char *v = t->value_string;
    int res = 0;

    if (!v)
        return res;

    if (strcmp(v, "return") == 0) {
        res = 1;
        t->keyword = K_RETURN;
    } else if (strcmp(v, "if") == 0) {
        res = 1;
        t->keyword = K_IF;
    } else if (strcmp(v, "else") == 0) {
        res = 1;
        t->keyword = K_ELSE;
    }

    return res;
}

int scan(struct scanfile *f, struct token *t)
{
    int c = skip(f);
    int ok = 0;
    memset(t, 0, sizeof(struct token));

    switch (c) {
        case EOF:
            t->token = T_EOF;
            return 0;
        case '+':
            t->token = T_PLUS;
            c = next(f);
            if (c == '+')
                t->token = T_PLUSPLUS;
            else
                putback(f, c);
            break;
        case '-':
            t->token = T_MINUS;
            c = next(f);
            if (c == '-')
                t->token = T_MINUSMINUS;
            else
                putback(f, c);
            break;
        case '*':
            t->token = T_STAR;
            break;
        case '&':
            t->token = T_AMP;
            c = next(f);
            if (c == '&')
                t->token = T_LOG_AND;
            else
                putback(f, c);
            break;
        case '/':
            t->token = T_SLASH;
            c = next(f);
            if (c == '/') {
                // This is comment until end of line
                while (c != '\n' && c != '\r') {
                    c = next(f);
                }
                // Scan next
                return scan(f, t);
            } else if (c == '*') {
                do {
                    int trigger;

                    c = next(f);
                    trigger = c == '*';
                    if (trigger) {
                        c = next(f);
                        if (c == '/')
                            break;
                    }
                } while (c != EOF);
                return scan(f, t);
            } else
                putback(f, c);
            break;
        case '%':
            t->token = T_MOD;
            break;
        case '=':
            t->token = T_EQ;
            c = next(f);
            if (c == '=')
               t->token = T_EQ_EQ;
            else
                putback(f, c);
            break;
        case '!':
            t->token = T_EXCLAM;
            c = next(f);
            if (c == '=')
               t->token = T_EQ_NE;
            else
                putback(f, c);
            break;
        case '|':
            t->token = T_OR;
            c = next(f);
            if (c == '|')
                t->token = T_LOG_OR;
            else
                putback(f, c);
            break;
        case '^':
            t->token = T_XOR;
            break;
        case ';':
            t->token = T_SEMI;
            break;
        case ',':
            t->token = T_COMMA;
            break;
        case '(':
            t->token = T_ROUND_OPEN;
            break;
        case ')':
            t->token = T_ROUND_CLOSE;
            break;
        case '{':
            t->token = T_CURLY_OPEN;
            break;
        case '}':
            t->token = T_CURLY_CLOSE;
            break;
        case '~':
            t->token = T_TILDE;
            break;
        case '?':
            t->token = T_QUESTION;
            break;
        case ':':
            t->token = T_COLON;
            break;
        case '<':
            t->token = T_LT;
            c = next(f);
            if (c == '<')
                t->token = T_LEFT;
            else
                putback(f, c);
            break;
        case '>':
            t->token = T_GT;
            c = next(f);
            if (c == '>')
                t->token = T_RIGHT;
            else
                putback(f, c);
            break;
        case '"':
            c = next(f);
            t->token = T_STR_LIT;
            t->value_string = scan_string(f, c, '"');
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
                if (keyword(t))
                    t->token = T_KEYWORD;
                else if (strcmp(t->value_string, "NULL") == 0)
                    t->token = T_NULL;
                else
                    t->token = T_IDENTIFIER;
                ok = 1;
            } else {
                putback(f, c);
            }
            if (!ok)
                ERR("Invalid token: %c", c);
    }
    //printf("*** Scan res: %s\n", token_dump(t));
    return 1;
}

void save_point(struct scanfile *f, struct token *t)
{
    FATAL(f->savecnt + 1 >= SCANFILE_SAVE_MAX,
            "Maximum save points reached");
    memcpy(&f->save_token[f->savecnt], t, sizeof(*t));
    long pos = ftell(f->infile);
    // If we have putback need to decrement pos.
    if (f->putback && pos)
        pos--;

    f->save_point[f->savecnt++] = pos;
}

void remove_save_point(struct scanfile *f, struct token *t)
{
    FATAL(!f->savecnt, "No save points to remove");
    (void)t;
    --f->savecnt;
}

void load_point(struct scanfile *f, struct token *t)
{
    FATAL(!f->savecnt, "No save points to load");
    f->putback = 0;
    fseek(f->infile, f->save_point[--f->savecnt], SEEK_SET);
    memcpy(t, &f->save_token[f->savecnt], sizeof(*t));
}
