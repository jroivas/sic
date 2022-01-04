#define _DEFAULT_SOURCE
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "sic.h"
#include "scan.h"
#include "fatal.h"
#include "str.h"

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
    "[", "]",
    ",", "SEMI",
    "&",
    "NULL",
    "~",
    "?",
    ":",
    ".",
    "->",
    "...",
    "EOF"
};

void scanfile_open(struct scanfile *f, const char *name)
{
    memset(f, 0, sizeof(struct scanfile));
    f->infile = fopen(name, "r");
    f->filename = name;
    f->line = 1;
    f->buf = buffer_init();
}

void scanfile_pipe(struct scanfile *f, FILE *pipe, const char *name)
{
    memset(f, 0, sizeof(struct scanfile));
    f->infile = pipe;
    f->filename = name;
    f->line = 1;
    f->pipe = 1;
    f->buf = buffer_init();
}

void scanfile_close(struct scanfile *f)
{
    if (f->buf)
        buffer_del(f->buf);
    if (f->pipe) {
        int res = WEXITSTATUS(pclose(f->infile));
        if (res)
            ERR("Preprocessor error: %d", res);
    } else
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
        case T_KEYWORD:
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

    if (f->linepos == 0)
        memset(f->linebuf, 0, SCANFILE_LINEBUF);
    if (f->putback) {
        c = f->putback;
        f->putback = 0;
    } else {
        if (buffer_size(f->buf) > buffer_pos(f->buf))
            c = buffer_getch(f->buf);
        else {
            c = fgetc(f->infile);
            if (c < 0)
                return c;
            buffer_putch(f->buf, c);
            c = buffer_getch(f->buf);
        }
    }
    if (f->linepos < SCANFILE_LINEBUF)
        f->linebuf[f->linepos] = c;
    f->linepos++;
    f->pos = buffer_pos(f->buf);
    if (c == '\n') {
        f->line++;
        f->linepos = 0;
    }

    //printf("Scanned: %c (%d) at %d@%d\n", c, c, f->line, f->linepos);
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
#if 1
    if (c == '\n') {
        f->line--;
        //ERR("putback line: %s", f->linebuf);
    }
    else if (f->linepos)
        f->linepos--;
#endif
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
    char *buf = str_alloc();
    char *ptr = buf;
    int escape = 0;

    while (c != end_char && ptr - buf < MAX_STR_LEN - 2) {
        *ptr = c;
        ptr++;
        c = next(f);
        if (escape && c == end_char)
            ;
        else if (c == end_char)
            break;
        escape = (!escape && c == '\\');
    }
    return buf;
}

char *scan_identifier(struct scanfile *f, int c)
{
    char *buf = str_alloc();
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
    } else if (strcmp(v, "while") == 0) {
        res = 1;
        t->keyword = K_WHILE;
    } else if (strcmp(v, "do") == 0) {
        res = 1;
        t->keyword = K_DO;
    } else if (strcmp(v, "for") == 0) {
        res = 1;
        t->keyword = K_FOR;
    } else if (strcmp(v, "struct") == 0) {
        res = 1;
        t->keyword = K_STRUCT;
    } else if (strcmp(v, "union") == 0) {
        res = 1;
        t->keyword = K_UNION;
    } else if (strcmp(v, "enum") == 0) {
        res = 1;
        t->keyword = K_ENUM;
    } else if (strcmp(v, "extern") == 0) {
        res = 1;
        t->keyword = K_EXTERN;
    } else if (strcmp(v, "static") == 0) {
        res = 1;
        t->keyword = K_STATIC;
    } else if (strcmp(v, "inline") == 0 || strcmp(v, "__inline__") == 0 || strcmp(v, "__inline") == 0) {
        res = 1;
        t->keyword = K_INLINE;
    } else if (strcmp(v, "break") == 0) {
        res = 1;
        t->keyword = K_BREAK;
    } else if (strcmp(v, "continue") == 0) {
        res = 1;
        t->keyword = K_CONTINUE;
    } else if (strcmp(v, "goto") == 0) {
        res = 1;
        t->keyword = K_GOTO;
    } else if (strcmp(v, "typedef") == 0) {
        res = 1;
        t->keyword = K_TYPEDEF;
    } else if (strcmp(v, "__attribute__") == 0) {
        res = 1;
        t->keyword = K_ATTRIBUTE;
    } else if (strcmp(v, "__extension__") == 0) {
        res = 1;
        t->keyword = K_EXTENSION;
    } else if (strcmp(v, "__asm__") == 0) {
        res = 1;
        t->keyword = K_ASM;
    } else if (strcmp(v, "sizeof") == 0) {
        res = 1;
        t->keyword = K_SIZEOF;
    }

    return res;
}

void token_set(struct scanfile *f, struct token *t, char c)
{
    t->filename = f->filename;
    t->line = f->line;
    t->linepos = f->linepos;
    t->c = c;
    t->linebuf[t->linepos + 1] = 0;
    memcpy(t->linebuf, f->linebuf, SCANFILE_LINEBUF);
}

int scan(struct scanfile *f, struct token *t)
{
    int c = skip(f);
    int ok = 0;

    memset(t, 0, sizeof(struct token));
    token_set(f, t, c);

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
            else if (c == '>')
                t->token = T_PTR_OP;
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
        case '#':
            // This is preprocessor directive, so ignore till end of line
            while (c != '\n' && c != '\r') {
                c = next(f);
            }
            // Scan next
            return scan(f, t);
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
        case '[':
            t->token = T_SQUARE_OPEN;
            break;
        case ']':
            t->token = T_SQUARE_CLOSE;
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
        case '\'':
            c = next(f);
            t->token = T_INT_LIT;
            t->value_string = scan_string(f, c, '\'');
            if (t->value_string) {
                int r = solve_escape(t->value_string);
                if (r >= 0)
                    t->value = r;
            }
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
                if (c == '.') {
                    c = next(f);
                    if (c == '.') {
                       t->token = T_ELLIPSIS;
                    } else
                        ERR("Got only two dots \"..\"");
                } else if (isdigit(c) || c == ' ') {
                    t->token = T_DEC_LIT;
                    t->fraction = scan_number(f, c);
                } else {
                    // Next is not number so just make dot token
                    putback(f, c);
                    t->token = T_DOT;
                }
                ok = 1;
            } else if (!ok && (isalpha(c) || c == '_')) {
                t->value_string = scan_identifier(f, c);
                if (strcmp(t->value_string, "__FUNCTION__") == 0 || strcmp(t->value_string, "__PRETTY_FUNCTION__") == 0) {
                    t->token = T_STR_LIT;
                } else if (strcmp(t->value_string, "__FILE__") == 0) {
                    t->token = T_STR_LIT;
                    t->value_string = (char*)f->filename;
                } else if (strcmp(t->value_string, "__LINE__") == 0) {
                    t->token = T_INT_LIT;
                    t->value = f->line;
                } else if (keyword(t))
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

    //printf("*** Scan res: %s from %d:%d\n", token_dump(t), t->line, t->linepos);
    return 1;
}

void save_point(struct scanfile *f, struct token *t)
{
    FATAL(f->savecnt + 1 >= SCANFILE_SAVE_MAX,
            "Maximum save points reached");
    memcpy(&f->save_token[f->savecnt], t, sizeof(*t));
    long pos = buffer_pos(f->buf);
#if 0
    f->save_token[f->savecnt].line = f->line;
    f->save_token[f->savecnt].linepos = f->linepos;
    f->save_token[f->savecnt].linepos = pos;
#endif
    //long pos = ftell(f->infile);
    // If we have putback need to decrement pos.
    if (f->putback && pos)
        pos--;

#if 0
    printf("* Saved: %d,%d token %s\n", t->line, t->linepos, token_dump(t));
    //stack_trace();
#endif
    f->save_point[f->savecnt++] = pos;
}

void remove_save_point(struct scanfile *f, struct token *t)
{
    FATAL(!f->savecnt, "No save points to remove");
    (void)t;
    --f->savecnt;
#if 0
    struct token *tmp = &f->save_token[f->savecnt];
    printf("Remove: %d,%d from %d,%d token %s\n", tmp->line, tmp->linepos, f->line, f->linepos, token_dump(t));
    //stack_trace();
#endif
}

void __load_point(struct scanfile *f, struct token *t, const char *file, int line)
{
    FATAL(!f->savecnt, "No save points to load");
    f->putback = 0;
    size_t p = buffer_size(f->buf);
    long savepoint = f->save_point[--f->savecnt];

    FATAL(p < savepoint, "Buffer underrun %lu < %ld", p, savepoint);
    buffer_seek(f->buf, savepoint);
    //fseek(f->infile, f->save_point[--f->savecnt], SEEK_SET);
    memcpy(t, &f->save_token[f->savecnt], sizeof(*t));
#if 0
    printf("Loaded: %d,%d from %d,%d token %s (%s:%d)\n", t->line, t->linepos, f->line, f->linepos, token_dump(t), file, line);
    //stack_trace();
#endif
    /*
     * Need to restore these as well in order to keep
     * track of position.
     */
    f->line = t->line;
    f->linepos = t->linepos;
    f->pos = t->pos;
    memcpy(f->linebuf, t->linebuf, SCANFILE_LINEBUF);
}
