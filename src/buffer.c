#include "sic.h"
#include "buffer.h"
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

struct buffer {
    char *data;
    size_t size;
};

static const unsigned MAX_FMT_LEN = 4096;

struct buffer *buffer_init(void)
{
    return calloc(1, sizeof(struct buffer));
}

int buffer_append(struct buffer *buf, const char *str)
{
    size_t len = strlen(str);
    size_t newsize = len + buf->size;
    buf->data = realloc(buf->data, newsize + 1);
    memcpy(buf->data + buf->size, str, len);
    buf->size = newsize;
    buf->data[buf->size] = 0;
    return buf->size;
}

int buffer_appendln(struct buffer *buf, const char *str)
{
    int res = buffer_append(buf, str);
    res += buffer_append(buf, "\n");
    return res;
}

int buffer_write(struct buffer *buf, const char *fmt, ...)
{
    char *tmp = calloc(1, MAX_FMT_LEN);
    int cnt = 0;

    va_list argp;
    va_start(argp, fmt);

    cnt = vsnprintf(tmp, MAX_FMT_LEN - 1, fmt, argp);
    FATAL(cnt == MAX_FMT_LEN - 1, "Too long string written to buffer: %d", cnt);
    buffer_append(buf, tmp);
    free(tmp);

    return cnt;
}

const char *buffer_read(struct buffer *buf)
{
    return buf->data ? buf->data : "";
}

void buffer_del(struct buffer *buf)
{
    free(buf);
}
