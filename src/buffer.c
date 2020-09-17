#include "sic.h"
#include "buffer.h"
#include "fatal.h"
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>


struct buffer {
    char *data;
    size_t size;
    size_t alloc_size;
    size_t pos;
};

static const unsigned BUFFER_EXTEND_SIZE = 256;
static const unsigned MAX_FMT_LEN = 4096;

struct buffer *buffer_init(void)
{
    return calloc(1, sizeof(struct buffer));
}

int buffer_append(struct buffer *buf, const char *str)
{
    size_t len = strlen(str);
    size_t newsize = len + buf->size;

    if (buf->alloc_size < newsize + 1) {
        while (buf->alloc_size < newsize + 1)
            buf->alloc_size += BUFFER_EXTEND_SIZE;

        buf->data = realloc(buf->data, buf->alloc_size);
    }

    memcpy(buf->data + buf->size, str, len);
    buf->size = newsize;
    buf->data[buf->size] = 0;
    return buf->size;
}

int buffer_putch(struct buffer *buf, char str)
{
    size_t len = 1;
    size_t newsize = len + buf->size;

    if (buf->alloc_size < newsize + 1) {
        while (buf->alloc_size < newsize + 1)
            buf->alloc_size += BUFFER_EXTEND_SIZE;

        buf->data = realloc(buf->data, buf->alloc_size);
    }

    *(buf->data + buf->size) = str;
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
    char tmp[MAX_FMT_LEN];
    int cnt = 0;

    va_list argp;
    va_start(argp, fmt);

    cnt = vsnprintf(tmp, MAX_FMT_LEN - 1, fmt, argp);
    FATAL(cnt == MAX_FMT_LEN - 1, "Too long string written to buffer: %d", cnt);
    buffer_append(buf, tmp);
    va_end(argp);

    return cnt;
}

const char *buffer_read(struct buffer *buf)
{
    return buf->data ? buf->data : "";
}

char buffer_getch(struct buffer *buf)
{
    return buf->data[buf->pos++];
}

size_t buffer_size(struct buffer *buf)
{
    return buf->size;
}

size_t buffer_pos(struct buffer *buf)
{
    return buf->pos;
}

void buffer_seek(struct buffer *buf, size_t pos)
{
    buf->pos = pos;
    if (buf->pos > buf->size)
        buf->pos = buf->size;
}

int buffer_eof(struct buffer *buf)
{
    return (buf->pos >= buf->size);
}

void buffer_del(struct buffer *buf)
{
    if (buf->data)
        free(buf->data);
    free(buf);
}
