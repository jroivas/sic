#include "buffer.h"
#include <stdlib.h>
#include <string.h>

struct buffer {
    char *data;
    size_t size;
};

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

const char *buffer_read(struct buffer *buf)
{
    return buf->data;
}

void buffer_del(struct buffer *buf)
{
    free(buf);
}
