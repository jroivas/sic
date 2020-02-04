#ifndef __BUFFER_H
#define __BUFFER_H

struct buffer;

struct buffer *buffer_init(void);
int buffer_append(struct buffer *, const char *str);
int buffer_appendln(struct buffer *, const char *str);
const char *buffer_read(struct buffer *);
void buffer_del(struct buffer *);

#endif
