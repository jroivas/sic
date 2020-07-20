#ifndef __BUFFER_H
#define __BUFFER_H

struct buffer;

struct buffer *buffer_init(void);
int buffer_append(struct buffer *, const char *str);
int buffer_appendln(struct buffer *, const char *str);
int buffer_write(struct buffer *, const char *fmt, ...);
const char *buffer_read(struct buffer *);
void buffer_del(struct buffer *);

char buffer_getch(struct buffer *);
int buffer_putch(struct buffer *buf, char str);
void buffer_seek(struct buffer *, size_t pos);
size_t buffer_size(struct buffer *);
size_t buffer_pos(struct buffer *);
int buffer_eof(struct buffer *);

#endif
