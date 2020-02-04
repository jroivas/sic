#include "test.h"
#include "buffer.h"
#include <string.h>

int test1()
{
    struct buffer *b = buffer_init();

    ASSERT(b);

    buffer_del(b);
    return 0;
}

int test2()
{
    struct buffer *b = buffer_init();

    ASSERT(b);

    buffer_append(b, "test1");
    buffer_append(b, "test2");
    buffer_append(b, "3");

    ASSERT(strcmp(buffer_read(b), "test1test23") == 0);

    buffer_del(b);
    return 0;
}

int test3()
{
    struct buffer *b = buffer_init();

    ASSERT(b);

    buffer_appendln(b, "test1");
    buffer_appendln(b, "test2");
    buffer_append(b, "4");
    buffer_appendln(b, "3");

    ASSERT(strcmp(buffer_read(b), "test1\ntest2\n43\n") == 0);

    buffer_del(b);
    return 0;
}

int test_buffer()
{
    TEST(test1);
    TEST(test2);
    TEST(test3);

    return 0;
}
