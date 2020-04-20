#include "test.h"
#include "parse.h"
#include <string.h>

static int test1()
{
    ASSERT(strcmp(node_type_str(A_LIST), "LIST") == 0);
}

int test_parse()
{
    TEST(test1);

    return 0;
}

