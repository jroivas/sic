#include "test.h"
#include "scan.h"
#include <string.h>

static int test1()
{
    ASSERT(strcmp(token_val_str(T_EOF), "EOF") == 0);
}

int test_scan()
{
    TEST(test1);

    return 0;
}
