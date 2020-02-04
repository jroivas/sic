#include <stdio.h>

extern int test_buffer();

#define TEST(X) if (X) { ++failed; printf("Test failed: %s\n", #X); }

int main()
{
    int failed = 0;

    TEST(test_buffer());

    if (!failed)
        printf("Tests passed\n");
    return failed;
}

