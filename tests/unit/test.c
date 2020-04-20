#include <stdio.h>

extern int test_buffer();
extern int test_scan();

#define TEST(X) if (X) { ++failed; printf("Test failed: %s\n", #X); }

int main()
{
    int failed = 0;

    TEST(test_buffer());
    TEST(test_scan());

    if (!failed)
        printf("Tests passed\n");
    return failed;
}

