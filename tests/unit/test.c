#include <stdio.h>

extern int test_buffer();
extern int test_scan();
extern int test_parse();

#define TEST(X) if (X) { ++failed; printf("Test failed: %s\n", #X); }

int main()
{
    int failed = 0;

    TEST(test_buffer());
    TEST(test_scan());
    TEST(test_parse());

    if (!failed)
        printf("Tests passed\n");
    return failed;
}

