#include <stddef.h>

int getval(int *val)
{
    if (val == NULL)
        return 0;
    return *val;
}

void tst(void)
{
    int a = 9;
}

int voidptr(void *ptr)
{
    int *v = (int *)ptr;
    if (v == NULL)
        return 0;
    return *v;
}

int main()
{
    int a = 42;
    int *b = &a;
    int c = 5;
    int d;

    if (getval(b) != 42)
        return 1;

    b = &c;
    if (getval(b) != 5)
        return 2;

    tst();

    if (a != 42)
        return 3;

    d = voidptr((void*)b);
    if (c != 5)
        return 4;

    if (getval(b) != 5)
        return 5;

    c = 6;
    if (c == d)
        return 6;

    if (c != *b)
        return 7;

    d = voidptr((void*)b);
    if (c != d)
        return 8;

    d = voidptr((void*)&a);
    if (d != 42)
        return 9;

    return 0;
}
