typedef struct test_t {
    int a;
    char b;
    long c;
} test;

struct tmp {
    int a;
};

typedef struct {
    int a;
    char b;
} test2;

int main()
{
    struct test_t a;
    struct tmp c;
    test b;
    test2 e;

    a.a = 5;
    a.b = 99;
    a.c = 8;

    c.a = 1111;

    b.a = 1;
    b.b = 2;
    b.c = 3;

    e.a = 10;
    e.b = 20;

    if (a.a != 5)
        return 1;
    if (a.b != 99)
        return 2;
    if (a.c != 8)
        return 3;

    if (b.a != 1)
        return 4;
    if (b.b != 2)
        return 5;
    if (b.c != 3)
        return 6;

    if (sizeof(a) != 16)
        return 7;
    if (sizeof(b) != 16)
        return 7;
    if (sizeof(test) != 16)
        return 8;

    if (e.a != 10)
        return 9;
    if (e.b != 20)
        return 10;

    return 0;
}
