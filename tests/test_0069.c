int printf(const char *fmt, ...);

typedef union test_2 {
    double a;
    long b;
} test;

union test_t {
    double a;
    long b;
};

int main()
{
    union test_t a;
    test b;

    a.a = 1.1;
    if (a.b != 4607632778762754458)
        return 1;

    b.b = 0x4000000000000000;
    if (b.a != 2.0)
        return 2;

    return 0;
}
