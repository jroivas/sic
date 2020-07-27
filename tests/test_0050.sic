struct values
{
    char a;
    double b;
    unsigned long int c;
    const unsigned long int d;
    int e;
};

extern int printf(const char *msg, ...);

int main()
{
    struct values v;

    v.a = 10;
    v.b = 4.2;
    v.c = 9090;

    if (v.a != 10)
        return 1;

    if (v.b != 4.2)
        return 2;

    if (v.c != 9090)
        return 3;

    if (sizeof(v) != 40)
        return 4;

    if (sizeof(struct values) != 40)
        return 5;

    return 0;
}
