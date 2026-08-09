struct values
{
    int a;
    char b;
    long c;
};

int main()
{
    struct values v;
    char b;

    v.a = 10;
    b = 20;
    v.b = 20;
    v.c = 30;

    if (v.a != 10)
        return 1;

    if (v.b != 20)
        return 2;

    if (v.c != 30)
        return 3;

    return 0;
}
