int main()
{
    int a = -1;
    int *b = &a;
    unsigned long c;
    double d;

    c = (unsigned long)a;
    c = (unsigned long)b;
    a = (int)c;

    a = -1;
    if (a != 0xFFFFFFFF)
        return 1;
    c = (unsigned long)a;
    if (c != 0xFFFFFFFFFFFFFFFF)
        return 2;

    d = (double)c;
    d = (double)a;

    if (d != -1.0)
        return 3;

    c = (unsigned long)d;
    if (c != 0xFFFFFFFFFFFFFFFF)
        return 4;
    a = (int)d;

    return 0;
}
