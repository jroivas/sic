int main()
{
    /* This is not legal */
#if 0
    int a = b = c = 4;
#else
    int a, b, c;

    a = b = c = 4;
#endif

    if (a != 4)
        return 1;
    if (b != 4)
        return 2;
    if (c != 4)
        return 3;

    c = a = b = 9;
    if (a != 9)
        return 4;
    if (b != 9)
        return 5;
    if (c != 9)
        return 6;

    return 0;
}
