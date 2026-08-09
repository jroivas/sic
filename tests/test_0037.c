int main()
{
    int a = 5;
    int b;

    b = a > 1 ? 1 : 0;
    if (b != 1)
        return 1;

    b = a < 5 ? 1 : 0;
    if (b != 0)
        return 2;

    if ((a >= 5 ? 6 : 4 == 4) != 6)
        return 3;

    if ((a >= 6 ? 6 : 4 == 4) != 1)
        return 4;

    if ((a >= 5 ? 6 : 4) == 4)
        return 5;

    // This evaluates to 6 so should return 0
    if (a >= 5 ? 6 : 4 == 4)
        return 0;

    return 6;
}
