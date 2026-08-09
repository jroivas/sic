int number = 5;
double numd = 6.0;

int main()
{
    int val = 9;
    double vald = 9.0;

    if (val + number != 14)
        return 1;

    if (val + 10 + number != 24)
        return 2;

    if (val + number + 11 != 25)
        return 3;

    number = 6;
    val = 10;

    if (val + number != 16)
        return 4;

    if (val + 10 + number != 26)
        return 5;

    if (vald + numd != 15.0)
        return 6;

    if (vald != 9.0)
        return 7;

    if (numd != 6.0)
        return 8;

    return 0;
}
