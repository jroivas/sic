int main()
{
    int a = 1;
    int b = 10;
    unsigned int c = 10;
    double d = 5.0;
    double e = 5.0;
    int res = 0;

    if (a > b)
        return 1;
    if (a >= b)
        return 2;
    if (b < a)
        return 3;
    if (b <= a)
        return 4;

    if (b > a)
        res += 1;
    if (b >= a)
        res += 1;
    if (a < b)
        res += 1;
    if (a <= b)
        res += 1;

    a = 10;
    if (a < b)
        return 5;
    if (a > b)
        return 6;
    if (a <= b)
        res += 1;
    if (a >= b)
        res += 1;

    if (c < b)
        return 7;
    if (c > b)
        return 8;
    if (c <= b)
        res += 1;
    if (c >= b)
        res += 1;


    if (d < e)
        return 9;
    if (d > e)
        return 10;
    if (d <= e)
        res += 1;
    if (d >= e)
        res += 1;

    if (res != 10)
        return 11;

    if (1.5 + 1.5 != 3.0)
        return 12;

    return 0;
}
