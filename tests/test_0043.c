int add5(int n)
{
    return n + 5;
}

int sum(int a, int b)
{
    return a + b + 1;
}

double sumd(double a, double b)
{
    return a + b + 4.2;
}

int main()
{
    int tmp = add5(3);

    if (tmp != 8)
        return 1;

    tmp = add5(1010);
    if (tmp != 1015)
        return 2;

    tmp = sum(3, 6);
    if (tmp != 10)
        return 3;

    double tmpd = sumd(1.1, 2.2);
    if (tmpd != 7.5)
        return 5;

    tmp = sum(26, add5(10));
    if (tmp != 42)
        return 6;

    tmp = sum(add5(add5(16)), add5(10));
    if (tmp != 42)
        return 7;

    return 0;
}
