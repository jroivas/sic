int test(int a, int b, int c, int d)
{
    return a + b + c + d;
}

int main()
{
    int res;

    res = test(1, 2, 1, 1);
    if (res != 5)
        return 1;

    res = test(1, 2, 3, 5);
    if (res != 11)
        return 2;

    return 0;
}
