int main()
{
    int res = 0;

    do {
        res++;
    } while (0);
    if (res != 1)
        return 1;

    do {
        res++;
    } while (res < 5);
    if (res != 5)
        return 2;

    int i = 0;
    res = 0;
    do {
        i++;
        res += i;
    } while (i < 10);

    if (res != 55)
        return 3;
    if (i != 10)
        return 4;

    return 0;
}
