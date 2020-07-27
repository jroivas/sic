int printf(const char *fmt, ...);

int main()
{
    long double a = 5.0;
    float b = 4.0;
    double c = 2.0;

    if (sizeof(a) != 16)
        return 1;
    if (sizeof(long double) != 16)
        return 2;
    if (a != 5.0)
        return 3;

    if (sizeof(b) != 4)
        return 4;
    if (sizeof(float) != 4)
        return 5;
    if (b != 4.0)
        return 6;

    if (sizeof(c) != 8)
        return 7;
    if (sizeof(double) != 8)
        return 8;
    if (c != 2.0)
        return 9;

    return 0;
}
