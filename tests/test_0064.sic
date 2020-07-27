typedef int VALUE;
typedef long VALUE2;

int main()
{
    VALUE a;
    VALUE2 b;

    a = 5;
    b = 7;
    if (a != 5)
        return 1;
    if (sizeof(a) != 4)
        return 2;
    if (sizeof(VALUE) != 4)
        return 3;
    if (sizeof(VALUE*) != 8)
        return 4;

    if (b != 7)
        return 5;
    if (sizeof(b) != 8)
        return 6;
    if (sizeof(VALUE2) != 8)
        return 7;
    if (sizeof(VALUE2*) != 8)
        return 8;

    return 0;
}
