typedef unsigned long int u64;
typedef u64 other;

int main()
{
    u64 a = 123;
    other b = 42;

    if (a != 123)
        return 1;

    if (b != 42)
        return 2;

    if (sizeof(a) != sizeof(b))
        return 3;

    return 0;
}
