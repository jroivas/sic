int main()
{
    int a = 0x40;
    int b = 0;

    a = a | 1 ^ 0x10;
    b ^= (0x4 << 4 | 0x10 | 0x2) ^ 0x10;

    if (a != 0x51)
        return 1;

    if (b != 0x42)
        return b;

    return 0;
}
