int main()
{
    int a = 0x10;
    int b = 0;
    int c = 0x1234;
    int d = 0xaa;

    a |= 0x2;
    b = 0x100 | 0x42;
    c &= 0xff00;
    d ^= 0xff;

    if (a != 0x12)
        return 1;
    if (b != 0x142)
        return 2;
    if (c != 0x1200)
        return 3;
    if (d != 0x55)
        return 4;

    a = a & 0xf0;
    d = d ^ 1;

    if (a != 0x10)
        return 5;
    if (d != 0x54)
        return 6;

    return 0;
}

