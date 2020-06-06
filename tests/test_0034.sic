int main()
{
    int a = 0x12345678;
    int b = 0;

    a &= ~0xff;

    if (a != 0x12345600)
        return 1;

    if (!!b)
        return 2;

    a &= ~0xffff00;
    if (a != 0x12000000)
        return 3;

    return 0;
}
