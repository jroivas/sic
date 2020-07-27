struct subvalues
{
    int a;
    int b;
};

struct values
{
    int a;
    struct subvalues b;
};

int main()
{
    struct values v;

    v.b.a = 20;
    v.b.b = 30;

    v.a = 10;
    if (v.a != 10)
        return 1;

    if (v.b.a != 20)
        return 2;

    if (v.b.b != 30)
        return 3;

    if (sizeof(v) != 12)
        return 4;

    if (sizeof(v.b) != 8)
        return 5;

    if (sizeof(struct values) != 12)
        return 6;

    if (sizeof(struct subvalues) != 8)
        return 7;

    return 0;
}
