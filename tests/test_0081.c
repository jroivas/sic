struct tst1
{
    int b;
};

struct tst2
{
    int a;
};

extern struct tst2 *tst(struct tst1 *a, struct tst2 *b);

int main()
{
    struct tst1 a;
    struct tst2 b;
    struct tst2 *r;

    r = tst(&a, &b);
    if (r == (void*)0)
        return 1;

    return 0;
}

struct tst2 *tst(struct tst1 *a, struct tst2 *b)
{
    return b;
}
