struct tmp {
    int a;
    int b;
};

int main()
{
    struct tmp v;
    struct tmp *vref;
    void *vc;

    v.a = 5;
    vref = &v;

    if (vref->a != 5)
            return 1;

    vc = (void *)vref;

    struct tmp *vcc = (struct tmp*)vc;
    if (vcc->a != 5)
            return 2;

    if (vcc != vref)
            return 3;

    if (vcc != &v)
            return 4;

    vc = (const void*)&vref->b;
    if (vcc->b != 0)
            return 5;

    int *tmp = (int*)vc;
    *tmp = 7;
    if (vcc->b != 7)
            return 6;

    return 0;
}
