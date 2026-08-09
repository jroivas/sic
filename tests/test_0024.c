int main()
{
    int a = 0;
    double b;
    double *b2;
    char *p;
    char *pp;
    int num = 4;

    if (a) {
        num = num + 1;
    } else {
        num = num + 100;
    }

    if (num == 104)
        return 0;

    return 1;
}
