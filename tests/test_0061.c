int main()
{
    int i;

    for (i = 0; i < 10; i++) {
        if (i == 5)
            break;
    }

    if (i != 5)
        return 1;

    int j;
    for (i = 0; i < 10; i++) {
        if (i == 5)
            continue;
        j++;
    }

    if (i != 10)
        return 2;

    if (j != 9)
        return 3;

    int sum;
    for (i = 0; i < 5; i++) {
        if (i == 2)
            continue;
        for (j = 0; j < 3; j++) {
            if (j == 2)
                break;
            sum++;
        }
    }
    if (sum != 8)
        return 4;

    i = 0;
    for (;;) {
        i++;
        if (i > 41)
            break;
    }

    if (i != 42)
        return 2;

    goto skip;

    i = 123;

skip:

    if (i == 123)
        return 3;
    if (i != 42)
        return 4;

    i = 5;
    j = 0;
retry:
    j++;
    if (--i)
        goto retry;

    if (i != 0)
        return 5;
    if (j != 5)
        return 6;

    return 0;
}
