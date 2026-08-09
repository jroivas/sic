int main()
{
    int a = 1;
    int b = 0;
    int c = 5;
    int d = 0;
    int res = 8;

    if (a && b)
        return 1;

    if (a && !c)
        return 2;

    if (b || !a)
        return 3;

    if (b || !c)
        return 4;

    if (a && (b || !c))
        return 5;

    if (b || d++)
        return 6;

    // Only b should be 0
    if (a && c && res && d && b)
        return 7;

    d = 0;
    /*
     * This is multiline comment.
     * Next should be true, since b == 0
     * and d == 0, but get's pre-incremented
     * before testing
     */
    if (b || ++d)
        res = 0;

    /**/
    return res;
}
