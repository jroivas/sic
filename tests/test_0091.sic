int main()
{
    int f[10];

    /* This is dependent on word size in C */
    if (sizeof(f) != sizeof(int) * 10)
        return 11;

#if 0
    int32 g[10];
    int64 h[10];

    /* In sic this is always the same */
    if (sizeof(g) != 40)
        return 12;
    if (sizeof(h) != 80)
        return 13;
#endif

    return 0;
}
