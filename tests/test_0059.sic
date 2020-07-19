int printf(char *fmt, ...);

int main()
{
    printf("In file %s\n", __FILE__);
    printf("This is line %d\n", __LINE__);
    if (__LINE__ != 7)
        return 1;

    printf("Now we're at %s:%d, function %s\n", __FILE__, __LINE__, __FUNCTION__);
    if (__LINE__ != 11)
        return 2;

    return 0;
}
