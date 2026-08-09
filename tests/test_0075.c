typedef int myint;

static inline int hello()
{
    return 42;
}

int main()
{
    if (hello() != 42)
        return 1;

    return 0;
}
