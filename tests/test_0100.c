struct test1 {
    char a;
};

int main()
{
    if (sizeof(struct test1) != 1)
        return 1;

    return 0;
}

