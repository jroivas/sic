typedef __builtin_va_list va_list;

#define va_start(ap, last) __builtin_va_start((ap), (last))
#define va_arg(ap, type) __builtin_va_arg((ap), type)
#define va_end(ap) __builtin_va_end(ap)

int test(int cnt, ...)
{
    va_list tmp;
    int sum = 0;

    va_start(tmp, cnt);
    for (int i = 0; i < cnt;  i++) {
        int val = va_arg(tmp, int);
        sum += val;
    }

    va_end(tmp);

    return sum;
}

int main()
{
    int sum = test(3, 1, 2, 4);
    if (sum != 7)
        return 1;
    return 0;
}
