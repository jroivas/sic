int globalVar = 10;
int globalVar2 = 42;

int main()
{
    if (globalVar != 10)
        return 1;
    if (globalVar2 != 42)
        return 2;
    return 0;
}
