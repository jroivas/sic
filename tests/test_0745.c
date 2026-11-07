// An ordering comparison of complex values is an error.
int main(void)
{
    _Complex double a = 1.0, b = 2.0;
    return a < b;
}
