/* A write through a pointer to const. */
int f(const char *s)
{
    s[1] = 0;
    return 0;
}
int main(void) { return 0; }
