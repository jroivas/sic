/* This is originally following assert test, but ran with cpp manually and cleaned up:

#include <assert.h>
#include <stddef.h>

int main()
{
    int a;
    double b;
    char *p;

    assert(a == 0);
    assert(b == 0.0);
    assert(p == NULL);
}
*/
extern void __assert_fail (const char *__assertion, const char *__file,
      unsigned int __line, const char *__function);

int main()
{
    int a;
    double b;
    char *p;

    ((a == 0) ? (void) (0) :__assert_fail ("a == 0", "<stdin>", 10, __PRETTY_FUNCTION__));
    ((b == 0.0) ? (void) (0) : __assert_fail ("b == 0.0", "<stdin>", 11, __PRETTY_FUNCTION__));
    ((p == ((void*)0)) ? (void) (0) : __assert_fail ("p == NULL", "<stdin>", 12, __PRETTY_FUNCTION__));
}
