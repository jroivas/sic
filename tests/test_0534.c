/* -Werror: system headers declare long double functions (strtold, sqrtl),
   but warnings are never reported from system headers. */
#include <stdlib.h>
#include <math.h>
#include <stdio.h>
int main(void) { return (int)sqrt(1764.0); }
