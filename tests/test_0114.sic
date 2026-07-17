// Regression: the compiler must predefine the host operating-system macros.
// sic preprocesses with `cpp -undef` (which strips all predefined macros) and
// re-supplies them; OS macros (`__linux__`, `_WIN32`, `__APPLE__`, ...) were
// missing, so `#ifdef __linux__` etc. never matched. At least one must be set.

#include <stdio.h>

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    int detected = 0;

#ifdef __unix__
    printf("__unix__\n");
    detected = 1;
#endif
#ifdef __linux__
    printf("__linux__\n");
    detected = 1;
#endif
#ifdef _WIN32
    printf("_WIN32\n");
    detected = 1;
#endif
#ifdef __OpenBSD__
    printf("__OpenBSD__\n");
    detected = 1;
#endif
#ifdef __sun__
    printf("__sun__\n");
    detected = 1;
#endif
#ifdef __FreeBSD__
    printf("__FreeBSD__\n");
    detected = 1;
#endif
#ifdef __DragonFly__
    printf("__DragonFly__\n");
    detected = 1;
#endif
#ifdef __NetBSD__
    printf("__NetBSD__\n");
    detected = 1;
#endif
#ifdef __APPLE__
    printf("__APPLE__\n");
    detected = 1;
#endif
#if defined(EMSCRIPTEN) || defined(__EMSCRIPTEN__)
    printf("EMSCRIPTEN\n");
    detected = 1;
#endif

    // Fail if no operating system was detected at all.
    return detected ? 0 : 1;
}
