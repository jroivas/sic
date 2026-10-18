/* Regression: __attribute__((destructor)) was ignored (only constructor ran).
   The destructor runs after main returns; _exit(42) there sets the status. */
#include <unistd.h>

static int ready;

__attribute__((constructor)) static void up(void) { ready = 1; }
__attribute__((destructor)) static void down(void) { if (ready) _exit(42); }

int main(void) { return 0; }
