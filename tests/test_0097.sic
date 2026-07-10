#include <time.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    int res;
    struct timespec ts;

    res = timespec_get(&ts, TIME_MONOTONIC);
    printf("TIME sec: %lu nsec: %lu\n", ts.tv_sec, ts.tv_nsec);
    return 0;
}
