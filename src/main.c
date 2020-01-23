#include <stdio.h>
#include <stdlib.h>
#include "scan.h"

static void usage(char *cname)
{
    printf("Usage: %s infile.sic\n", cname);
}

#define ERR(msg, ...) { \
    fprintf(stderr, "ERROR:");\
    fprintf(stderr, msg, __VA_ARGS__);\
    fprintf(stderr, "\n");\
    exit(1); \
}

int main(int argc, char **argv)
{
    int res = 0;
    struct scanfile f;

    if (argc <= 1) {
        usage(argv[0]);
        return 1;
    }
    
    f.infile = fopen(argv[1], "r");
    f.line = 0;
    f.putback = 0;
    if (!f.infile)
        ERR("Can't open file: %s", argv[1]);

    return res;
}
