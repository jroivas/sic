#include <stdio.h>
#include "sic.h"
#include "scan.h"

static void usage(char *cname)
{
    printf("Usage: %s infile.sic\n", cname);
}

int main(int argc, char **argv)
{
    int res = 0;
    struct scanfile f;
    struct token token;

    if (argc <= 1) {
        usage(argv[0]);
        return 1;
    }

    f.infile = fopen(argv[1], "r");
    f.line = 0;
    f.putback = 0;
    if (!f.infile)
        ERR("Can't open file: %s", argv[1]);

    while (scan(&f, &token)) {
        char *val = token_dump(&token);
        printf("Got: %s\n", val);
        free(val);
    }

    return res;
}
