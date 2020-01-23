#include <stdio.h>
#include "sic.h"
#include "scan.h"
#include "parse.h"

static void usage(char *cname)
{
    printf("Usage: %s infile.sic\n", cname);
}

int main(int argc, char **argv)
{
    int res = 0;
    struct scanfile f;
    struct token token;
    struct node *node;

    if (argc <= 1) {
        usage(argv[0]);
        return 1;
    }

    f.infile = fopen(argv[1], "r");
    f.line = 0;
    f.putback = 0;
    if (!f.infile)
        ERR("Can't open file: %s", argv[1]);

    if (scan(&f, &token)) {
        node = expression(&f, &token);
        (void)node;
    }

    return res;
}
