#include <stdio.h>
#include <string.h>
#include "sic.h"
#include "scan.h"
#include "parse.h"
#include "cg.h"

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
    FILE *outfile;
    char outname[256];

    if (argc <= 1) {
        usage(argv[0]);
        return 1;
    }

    open_input_file(&f, argv[1]);
    if (!f.infile)
        ERR("Can't open file: %s", argv[1]);

    if (!scan(&f, &token))
        ERR("Error while parsing %s", argv[1]);

    node = parse(&f, &token);
    close_input_file(&f);
    node_walk(node);

    snprintf(outname, 255, "%s.ir", argv[1]);
    outname[255] = 0;
    outfile = fopen(outname, "w+");
    codegen(outfile, node);
    fclose(outfile);

    return res;
}
