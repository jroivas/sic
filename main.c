#include <stdio.h>
#include <string.h>
#include "sic.h"
#include "scan.h"
#include "parse.h"
#include "cg.h"
#include "str.h"

static void usage(char *cname)
{
    printf("Usage: %s infile.sic\n", cname);
}

int main(int argc, char **argv)
{
    int res = 0;
    struct scanfile f;
    struct node *node;
    FILE *outfile = NULL;
    char *outname = NULL;
    const char *srcname = NULL;
    int i;
    int dump_tree = 0;

    if (argc <= 1) {
        usage(argv[0]);
        return 1;
    }
    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "-o") == 0) {
                i++;
                FATAL(i >= argc, "Missing output file name!");
                outname = argv[i];
            } else if (strcmp(argv[i], "--dump-tree") == 0) {
                dump_tree = 1;
            } else {
                ERR("Invalid argument: %s\n", argv[i]);
            }
        } else {
            FATAL(srcname, "Input file already defined!");
            srcname = argv[i];
        }
    }

    open_input_file(&f, srcname);
    if (!f.infile)
        ERR("Can't open file: %s", srcname);

    node = parse(&f);
    close_input_file(&f);
    if (dump_tree)
        node_walk(node);

    if (!outname) {
        outname = calloc(1, 256);
        snprintf(outname, 255, "%s.ir", srcname);
        outname[255] = 0;
    }
    outfile = fopen(outname, "w+");
    codegen(outfile, node);
    fclose(outfile);

    node_free(node);
    str_free_all();

    return res;
}
