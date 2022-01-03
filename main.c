#include <stdio.h>
#include <string.h>
#include "sic.h"
#include "scan.h"
#include "fatal.h"
#include "parse.h"
#include "cg.h"
#include "str.h"

static void usage(char *cname)
{
    printf("Usage: %s infile.sic\n", cname);
}

char **add_inc(char **incs, int inc_cnt, char *newinc)
{
    if (!incs)
        incs = calloc(inc_cnt, sizeof(*incs));
    else
        incs = realloc(incs, inc_cnt * sizeof(*incs));
    incs[inc_cnt - 1] = newinc;
    return incs;
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
    char **incs = NULL;
    int inc_cnt = 0;
    int do_preprocess = 1;

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
            } else if (strcmp(argv[i], "-I") == 0) {
                i++;
                FATAL(i >= argc, "Missing include dir");
                inc_cnt++;
                incs = add_inc(incs, inc_cnt, argv[i]);
            } else if (strncmp(argv[i], "-I", 2) == 0) {
                char *tmp = argv[i] + 2;
                inc_cnt++;
                incs = add_inc(incs, inc_cnt, tmp);
            } else if (strcmp(argv[i], "--dump-tree") == 0) {
                dump_tree = 1;
            } else if (strcmp(argv[i], "--no-cpp") == 0) {
                do_preprocess = 0;
            } else {
                ERR("Invalid argument: %s\n", argv[i]);
            }
        } else {
            FATAL(srcname, "Input file already defined!");
            srcname = argv[i];
        }
    }

    FILE *preproc = NULL;
    if (do_preprocess) {
        preproc = preprocess(srcname, incs, inc_cnt);
        if (preproc)
            scanfile_pipe(&f, preproc, srcname);
        else
            scanfile_open(&f, srcname);
    } else
        scanfile_open(&f, srcname);

    if (!f.infile)
        ERR("Can't open file: %s", srcname);

    node = parse(&f);
    parse_end(&f);
    scanfile_close(&f);
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
