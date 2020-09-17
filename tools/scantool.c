#include <stdio.h>
#include "sic.h"
#include "scan.h"

int main(int argc, char **argv)
{
    struct scanfile f;
    char *srcname;

    if (argc <= 1) {
        printf("Usage: %s file_to_scan\n", argv[0]);
        return 1;
    }
    srcname = argv[1];

    open_input_file(&f, srcname);
    if (!f.infile)
        ERR("Can't open file: %s", srcname);

    struct token token;
    int saved = 0;
    do {
        char *tstr;
        scan(&f, &token);
        tstr = token_dump(&token);
        printf("(%5d,%5d) Token: %s\n", token.line, token.linepos, tstr);
        free(tstr);
    } while (token.token != T_EOF);

    close_input_file(&f);

    return 0;
}
