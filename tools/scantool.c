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

    scanfile_open(&f, srcname);
    if (!f.infile)
        ERR("Can't open file: %s", srcname);

    struct token token;
    int cnt = 0;
    do {
        char *tstr;

#if 0
        if (f.savecnt > 10) {
            while (f.savecnt > 0) {
                load_point(&f, &token);
                printf("(%5d,%5d) *** Loaded\n", token.line, token.linepos);
            }
        } if (cnt % 15 == 14) {
            printf("(%5d,%5d) *** Saving\n", token.line, token.linepos);
            save_point(&f, &token);
        } else if (f.savecnt > 0 && cnt % 50 == 42) {
            load_point(&f, &token);
            printf("(%5d,%5d) *** Loaded\n", token.line, token.linepos);
        }
#endif
        scan(&f, &token);
        tstr = token_dump(&token);
        printf("(%5d,%5d) Token: %s (%d)\n",
            token.line, token.linepos, tstr,
            cnt);
        free(tstr);
        cnt++;
    } while (token.token != T_EOF);

    scanfile_close(&f);

    return 0;
}
