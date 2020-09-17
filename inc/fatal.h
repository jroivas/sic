#ifndef __FATAL_H
#define __FATAL_H

#include "sic.h"

#include "parse.h"
#define FATALN(check, _node, ...) { if (check) { \
    if (_node) { \
        /*if (((struct node*)_node)->parent) node_walk(((struct node*)_node)->parent);\
        else */node_walk(_node);\
        fprintf(stderr, "FATAL Compiler error in %s at %d, %s:%d,%d: ", __FILE__, __LINE__, \
        ((struct node*)_node)->filename, ((struct node*)_node)->line, ((struct node*)_node)->linepos);\
    } else { fprintf(stderr, "FATAL Compiler error in %s at %d: ", __FILE__, __LINE__); } \
    fprintf(stderr,  __VA_ARGS__);\
    fprintf(stderr, "\n");\
    stack_trace();\
    exit(EXIT_FAILURE); \
} }

#define FATALF(check, file, ...) do {\
    struct node *n = calloc(1,sizeof(struct node));\
    n->filename =  file->filename;\
    n->line =  file->line;\
    n->linepos =  file->linepos;\
    FATALN(check, n, __VA_ARGS__);\
} while(0);
#define FATAL(check, ...) FATALN(check, NULL, __VA_ARGS__)

#endif
