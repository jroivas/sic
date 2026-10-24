/* `-D VAL=7` and `-I /usr/include` given as separate arguments (see .flags): the
   values went to the link as input files ("Failed to mmap input file"). */
#include <stdio.h>
int main(void) { return VAL * 6; }
