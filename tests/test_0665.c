// A label declared by __label__ is local to its block: a goto outside does not
// see it. (sic accepted any goto to an undefined label, and fell through.)
int main(void) {
    { __label__ in; in: ; }
    goto in;
    return 0;
}
