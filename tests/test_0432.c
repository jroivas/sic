/* -Werror turns -Wdiv-by-zero (on by default) into an error. */
int main(int argc, char **argv) { (void)argv; return argc / 0; }
