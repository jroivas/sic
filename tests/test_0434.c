/* -Werror=shift-count-overflow: a constant shift count >= the promoted width. */
int main(int argc, char **argv) { (void)argv; return argc << 32; }
