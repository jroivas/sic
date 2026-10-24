// __builtin_trap() ends the program with SIGILL (it was an unknown function).
int main(void) { __builtin_trap(); return 0; }
