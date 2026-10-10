/* `sizeof` of an undeclared name is an error (it silently inferred `int` and
 * yielded 4, like gcc's "'NoSuchThing' undeclared" not being reported). */
int main(void) { return (int)sizeof(NoSuchThing); }
