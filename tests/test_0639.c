// A false static assertion is an error carrying its message (it used to be
// accepted without being evaluated).
struct big { char x[16]; };
_Static_assert(sizeof(struct big) == 8, "struct big is 8 bytes");

int main(void) { return 0; }
