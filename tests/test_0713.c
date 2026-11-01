// A case label must be a constant; it must not vanish.
int main(int argc, char **argv)
{
	int n = argc;
	switch (argc) { case n: return 1; }
	return 0;
}
