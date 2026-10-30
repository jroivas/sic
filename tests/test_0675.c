// `&&label` of a label that does not exist.
int main(void)
{
	void *p = &&nope;

	goto *p;
}
