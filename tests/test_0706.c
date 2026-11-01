// A member's array length must be a constant: it used to become 0 without a word.
int n;
struct s { int a[n]; int b; };
struct s v;
int main(void) { return v.b; }
