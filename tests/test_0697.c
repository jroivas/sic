// A global whose initializer is not a constant is an error at the element, not a
// silently zero-filled object.
int f(void);
struct s { int a; long b; int c; };
struct s g = { 1, 2, f() };
