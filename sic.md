# SIC - Slighltly Improved C


# All variables are initialized

All variables are initialized to their type default.

Example:

    int main()
    {
        int a;
        double b;
        char *p;

        assert(a == 0);
        assert(b == 0.0);
        assert(p == NULL);
    }


# Limit undefined behaviour

One of C's optimization strategies is "undefined behaviour"
when copiler may do whatever it wants.

We remove that freedom and try to specify what to do on each of the cases.

Reason is to avoid hard to debug problematic cases.
Our thesis is, compiler can do optimal code even with these rules
but avoid lost programmer time.


# Built-in fixed point

Floating point is great, but sometimes more exact representation is needed.
Solution if fixed point math, and it improves precision on, for example,
financial calculations.

# Built-in string

We have built in string type, which creates optimal code to target.
However null terminated strings are of course still supported...

# Empty brackets pointer

This is not valid:
    char test[];


# Scopes and automatic release

We borrow `new` keyword from C++ to create new "objects".
However they're not fat objects like in C++, but structs which can have
constructor and destructor.

Example:

    struct test {
        test() {
            val = malloc(10);
        }
        ~test() {
            free(val);
        }
        int *val;
    }


Seems like C++ classes, but all allowed method members are constructor and destructor.
As assumed, they're automatically called on creation:


    void test()
    {
        struct test a;
        struct test *b = new struct test;;

        // destructor of a called here, and a is released,
        // but b is not
    }


# Assignment and equals

Making clear rules for assignment and equals operators.

Example in C:

    while (c = getc(in) != EOF)
        putc(c,out);

This is actually:

    while (c = (getc(in) != EOF))
        putc(c,out);

Which is wrong on that case, and code should have been written as:

    while ((c = getc(in)) != EOF)
        putc(c,out);


Same problem applies to:

    if (x = y)
        foo();

Which is just typo, and should be:

    if (x == y)
        foo();

One solution is to disallow assignment in thuth evaluation expressions
like if, while, etc.

First case would then be:

    c = getc(in);
    while (c != EOF) {
        putc(c,out);
        c = getc(in);
    }

Second would cause compiler error if intended that way.
This is, however, way much longer and against the expressiveness of C language.
On the other hand, we have `for` where this would go like:

    if (char *c = getc(int); c != EOF; c = getc(int))
        putc(c,out);

We still have our repeated steps.

This leads to conclusion, that our first solution might not be the best.
Better is to mandate usage of braces with assignment operators when using
in evaluation expression. Thus this is fully valid:

    while ((c = getc(in)) != EOF)
        putc(c,out);

So would be if that's what you want:

    while (c = (getc(in) != EOF))
        putc(c,out);

Other case looks bit more stupid, but tells compiler you really mean it:

    if ((x = y))
        foo();

On that case compiler is allowed to optimize this to:

    x = y;
    foo();

# 
