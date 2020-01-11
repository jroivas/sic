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

Reason is to avoid hard to debug undefined behaviour cases.
Our thesis is, compiler can do good enough (if not optimal) code even with
these rules, and same time prevent unnecessary lost human time.

## Integer overflow

Integer overflow is not undefined behaviour.
Instead these rules apply:

- By default signed and unsigned overflow causes wrap around
- For example: unsigned 8 bit integer `255` plus one becomes `0`
- For example: signed 8 bit integer `127` plus one becomes `-128`
- Divide by zero results in `0`

There's possibility to relax these checks and make all operations unsafe.
Thus operations must be wrapped inside `unsafe` block:

    unsafe {
        int a = MAX_INT;
        a++;
    }

That would cause exception instead of becoming MIN_INT.
Only way to guard and prevent exception inside `unsafe` block is to
enclose operation into `overflow` keyword.
The usage of `overflow` is not limited to `unsafe` blocks
and it can be used to detect overflow situations.

Example:

    int main()
    {
        int a = MAX_INT - 5;

        unsafe {
            while (a > MAX_INT - 10 || a < 5) {
                if (overflow { a++ }) {
                    a = 0;
                }
            }
        }

        return 0;
    }

Without `overflow` keyword execution of program would be
ended into an exception. Now it just iterates first from
MAX_INT - 5 to MAX_INT, then assings a = 0, and continues
iteration until 5.

However this example is perfectly valid:

    int main()
    {
        int a = MAX_INT - 5;

        while (a > MAX_INT - 10 || a < 5) {
            a++;
        }

        return 0;
    }

That would turn from MAX_INT to MIN_INT, and then continue
until would reach 5. However on functionality way it's not
 same as first example.
Thus most logical way to use `overflow` is just:

    int main()
    {
        int a = MAX_INT - 5;

        while (a > MAX_INT - 10 || a < 5) {
            if (overflow { a++ }) {
                a = 0;
            }
        }

        return 0;
    }


On case of overflow no values are changed.
Thus let's consider this example:

    int main()
    {
        int a = MAX_INT;
        int b = 0;

        unsafe {
            overflow { a++ };
            // Value of a is unchanged, so it's still MAX_INT
            int c = overflow {
                b = 1;
                a += 10; // This will overflow and
                         // break out from overflow block
                b = 2;
                a += 20;
                b = 3;
                a += 30;
                b = 4;
            };
        }

        assert(a == MAX_INT);
        assert(b == 1);

        return c;
    }

That program would exit with error code,
but would not fail at any point.
Without `overflow` keywords execution would be ended at first `a++`.
Also, here we first time take return value `overflow` and assign it into
and integer. Earlier example in case of `if` works same way.
So `overflow` return `0` in case of success, and `1` if overflow was detected.

# Integer sizes

Traditionally in C the size of `int` may be different according the system where it's compiled into.
We specify size of all types explicitly:

- 8 bits: char == unsigned char
- 8 bits: byte and unsigned byte
- 16 bits: short and unsigned short
- 32 bits: int and unsigned int
- 64 bits: long and unsigned long
- 64 bits: long long and unsigned long long

All chars are unsigned, and signed char does not exists. Value is always between 0 - 255.
Instead byte is signed in range -128 - 127 and unsigned byte matches char.

On top of that we have specific bit size ints:

- 8 bits: int8, uint8
- 16 bits: int16, uint16
- 32 bits: int32, uint32
- 64 bits: int64, uint64
- 128 bits: int128, uint128

Extending to bigger types is trivial, if there comes hardware support.

# Built-in fixed point

Floating point is great, but sometimes more exact representation is needed.
Solution if fixed point math, and it improves precision, for example,
on financial calculations.

# Built-in string

We have built in string type, which creates optimal code to target.
However null terminated strings are of course still supported...

Built-in strings supports natively UTF-8.

Conversion to traditional null terminated can be performed easily,
with certain constraints.

# Empty brackets pointer

This is not valid:

    char test[];


# Scopes and automatic release

We borrow `new` keyword from C++ to create new "objects".
However they're not fat objects like in C++, but structs which can have
constructor and destructor:

    struct test {
        test() {
            val = malloc(10);
        }
        ~test() {
            free(val);
        }
        int *val;
    }


These looks like C++ classes, but we do not support direclty other member methods
than the constructor and destructor. Like in C++ they're automatically called on creation
and when getting out of scope:


    void test()
    {
        struct test a; // constructor of 'test' for 'a' is called here
        struct test *b = new struct test; // constructor of 'test' for 'b' is called here

        // destructor of 'test' for 'a' called here, and 'a' is released,
        // however 'b' is not released since it's not getting ouf of scope
    }


# Assignment and equals

There's make clear rules for assignment and equals operators,
which is not always the case in C.

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

# Dangling else

Force curly braces for non-trivial if-statement.

# Imports

Current C-preprocessor mechanism of include, headers and main units works
but has it's drawbacks.

Add support for real modules, which can be imported.

Example of module:

    module test;

    int double_int(int x)
    {
        return 2 * x;
    }

    int power(int x)
    {
        return x * x;
    }


Everything is by default exported, unless defined as static.
Difference from C headers is, that implementation is not exported,
but only the definitions.

To use module:

    import test;

    void main()
    {
        printf("%d\n", test.double_int(5));
        printf("%d\n", test.power(5));
    }

Not also, that exported symbols are on module's namespace.
Import can be overridden with preprocessor, specific import or with rename:

    // Imports only double_int from test and specifies it as "double_int" here
    import test.double_int;
    // Imports power from test, but renames it to "my_power"
    import test.power as my_power;
    // Module "test" is NOT imported, only those two symbols from it

    void main()
    {
        printf("%d\n", double_int(5));
        printf("%d\n", my_power(5));
    }

Idea of modules is to be separate compile units, which can be tested and exported separately.
Modules could be described as libraries.
For C compatibility normal header files are autogenerated from module.
On that case, module usage would be (in C):

    #include "module_test.h"

    void main()
    {
        printf("%d\n", test_double_int(5));
        printf("%d\n", test_power(5));
    }

Module can spread into multiple compile units.
Files in a module must be in one folder to be included.
Headers and other files can be included still with preprocessor `#include`.

When compiling a module, it produces these outputs:

- [module\_name]\_[file\_name].o
- [module\_name].a
- module\_[module\_name].h
- module\_[module\_name].def

# Switch - case

One problematic construction is `switch` and it's `case`.
Biggest problem is the fallthrough in case of missing break.

We're breaking `switch` and making it opposite.
Default is to break after case, and fallthrough
must be specificly stated:

    int test(int x)
    {
        int r = 0;
        switch (x) {
            case 1: r = 111;
            case 2: r = 222;
            case 3: r = 333;
            case 4: r = 444;
            case 5: r = 555;
            case 6: fallthrough;
            case 7: fallthrough;
            case 8: r = 678;
            case 9: r = 999;
            default: r = 0;
        }
        return r;
    }

On this example all other cases break, except 6 and 7.
So instead of `break` one must state `fallthrough`.
Having break is not a fault, but fallthrough case is a breaking change.


# Rotate and shift

Original C has only shift left and right operators, but missing rotate,
even thought there's instructions for it on some CPU's, and it's widely used.

Introducing rotate left `<<<` and rotate right `>>>` operators, we extend support for it.

Example:

    int main()
    {
        unsigned int a = 0x12345678;
        printf("%x\n", a <<< 8);
    }

That would print out `0x34567812`.

Shift cases are cleared:

- Right shift case
  * Unsigned fills always zero
  * Signed fills always sign bit
- Shift count can be anything
  * If overflow result is in most cases zero, except if signed, it's filled with sign bit
  * If count is zero or negative, value is not shifted at all.

Examples:

    int main()
    {
        unsigned int a = 0x12345678;
        int b = -88888888;
        printf("%x\n", a << 100);
        printf("%x\n", a << -1);
        printf("%x\n", b >> 0);
        printf("%x\n", b >> 16);
        printf("%x\n", b >> 32);
    }

Results would be: `0`, `0x12345678`, `0xfab3a9c8`, `0xfffffab3`, `0xffffffff`.
