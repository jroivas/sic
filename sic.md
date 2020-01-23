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

## Initialized variables

All variables are initialized to 0 (or logically similar).
This avoids problems with uninitialized variables.

- Integral values to 0
- Floating and fixed point to 0.0
- Pointers to NULL
- Strings to empty string
- Structures to memset(sizeof(struct), 0)

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

Strings support concatenate and substring:

    int main()
    {
        string test = "Hello world!"
        string another = test + " And all others!";

        printf("%s\n", test);
        printf("%s\n", another);
        // Substring, will print "world", open interval
        printf("%s\n", another[6:11]);
    }


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
        putc(c, out);

This is actually:

    while (c = (getc(in) != EOF))
        putc(c, out);

Which is wrong on that case, and code should have been written as:

    while ((c = getc(in)) != EOF)
        putc(c, out);


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
        putc(c, out);
        c = getc(in);
    }

Second solution would cause compiler error if intended that way.

Third option is to keep with what we have, for example `for` statement would be:

    for (char *c = getc(int); c != EOF; c = getc(int))
        putc(c, out);

But we still have our repeated calls to `getc`.

This leads to conclusion, that our solutions so far might not be the best ones.
Better is to mandate usage of braces with assignment operators when using
in evaluation expression. Thus this is fully valid:

    while ((c = getc(in)) != EOF)
        putc(c, out);

This would be valid with braces, if that's what you want:

    while (c = (getc(in) != EOF))
        putc(c, out);

The another case looks bit more stupid with double braces, but tells compiler you really mean it:

    if ((x = y))
        foo();

On that case compiler is allowed to optimize this to:

    x = y;
    foo();

# Dangling else

Force curly braces for non-trivial if-statement.

This is valid:

    if (test)
        do_something();
    else
        do_other();

This would not be:

    if (test)
        if (second_test)
            do_something();
    else
        do_other();

Proper way would be:

    if (test) {
        if (second_test)
            do_something();
    } else
        do_other();

Now it's clear to for which `if`the `else` belongs to.

# Imports

Current C-preprocessor mechanism of include, headers and main units works
but has it's drawbacks.

Add support for real modules, which can be imported.

Example of module:

    module test;

    int meaning = 42;

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
but only definitions of non-static symbols from the module.

To use the module:

    import test;

    void main()
    {
        printf("%d\n", test.double_int(5));
        printf("%d\n", test.power(5));
        printf("%d\n", test.meaning);
    }

Not also that exported symbols are accessible only from module's namespace.
We can import specific symbols from module, or assign a new local identifier to them:

    // Imports only "double_int" from test and specifies it as "double_int" here
    import test.double_int;
    // Imports "power" from test, but renames it to "my_power"
    import test.power as my_power;
    // Module "test" itself is NOT imported, only those two symbols from it

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
Files of the module must be located in one folder,
and it's considered to be different module if files located in different folder.
Headers and other files can be included still with preprocessor `#include`
from outside the module folder.

When compiling a module, it produces these outputs:

- [module\_name]\_[file\_name].o
- [module\_name].a
- module\_[module\_name].h
- module\_[module\_name].def

# Switch - case

One problematic construction is `switch` and it's `case`.
Biggest problem is the fallthrough in case of missing break.

We're breaking `switch` and making it opposite.
Default is to break after each case, and fallthrough
must be specificly stated:

    int test(int x)
    {
        int r = 0;
        int a = 0;
        switch (x) {
            case 1: r = 111; a = 1;
            case 2:
                int tmp = x;
                r = 222;
                a = 1 + tmp;
            case 3: r = 333;
            case 4:
                r = 444;
                a = 2;
            case 5: r = 555;
            case 6: fallthrough;
            case 7: fallthrough;
            case 8: r = 678;
            case 9: r = 999; a = 3;
            default: r = 0;
        }
        return r + a;
    }

On this example all other cases break, except 6 and 7.
So instead of `break` one must state `fallthrough`.
You can imagine automatic `break` just before every new `case` or `default` statement.
Case may contain multiple expressions and span to multiple lines.
It's valid to define variables inside case, unlike in C.
One can imagine automatic curly braces after the colon, until next `case`,
with automatic `break` added.

Compared to C this is a breaking change.


# Rotate and shift

Original C has only shift left and right operators, but missing rotate,
even thought there's instructions for it on some CPU's, and it's widely utilized on programs.

Introducing rotate left `<<<` and rotate right `>>>` operators.  Example:

    int main()
    {
        unsigned int a = 0x12345678;
        printf("%x\n", a <<< 8);
    }

That would print out `0x34567812`.

Shifts are exaclty specified:

- Left shift `<<`
  * Always fills zero
- Right shift `>>`
  * Unsigned fills always zero
  * Signed fills always sign bit
- Shift count can be anything
  * In case of overflow result is zero, except if signed, it's filled with sign bit
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

## Arrays and lists

Extend arrays and list handling with helpful sugar. Let's take an example:

    int main()
    {
        int values[5];
        int tail[5];
        string test = "Hello world!"

        for (int i = 0; i < values.size(); i++) {
            values[i] = i;
            tail[i] = i + values.size();
        }

        printf("String: %s, len: %d\n", test, test.length());

        int combined[20] = values + tail;
        // Will print 20, and not 10
        // Contents will be 1..10 and rest zeros
        printf("Combined length: %d\n", combined.length());

        // Will print 10
        printf("Combined2 length: %d\n", (values + tail).length());
    }

## Swap

Support built-in swap operation, which can be compiled to assembly instruction
on target architectures supporting it.
