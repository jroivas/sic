# SIC - Slightly Improved C specification

Slightly Improved C is a programming language that borrows a lot from C,
but is not afraid to introduce breaking changes in order to improve it.

**REMARK** Most of the features described here are only planned, and **NOT** yet implemented.
For now the focus has been implementing more or less standard C compiler.

# Limit undefined behavior

One of C's optimization strategies is "undefined behavior"
when compiler may do whatever it wants.

We remove that freedom and try to specify what to do on each of the cases.

Reason is to avoid hard to debug undefined behavior cases.
Our thesis is, compiler can do good enough code even with
these rules, and same time prevent unnecessary lost human time.

## Initialized variables

All variables are initialized to 0 (or logically similar).
This avoids problems with uninitialized variables.

- Integral values to 0
- Floating and fixed point to 0.0
- Pointers to NULL
- Strings to empty string
- Structures to memset(struct, 0, sizeof(struct))

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

# Integer sizes

Traditionally in C the size of `int` may be different according the system where it's compiled into.
We specify size of all types explicitly:

- 8-32 bits: one unicode character as UTF-8
- 8 bits: byte and unsigned byte
- 16 bits: short and unsigned short
- 32 bits: int and unsigned int
- 64 bits: long and unsigned long
- 64 bits: long long and unsigned long long

All chars are unsigned and may expand to max 4 bytes (UTF-8). Signed char does not exists.
Instead byte is signed in range -128 - 127 and unsigned byte has value between 0 - 255.

On top of that we have specific bit size ints:

- 8 bits: int8, uint8
- 16 bits: int16, uint16
- 32 bits: int32, uint32
- 64 bits: int64, uint64
- 128 bits: int128, uint128

Extending to bigger types is trivial, in case hardware support comes available.
However compiler supports built-in bigint, which allows arbitrary big integers.
These are not any specific bit/byte size, but can grow any size when needed.
This of course has it's performance and storage size cost.
Otherwise bigints can be used like any other integer type:

    int32 a = 12345;
    int64 b = 567890;
    bigint c = 123456789123456789001234567890;

    bigint d = a + b;
    d += c;

In case it's specificly needed there's two types for machine word size:

- isize: signed machine word size (32/64 bits)
- usize: unsigned machine word size (32/64 bits)

These can be used to produce optimal code for the target architecture. Should not be used in portable code.

## Integer overflow

Integer overflow is not undefined behavior.
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
ended with an exception. Now it just iterates first from
MAX_INT - 5 to MAX_INT, then assigns a = 0, and continues
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
same as the first example.
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

That program would exit with error code, but would not fail at any point.
Without `overflow` keywords execution would be ended at first `a++`.
Also, here we first time take return value `overflow` and assign it into
and integer. Earlier example in case of `if` works same way.
So `overflow` return `0` in case of success, and `1` if overflow was detected.

# Built-in fixed point, and extended floats

Floating point is great, but sometimes more exact representation is needed.
Solution if fixed point math, and it improves precision, for example,
on financial calculations.

For float:

- 32 bits: float32, float
- 64 bits: float64, double
- 128 bits: float128

Fixed point precision contains two parts: integral and fraction.
It's possible to select precision for both of them separately.
From integral part one bit is reserved for sign flag.
Syntax for fixed number types is `fixed<a,b>`
where `a` is max meaningful digits for integral part,
and `b` is max meaningful digits for fraction part.

- fixed<2,4>: 2 digits for integral, 4 digits for fraction allowing -99.9999 to 99.9999
- fixed<2,2>: 2 digits for integral, 2 digits for fraction allowing -99.99 to 99.99
- fixed<10,1>: 10 digits for integral, 1 digit for fraction allowing -9999999999.9 to 9999999999.9

One can use plain `fixed` but it's in most cases sub-optimal.
Compiler tries to determine maximum value, but sometimes that's just impossible.
On these cases plain `fixed` can be extended to bigger precision.
Unfortunately that might be expensive and compiler is unable to produce optimal code.
It's always recommended to define precision for fixed types.

On can perform operations on different sized fixed numbers with certain constraints.
Result of the operation must fit into the combined bigger precision limits.
Compiler takes bigger integral and fraction parts and uses that as result type.

For example:

    fixed<10,2> a = 123456789.55;
    fixed<1,9> b = 1.123456789;

    // Prints fixed<10,9>
    printf("%s\n", typestr(a + b));

Similar way if storing the result to new fixed point number, reserved precision must be matching or bigger:

    fixed<10,2> a = 123456789.55;
    fixed<1,9> b = 1.123456789;

    fixed<10,9>  c = a + b;
    fixed<11,11> d = a + b;
    fixed<5,4>   f = a + b;  // Compiler failure

Fixed numbers are most effective when the whole precision fits into 64 bit number, but are not limited to that.
One just need to keep in mind, that compiler can generate way much more optimal code if the numbers does not
exceed certain limits.
Otherwise it might need to rely on bigint feature, which means most of the time a performance hit.


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


These looks like C++ classes, but we do not support directly other member methods
than the constructor and destructor. Like in C++ they're automatically called on creation,
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

One solution is to disallow assignment in truth evaluation expressions
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

Now it's clear to which `if`the `else` belongs to.

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
must be specifically stated:

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
One can still explicitly state `break`, but it has no effect.

Compared to C this is a breaking change.


# Rotate and shift

Original C has only shift left and shift right operators, but missing rotate,
even thought there's instructions for it on some CPU's, and it's widely utilized on programs.

Introducing rotate left `<<<` and rotate right `>>>` operators.  Example:

    int main()
    {
        unsigned int a = 0x12345678;
        printf("%x\n", a <<< 8);
    }

That would print out `0x34567812`.

Shifts are exactly specified:

- Left shift `<<`
  * Always fills zero
- Right shift `>>`
  * Unsigned fills always zero
  * Signed fills always sign bit
- Shift count can be anything
  * In case of overflow result is zero, except if signed right shift, it's filled with sign bit
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

        for (int i = 0; i < values.size; i++) {
            values[i] = i;
            tail[i] = i + values.size;
        }

        printf("String: %s, len: %d\n", test, test.length);

        int combined[20] = values + tail;
        // Will print 20, and not 10
        // Contents will be 1..10 and rest zeros
        printf("Combined length: %d\n", combined.length);

        // Will print 10
        printf("Combined2 length: %d\n", (values + tail).length);
    }

Thus arrays (and strings) has both `size` and `length` values, which are calculated usually at compile time,
but might get updated at runtime. For now both of those are the same.
Recommendation is to use `length` to determine number of elements.
In case of string `length` tells number of unicode characters (or code points) in the string, but size is the size in bytes.

The values are also used to perform runtime bound checks for extra safety and to prevent out of bounds errors.

## Tuples

Support for built-in tuple type. Eases for example returning multiple values from function:

    tuple get_two(int x)
    {
        return tuple(x * 2, x * 3)
    }

    int main()
    {
        int a, b;

        tuple(a, b) = get_two(42);

        printf("Got: %d and %d\n", a, b);

        return 0;
    }

Thus keyword "tuple" works in three ways:

- type: tuple tmp;
- pack values as: tmp = tuple(pack1, pack2, ...);
- unpack values as: tuple(unpack1, unpack2, ...) = tmp;

One can also access tuples with indexes, like arrays:

    tuple tmp;

    tmp = tuple(88, 66, 42);

    printf("First : %d\n", tmp[0]);
    printf("Second: %d\n", tmp[1]);
    printf("Third : %d\n", tmp[2]);

Values in tuples are strongly typed. Types are checked when unpacking.

## Swap

Support built-in swap operation, which can be compiled to assembly instruction
on target architectures supporting it.

    int a = 6;
    int b = 20;

    a <> b;   // Swap values

    printf("%d\n", a); // prints 20
    printf("%d\n", b); // prints 6
