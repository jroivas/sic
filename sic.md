# SIC - Slightly Improved C specification

Slightly Improved C is a programming language that borrows a lot from C,
but is not afraid to introduce breaking changes in order to improve it.

**REMARK** Most of the features described here are only planned, and **NOT** yet implemented.
For now the focus has been implementing more or less standard C compiler.

## Limit undefined behavior

One of C's optimization strategies is "undefined behavior"
when compiler may do whatever it wants.

We remove that freedom and try to specify what to do on each of the cases.

Reason is to avoid hard to debug undefined behavior cases.
Our thesis is, compiler can do good enough code even with
these rules, and same time prevent unnecessary lost human time.

### Initialized variables

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

## Integer sizes

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

## Built-in fixed point, and extended floats

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


## Built-in string

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


## Empty brackets pointer

This is not valid:

    char test[];

## Scopes and automatic release

We borrow `new` keyword from C++ to create new "objects".
However they're not fat objects like in C++, but structs which can have
constructor and destructor:

    struct test {
        test() {
            val = new int(8);
        }
        ~test() {
            del val;
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

All dynamically allocated memory is reference counted.
Accessing dynamically allocated memory causes boundary checks.

Using `new` and `del` is recommended instead of C style malloc/free.
Let's see this example bit closer:

    int *val = new int(10);
    val[10] = 0;
    del val;

This would either cause compile error or runtime exception.
First `new int(10)` allocates memory for 10 ints so it's same as `sizeof(int) * 10`.
In order to allocate just one integer `new int` is enough.

Returned pointer is so called fat pointer. It will include information about the size of the allocation:

- start_of_allocation
- size_of_allocation
- reference_cnt
- data

It will have reference_cnt set as 1.
On every access to the data is protected with boundary checks. Thus the next line will end up making this check:

    (10 * sizeof(int)) < size_of_allocation

Since we have allocated `10 * sizeof(int)` but we're accessing element starting at `10 * sizeof(int)` this check will fail.
Failed check will cause runtime exception.

In case there would not be any overflows we would end up deleting the allocation.
It will free the memory in case reference_cnt is decremented to 0.
It's also possible that reference to the allocation has been passed forward to a thread.
On that case reference_cnt is still not 0, and memory will be freed when the reference gets out of scope.

## References

First we have a reference, which is indicated by `@` at the beginning of the type declaration.
When taking a reference of a variable it's name is also prefixed with `@`:

    int calculate_length(@char* s) {
        mut int i = 0;

        while (s[i]) {
            i++;
        }
        return i;
    }

    char *name = new char(10);
    memcpy(name, "test", 5);

    int len = calculate_length(@name);

This example looks like what you would normally do in C.
Difference is that a reference to variable `name` is taken instead of passing `name` as plain pointer.
Pointer would normally be passed as-is, but since we use `@` we're handling new kind of references.
This referece has it's scope, and is automatically freed when getting out of scope.
Thus it's valid only inside `calculate_length()` function.
Inside the functin variable `s` itself can be utilized as it would be a normal immutable pointer passed there.

There's few things that happens:
First one is reference counting.
In case `name` would be freed on another context, freeing up the memory is not done until the last reference is dropped.
It's safe to pass references around, since they can never point to freed memory.
This means that one can't call `free` on a reference.
Dereferencing is not allowed. Thus references are **always** scoped.

Note that on previous example the reference itself is mutable, but the value it's referring to is not.
It would be totally fine to do even one step closed to "normal C":

    int calculate_length(@char* s) {
        mut int i = 0;

        while (*s) {
            s++;
            i++;
        }
        return i;
    }

This is still memory safe. All access to the reference causes boundary checks.
In case the boundaries are violated an exception is raised.

In order to pass reference to mutable variable one needs to explicitly state that:

    int calculate_length(@mut char* s) {
        int v = *(++s);

        // We can mutate value referenced by "s"
        *s = 0;
        return v;
    }

On that example both the reference itself and the value it's referring to are both mutable.
One should rarely pass reference to a mutable variable.
First of all, passing `@mut` makes the function to receive exclusive reference to the variable.
Referenced variables may have either multiple readers, or only one writer.
When a write reference is taken, other reads (or write) is not possible.
Taking another reference to a variable with a mutable reference is not allowed by compiler.

Second, if you end up using this kind of construction, it's highly recommended to reconsider if you really need it.
There is still legit use cases for this, thus it's not restricted by the language.

Returning a reference to local variable is not allowed. However if one wants to keep the reference alive
it can be returned back to the caller:

    @char *tst(@char *s) {
        printf("Ref: %s\n", s);
        return s;
    }

    char *name = "test";
    @char *ret = tst(@name);
    printf("Still: %s\n", ret);

After the return reference is kept alive, it's scope just changes.
This would cause compile error:

    @int tst() {
        int x = 42;
        return @x;
    }

    @int ret = tst();

Variable `x` is local, and it's lifetime is bounded on the function scope.
Referencing to it is allowed, but returning the reference is not.

Passing reference to another function is valid:

    int strlen_ref(@char *s) {
        int l = 0;
        while (*s) {
            ++l;
            ++s;
        }
        return l;
    }

    int add5(@char *s) {
        return *s + 5;
    }

    int adds(@char *s) {
        int res = strlen_ref(s);
        res += add5(s);
        return res;
    }

When passing a reference as a parameter a new reference is formed, and the reference count of original variable is increased.

## Strict mode

As another addition we add more rusty like features, which however are optional.
In order to enable those a new strict mode is introduced.
This can be applied per function, or per compile unit.

To enable it for whole compile unit do:

    using strict;

To use it for a single function:

    strict int fn() {
        return 42;
    }

It changes few things:

All variables are by default immutable after initial assign.
Thus introduce new `mut` keyword to change this:

    int meaning = 42;
    mut int life = 123;

On that example variable `meaning` can't be changed, but `life` can.
This is the opposite of the default in C.
Mutable variable can be automatically promoted to immutable,
but not the other way around.

Another change is passing pointers.
We are adding borrowing, reference counting and ownership to all pointer by default.

### Ownership, and moving it

One big thing is ownership. Variables are always owned by someone.
Let's see example in strict mode:

    const char *text = "Hello";
    char *another = text;

First we have `text` which refers to const string `Hello`.
In strict mode one can omit `const` since all variables are by default immutable,
that's why variable `another` doesn't need `const`.

This flow is different from C. In C both `text` and `another` would be valid.
In strict mode instead of doing assign, the value is moved.
This means that `text` is not valid any more after line `another = text`.

If one needs to copy the value in two different variables, there's clone keyword:

    char *text = "Hello";
    char *another = clone text;

This makes a clone of the value of `text` and assigns it to `another`.
After this both variables are valid.

Cloning might me expensive operation, and is done recursively if needed.
For example:

    struct test1 {
        int a;
        int b;
    };

    struct test2 {
        int a;
        float b;
    };

    struct test3 {
        struct test1 a;
        struct test2 b;
    };

    struct test4 {
        struct test3 a;
        struct test3 *b;
        @struct test3 *c;
    };

    struct test4 *val1 = new struct test4;
    val1->b = new struct test3;
    val1->c = @val1->b;
    struct test4 *val2 = clone val1;

At this example `clone` needs to check all the other structs inside of it,
and call clone on them. This is done recursively until done.
References can't be cloned as is, but a new similar reference is formed.
In this example `val2->c` would still refer to `val1->b`,
but `val2->b` would be different from `val1->b`.

Remark that cloning and moving is meant for only non-primitive types.
All primitive types (int, float, etc.) can be simply assigned:

    int a = 4;
    int b = a;

On that example both `a` and `b` are still valid and usable.

Ownership is moved similar way when passing as parameter:

    void tst1(char *s) {
        // Ownership is moved here
        printf("Passed: %s\n", s);
    }

    void tst2(int v) {
        printf("Passed: %v\n", v);
    }

    char *text = "Hello";
    int val = 42;

    tst1(name);
    tst2(val);

This example follows the rules defined earlier.
After calls to function `name` is not usable on the caller, but value of `val` would be usable since it's primitive.
Ownership of a variable can be passed back by returning the passed variable:

    char *print_and_return(char *s) {
        printf("Passed: %s\n", s);
        return s;
    }

    char *text = "Hello";
    char *text2 = print_and_return(text);

    printf("Returned: %s\n", text2);

This is perfectly valid, since ownership is first taken, and then returned.
Since `text` is not mutable, one can't assign the return value back to it,
but need to reserve new variable for it.
Rules state also that `text` is moved and not useable after the call.

## Assignment and equals

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

## Dangling else

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

## Imports

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

## Match

New alternative to traditional `switch` and `case`.
Match takes an instance of `enum`.
Old C style enums are imporoved a bit:

    enum Option {
        Some<int>,
        None
    };

    enum Result<T> {
        Ok<T>,
        Err<string>
    };

With these two we can make something like:

    Option a = Some(5);
    Option b = None;

    function check_option(Option opt) {
        match (opt) {
            Some(val): printf("Some value: %d\n", val);
            None: printf("None value");
        }
    }
    check_option(a);
    check_option(b);

    Result<int> r = Ok(5);
    Result<int> e = Err("Some error");

    void check_result(Result<int> res) {
        match (r) {
            Ok(val): printf("Result: %d\n", val);
            Err(msg): {
                printf("Error: %s\n", msg);
                exit(1);
            }
        }
    }

    check_result(r);
    check_result(e);

Thus enum itself may contain type of the value.
All entries in the enum contains name, and optionally a type.
Instances of enums can contain value value of the defined type.
All entries may have different type.

## Switch - case

One problematic construction is `switch` and it's `case`.
Biggest problem is the fallthrough in case of missing break.

We're breaking `switch` and making case end mandatory.
Thur `break` and `fallthrough` must be specifically stated:

    int test(int x)
    {
        int r = 0;
        int a = 0;
        switch (x) {
            case 1: r = 111; a = 1;
                break;
            case 2:
                int tmp = x;
                r = 222;
                a = 1 + tmp;
                break;
            case 3: r = 333;
                break;
            case 4:
                r = 444;
                a = 2;
                break;
            case 5: r = 555;
                break;
            case 6: fallthrough;
            case 7: fallthrough;
            case 8: r = 678;
                break;
            case 9: r = 999; a = 3;
                break;
            default: r = 0;
                break;
        }
        return r + a;
    }

It's fault in case there's missing `break` or `fallthrough` statement after every `case`.
It's not allowed to have any code between `break` or `fallthrough` and the next `case` statement.
Compared to C this is a breaking change, however current C code can easily make compatible by adding missing `fallthrough` statements.

## Rotate and shift

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

# Arrays and lists

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

Swapped values must be same type.

## Errors and exceptions

We have been talking about errors and exceptions earlier in this document, but haven't yet specified how they work.
In case of SIC most errors are actually just bit better error codes. Let's take an example:

    int readbyte(&mut std.File f) {
        return f.read(1);
    }

This simple function tries to read one byte from a file. We get the file as reference, read one byte from there and return the value.
Instead of C API we use SIC API and it's `std.File` interface which implements SIC style errors.

When we try to compile that example it fails. Reason is that we didn't actually handle the possible exception.
For that we have two options: handle it locally, or pass it forward. Here's an example to just handle it there:

    int readbyte(&mut std.File f) {
        std.Result<int, string> res = f.read(1);

        match (res) {
            Ok(val): return val;
            Err(msg): printf("Can't read from file!\n");
        }
    }

As you can see the error in this case is actually just wrapper around an enum. In order to pass it forward one just:

    std.Result<int, string> readbyte(&mut std.File f) {
        return f.read(1);
    }

Which passes the result forward and it's caller's responsibility to handle it.

There's exceptions that may be triggered by some operations. For example divide by zero in unsafe mode
(Remark that in normal mode result would be `0` instead without any exceptions):

    int dodiv(int a, int b) {
        unsafe {
            return a / b;
        }
    }

    printf("Res: %d\n", dodiv(10, 0));

On these primitive exceptions the program in question is terminated. Stack trace might be printed, or some other error message.
In order to handle the exeption instead of crashing the program one can use specific exception keywords: `overflow`, `divide_by_zero` and `exception`:

    int dodiv(int a, int b) {
        unsafe {
            int res:
            if (divide_by_zero { res = a / b }) {
                return 0;
            }
            return res;
        }
    }

    printf("Res: %d\n", dodiv(10, 0));

On this case the example works exacly as it would in normal mode without the manual handling.

## Multine strings

We're borrowing multiline string syntax from Python:

    string multistring = """This is multine string.
        It starts with three quotation marks, and ends
        until three quotations marks are found.
        Thus it's valid to insert " or ' inside here.
        In case one would like to have three quotation marks,
        one can always escape it like \"\"\" this.
        One escape would also work: \""""

        Inside this quotation newlines and indent is NOT saved unless
        the string is marked as raw string.
        That happens by giving identifier r before fist quotation mark.
        """;

    string raw_multistring = r"""This is raw multiline string.

        All formatting, newlines, etc. is preserved.
        Suitable for making templates that should be printed or written as-is.
        """;

Those strings can be used like any strings.
