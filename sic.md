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

# 
