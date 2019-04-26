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

We remove that freedom and try to specify what to do on each
of the cases.
