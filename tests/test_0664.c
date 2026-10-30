// GNU __label__: a label local to its block, so a macro with a label can expand
// many times in one function (Linux's unsafe_put_user, get_user_inline).

// Same label in every expansion, jumped to by goto.
#define CHECK(v) ({                 \
    __label__ bad;                  \
    int r = 1;                      \
    if ((v) < 0) goto bad;          \
    r = 2;                          \
    if (0) {                        \
    bad:                            \
        r = 3;                      \
    }                               \
    r;                              \
})

// The label is the target of an asm goto, by name and by number.
#define BRANCH(c) ({                                        \
    __label__ yes;                                          \
    int r = 0;                                              \
    asm goto("cmpl $0, %0\n\tjne %l[yes]" : : "r"(c) : "cc" : yes); \
    r = 10;                                                 \
    if (0) { yes: r = 20; }                                 \
    r;                                                      \
})
#define BRANCH2(c) ({                                       \
    __label__ yes;                                          \
    int r = 0;                                              \
    asm goto("cmpl $0, %0\n\tjne %l1" : : "r"(c) : "cc" : yes); \
    r = 30;                                                 \
    if (0) { yes: r = 40; }                                 \
    r;                                                      \
})

static int shadow(int n) {
    int r = 0;
    goto out;           // the function's label, not the block's
    {
        __label__ out, again;
        int i = 0;
    again:
        if (++i < n) goto again;
        r = i;
        goto out;
    out:
        r += 100;
    }
    return r;
out:
    return r + 1;
}

static int inner_shadow(int n) {
    __label__ done;
    int r = 0;
    {
        __label__ done;
        if (n) goto done;
        r = 1;
    done:
        r += 2;
    }
    if (n > 1) goto done;
    r += 4;
done:
    return r;
}

int main(void) {
    int x = -1, y = 1, z = 0, one = 1;
    if (CHECK(x) != 3 || CHECK(y) != 2 || CHECK(z) != 2) return 1;
    if (BRANCH(y) != 20 || BRANCH(z) != 10) return 2;
    if (BRANCH2(y) != 40 || BRANCH2(z) != 30) return 3;
    if (shadow(5) != 1) return 4;
    if (inner_shadow(0) != 7 || inner_shadow(1) != 6 || inner_shadow(2) != 2) return 5;
    return 41 + one;
}
