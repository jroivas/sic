// `a[1]` scales a constant index by a constant size: without the optimizer that
// multiply has two constant operands, and Cranelift pools one inside the code,
// which -mcmodel=kernel must not do (objtool cannot decode past data in .text).
struct big { long a[8]; };

static struct big copy(struct big *b) {
    struct big c = *b;
    c.a[1] = 40;
    c.a[2] = c.a[1] + 2;
    return c;
}

int main(void) {
    struct big b = {{0}};
    return (int)copy(&b).a[2];
}
