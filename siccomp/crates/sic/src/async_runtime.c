extern void *malloc(unsigned long);
extern void free(void *);

typedef struct __sic_task { unsigned long value; } __sic_task;

__attribute__((weak)) __sic_task *__sic_task_new(unsigned long v) {
    __sic_task *t = (__sic_task *)malloc(sizeof(__sic_task));
    t->value = v;
    return t;
}

__attribute__((weak)) unsigned long __sic_await(__sic_task *t) {
    if (!t) return 0;
    unsigned long v = t->value;
    free(t);
    return v;
}
