/* sic's task runtime (sic.md §"Async"): a cooperative scheduler, one per
   thread, running each task on a stack of its own (stackful coroutines), so
   `await` can suspend from any depth of calls. Prepended to every unit that
   uses `async`, `await`, `Task` or `art`; everything is weak, so the copies
   in a program's units are one, and the `art` module calls this one.

   A task runs when the code that made it waits: `await`, `art::yield_now()`,
   `art::sleep()` or `art::run()`. Awaiting a task that is not done runs the
   others until it is. */
extern void *malloc(unsigned long);
extern void *calloc(unsigned long, unsigned long);
extern void free(void *);
extern void *mmap(void *, unsigned long, int, int, int, long);
extern int munmap(void *, unsigned long);
extern int mprotect(void *, unsigned long, int);
extern int nanosleep(const void *, void *);
extern int clock_gettime(int, void *);
extern long write(int, const void *, unsigned long);
extern void abort(void);

/* A task's stack is 256 KiB (`__SIC_TASK_STACK` below), with a page under it
   that faults on an overflow (`__SIC_TASK_GUARD`). The runtime is added after
   preprocessing, so these are literals. */

typedef struct __sic_task {
    /* One count for the `Task` handles (their copies share it) and one for
       the scheduler until the task is done. */
    unsigned long refs;
    int state;                       /* 0 not started, 1 started, 2 done */
    void (*run)(void *frame, void *out);
    void (*rdrop)(void *out);        /* releases a result that owns something */
    void *frame;                     /* the arguments, `run`'s to release */
    void *out;                       /* the result, in this block */
    void *sp;                        /* stack pointer while switched out */
    char *stack;                     /* the mapping: guard page, then stack */
    struct __sic_task *blocked_on;   /* awaiting this task */
    long wake;                       /* asleep until this time (ns), or 0 */
    struct __sic_task *next;         /* the scheduler's ring */
    unsigned long vg_stack;          /* the stack's valgrind id */
    int taken;                       /* the result was moved out */
} __sic_task;

typedef struct __sic_sched {
    __sic_task *head, *tail;         /* every task not yet done */
    __sic_task *cur;                 /* running, or 0 in the thread's own stack */
    void *main_sp;                   /* the thread's stack, while a task runs */
    long live;
} __sic_sched;

/* Save the callee-saved registers, MXCSR and the x87 control word on this
   stack, store the stack pointer in `*from`, and resume the stack `to` as it
   was saved. A new task's stack is laid out so that resuming it starts
   `__sic_task_main(task)` (the task in r12). */
__asm__(
    ".text\n"
    ".weak __sic_ctx_switch\n"
    ".type __sic_ctx_switch,@function\n"
    "__sic_ctx_switch:\n"
    "    pushq %rbp\n"
    "    pushq %rbx\n"
    "    pushq %r12\n"
    "    pushq %r13\n"
    "    pushq %r14\n"
    "    pushq %r15\n"
    "    subq $8, %rsp\n"
    "    stmxcsr (%rsp)\n"
    "    fnstcw 4(%rsp)\n"
    "    movq %rsp, (%rdi)\n"
    "    movq %rsi, %rsp\n"
    "    ldmxcsr (%rsp)\n"
    "    fldcw 4(%rsp)\n"
    "    addq $8, %rsp\n"
    "    popq %r15\n"
    "    popq %r14\n"
    "    popq %r13\n"
    "    popq %r12\n"
    "    popq %rbx\n"
    "    popq %rbp\n"
    "    ret\n"
    ".size __sic_ctx_switch, .-__sic_ctx_switch\n"
    ".weak __sic_task_start\n"
    ".type __sic_task_start,@function\n"
    "__sic_task_start:\n"
    "    movq %r12, %rdi\n"
    "    call __sic_task_main@PLT\n"
    "    ud2\n"
    ".size __sic_task_start, .-__sic_task_start\n"
    /* A valgrind client request (`args`: the request and its arguments) and
       its result, or 0 outside valgrind: the rotations add up to none and
       the `xchg` does nothing, unless valgrind runs the program. */
    ".weak __sic_valgrind_request\n"
    ".type __sic_valgrind_request,@function\n"
    "__sic_valgrind_request:\n"
    "    movq %rdi, %rax\n"
    "    xorl %edx, %edx\n"
    "    rolq $3, %rdi\n"
    "    rolq $13, %rdi\n"
    "    rolq $61, %rdi\n"
    "    rolq $51, %rdi\n"
    "    xchgq %rbx, %rbx\n"
    "    movq %rdx, %rax\n"
    "    ret\n"
    ".size __sic_valgrind_request, .-__sic_valgrind_request\n");
extern void __sic_ctx_switch(void **from, void *to);
extern void __sic_task_start(void);
extern unsigned long __sic_valgrind_request(unsigned long *args);

/* Tell valgrind about a task's stack (`VALGRIND_STACK_REGISTER`, request
   0x1501), so that a switch to it is a change of stack, not a frame of
   megabytes whose memory it takes for uninitialised; and forget it
   (`VALGRIND_STACK_DEREGISTER`, 0x1502). */
__attribute__((weak)) unsigned long __sic_vg_stack_register(char *lo, char *hi) {
    unsigned long a[6] = { 0x1501, (unsigned long)lo, (unsigned long)hi, 0, 0, 0 };
    return __sic_valgrind_request(a);
}

__attribute__((weak)) void __sic_vg_stack_deregister(unsigned long id) {
    unsigned long a[6] = { 0x1502, id, 0, 0, 0, 0 };
    __sic_valgrind_request(a);
}

__attribute__((weak)) __sic_sched *__sic_sched_get(void) {
    static __thread __sic_sched s;
    return &s;
}

__attribute__((weak)) void __sic_task_fail(const char *msg) {
    unsigned long n = 0;
    while (msg[n]) n++;
    write(2, msg, n);
    abort();
}

__attribute__((weak)) long __sic_task_now(void) {
    long ts[2];
    clock_gettime(1 /* CLOCK_MONOTONIC */, ts);
    return ts[0] * 1000000000L + ts[1];
}

/* Drop one reference; the last frees the task and the result it holds. */
__attribute__((weak)) void __sic_task_release(__sic_task *t) {
    if (!t) return;
    if (__atomic_sub_fetch(&t->refs, 1, __ATOMIC_SEQ_CST) != 0) return;
    if (t->state == 2 && !t->taken && t->rdrop) t->rdrop(t->out);
    free(t);
}

/* A `Task` handle's destructor. Its copies share the struct count the
   compiler gives every struct with a destructor (`__sic_rc`, 0 while there
   is one owner); the last of them releases the task. */
__attribute__((weak)) void __sic_task_drop(void *self) {
    struct { __sic_task *h; unsigned long *rc; } *p = self;
    unsigned long *rc = p->rc;
    if (rc) {
        if (__atomic_fetch_sub(rc, 1, __ATOMIC_SEQ_CST) != 1) return;
        free(rc);
        p->rc = 0;
    }
    __sic_task_release(p->h);
    p->h = 0;
}

/* Where a task's stack starts: run it, then go back to the scheduler for
   good. */
__attribute__((weak)) void __sic_task_main(__sic_task *t) {
    t->run(t->frame, t->out);
    t->state = 2;
    __sic_sched *s = __sic_sched_get();
    __sic_ctx_switch(&t->sp, s->main_sp);
    __sic_task_fail("sic: a finished task was resumed\n");
}

/* A new task, scheduled: `run(frame, out)` writes its result (`size` bytes)
   to `out`. The caller holds one reference, the scheduler the other. */
__attribute__((weak)) __sic_task *__sic_task_spawn(void (*run)(void *, void *), void *frame,
                                                   void (*rdrop)(void *), unsigned long size) {
    unsigned long head = (sizeof(__sic_task) + 15) & ~15UL;
    __sic_task *t = calloc(1, head + (size ? size : 1));
    if (!t) __sic_task_fail("sic: out of memory for a task\n");
    t->refs = 2;
    t->run = run;
    t->rdrop = rdrop;
    t->frame = frame;
    t->out = (char *)t + head;
    __sic_sched *s = __sic_sched_get();
    if (s->tail) s->tail->next = t; else s->head = t;
    s->tail = t;
    s->live++;
    return t;
}

__attribute__((weak)) int __sic_task_runnable(__sic_task *t, long now) {
    if (t->blocked_on && t->blocked_on->state != 2) return 0;
    if (t->wake && t->wake > now) return 0;
    return 1;
}

/* Take a finished task out of the ring and free its stack (from the thread's
   own stack: the task's is no longer in use). */
__attribute__((weak)) void __sic_task_retire(__sic_sched *s, __sic_task *t) {
    __sic_task *prev = 0;
    for (__sic_task *q = s->head; q; prev = q, q = q->next) {
        if (q != t) continue;
        if (prev) prev->next = t->next; else s->head = t->next;
        if (s->tail == t) s->tail = prev;
        break;
    }
    t->next = 0;
    s->live--;
    if (t->stack) {
        __sic_vg_stack_deregister(t->vg_stack);
        munmap(t->stack, 262144UL /* __SIC_TASK_STACK */ + 4096UL /* __SIC_TASK_GUARD */);
    }
    t->stack = 0;
    __sic_task_release(t);
}

/* Resume `t` until it next waits or finishes. */
__attribute__((weak)) void __sic_task_resume(__sic_sched *s, __sic_task *t) {
    if (!t->stack) {
        char *m = mmap(0, 262144UL /* __SIC_TASK_STACK */ + 4096UL /* __SIC_TASK_GUARD */, 3 /* PROT_READ|PROT_WRITE */,
                       0x20022 /* MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK */, -1, 0);
        if (m == (char *)-1) __sic_task_fail("sic: out of memory for a task's stack\n");
        mprotect(m, 4096UL /* __SIC_TASK_GUARD */, 0 /* PROT_NONE */);
        t->stack = m;
        t->vg_stack = __sic_vg_stack_register(m + 4096UL /* __SIC_TASK_GUARD */,
                                              m + 262144UL /* __SIC_TASK_STACK */ + 4096UL /* __SIC_TASK_GUARD */);
        unsigned long *sp = (unsigned long *)(m + 262144UL /* __SIC_TASK_STACK */ + 4096UL /* __SIC_TASK_GUARD */) - 10;
        sp[0] = 0x1F80UL | (0x037FUL << 32);     /* MXCSR, x87 control word */
        sp[1] = sp[2] = sp[3] = 0;               /* r15 r14 r13 */
        sp[4] = (unsigned long)t;                /* r12: the task */
        sp[5] = sp[6] = 0;                       /* rbx rbp */
        sp[7] = (unsigned long)__sic_task_start; /* where the switch returns */
        t->sp = sp;
        t->state = 1;
    }
    s->cur = t;
    __sic_ctx_switch(&s->main_sp, t->sp);
    s->cur = 0;
    if (t->state == 2) __sic_task_retire(s, t);
}

/* Run tasks from the thread's own stack until `target` is done, or until the
   time `until` when it is not 0, or, with neither, until no task is left.
   `once`: give each task that can run one turn, then return. */
__attribute__((weak)) void __sic_sched_loop(__sic_task *target, long until, int once) {
    __sic_sched *s = __sic_sched_get();
    for (;;) {
        if (target && target->state == 2) return;
        if (!s->head) {
            if (target) __sic_task_fail("sic: awaiting a task that cannot finish\n");
            if (!until) return;
        }
        long now = __sic_task_now();
        if (until && now >= until) return;
        int ran = 0;
        long first_wake = 0;
        /* One turn each, in order; a task made during the pass waits for the
           next one. */
        __sic_task *last = s->tail;
        for (__sic_task *t = s->head, *n; t; t = n) {
            n = t->next;
            int was_last = t == last;
            if (__sic_task_runnable(t, now)) {
                __sic_task_resume(s, t);
                ran = 1;
                if (target && target->state == 2) return;
            } else if (t->wake && (!first_wake || t->wake < first_wake)) {
                first_wake = t->wake;
            }
            if (was_last) break;
        }
        if (once) return;
        if (ran) continue;
        /* Nothing can run: sleep until the first task wakes, or `until`. */
        long wake = first_wake;
        if (until && (!wake || until < wake)) wake = until;
        if (!wake) __sic_task_fail("sic: every task is waiting for another (await deadlock)\n");
        long d = wake - __sic_task_now();
        if (d > 0) {
            long ts[2] = { d / 1000000000L, d % 1000000000L };
            nanosleep(ts, 0);
        }
    }
}

/* `await`: the result of `t`, once it is done. A task waits for it, and lets
   the others run meanwhile; the thread's own code runs the tasks until it is. */
__attribute__((weak)) void *__sic_task_await(__sic_task *t) {
    if (!t) __sic_task_fail("sic: awaiting an empty Task\n");
    __sic_sched *s = __sic_sched_get();
    __sic_task *me = s->cur;
    if (me == t) __sic_task_fail("sic: a task awaits itself\n");
    if (!me) {
        __sic_sched_loop(t, 0, 0);
    } else {
        while (t->state != 2) {
            me->blocked_on = t;
            __sic_ctx_switch(&me->sp, s->main_sp);
        }
        me->blocked_on = 0;
    }
    return t->out;
}

/* `await` of a task whose handle the caller gives up right after (`await
   f(x)`): the result, and in `*moved` whether the caller may take it rather
   than copy it — when that handle has no count (`rc`, so no copies), it is
   the only one, and nobody can await the task again. */
__attribute__((weak)) void *__sic_task_await_take(__sic_task *t, void *rc, int *moved) {
    void *out = __sic_task_await(t);
    *moved = 0;
    if (!rc && !t->taken) {
        t->taken = 1;
        *moved = 1;
    }
    return out;
}

/* `art::yield_now()`: let the other tasks run. */
__attribute__((weak)) void __sic_task_yield(void) {
    __sic_sched *s = __sic_sched_get();
    __sic_task *me = s->cur;
    if (me) __sic_ctx_switch(&me->sp, s->main_sp);
    else __sic_sched_loop(0, 0, 1);
}

/* `art::sleep(ms)`: wait at least `ms` milliseconds; the others run. */
__attribute__((weak)) void __sic_task_sleep_ms(long ms) {
    __sic_sched *s = __sic_sched_get();
    long until = __sic_task_now() + (ms > 0 ? ms : 0) * 1000000L;
    __sic_task *me = s->cur;
    if (me) {
        me->wake = until;
        __sic_ctx_switch(&me->sp, s->main_sp);
        me->wake = 0;
    } else {
        __sic_sched_loop(0, until, 0);
    }
}

/* `art::run()`: run until every task has finished. In a task: until it is the
   only one left. */
__attribute__((weak)) void __sic_task_run_all(void) {
    __sic_sched *s = __sic_sched_get();
    __sic_task *me = s->cur;
    if (!me) { __sic_sched_loop(0, 0, 0); return; }
    while (s->live > 1) __sic_ctx_switch(&me->sp, s->main_sp);
}

/* The tasks of this thread not yet finished. */
__attribute__((weak)) long __sic_task_pending(void) {
    return __sic_sched_get()->live;
}

/* `art::spawn(fn, arg)`: `fn(arg)` as a task nobody awaits. */
__attribute__((weak)) void __sic_task_fn_run(void *frame, void *out) {
    void **f = frame;
    void (*fn)(void *) = (void (*)(void *))f[0];
    void *arg = f[1];
    free(frame);
    fn(arg);
}

__attribute__((weak)) int __sic_task_spawn_fn(void (*fn)(void *), void *arg) {
    void **f = malloc(2 * sizeof(void *));
    if (!f) return -1;
    f[0] = (void *)fn;
    f[1] = arg;
    __sic_task_release(__sic_task_spawn(__sic_task_fn_run, f, 0, 0));
    return 0;
}
