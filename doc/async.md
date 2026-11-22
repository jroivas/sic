# Async — tasks, `await` and `art`

An `async` function returns a `Task<T>` instead of running to completion where it
is called; `await` waits for a task and gives its result:

```sic
async int fetch(int id) { return id * 2; }

int main() {
    Task<int> t = fetch(21);   // make the task; it has not run yet
    int a = await t;           // 42
    int b = await fetch(50);   // 100 — await a call directly
    return a + b - 142;
}
```

Struct methods and generic functions can be `async` too:

```sic
struct Counter { int v; async int next(Counter *self) { self.v++; return self.v; } };
async T same<T>(T x) { return x; }
```

## How tasks run

Tasks are **cooperative** and run on the thread that made them, each on a stack of
its own — so an `await` anywhere in a task's calls suspends just that task, and the
async function's body is ordinary code (no state machine, no colouring of the
functions it calls).

A task **starts when the thread waits**: at an `await`, or an `art::yield_now()`,
`art::sleep()` or `art::run()`. It then runs until it finishes or waits itself.
Awaiting a task that is not done runs the other tasks until it is, so two tasks
that wait (sleep, yield, await something) make progress at the same time:

```sic
import art;

async int nap(int ms, int v) { art::sleep(ms); return v; }

int main() {
    Task<int> slow  = nap(40, 1);
    Task<int> quick = nap(5, 2);
    return await slow + await quick;   // both sleep at once: about 40 ms, not 45
}
```

Tasks that await each other in a cycle can never finish; the program stops with
`sic: every task is waiting for another (await deadlock)` (a task awaiting itself
is reported too).

Each thread has its own scheduler. A task stays on the thread that made it; to use
several cores, run tasks on several [`std::thread`](standard-library.md) threads.

## Handles and results

- A `Task<T>` is a **handle**. Copies of it are the same task, counted like any
  struct with a destructor; the task and its result are freed with the last handle.
- `await` gives the result **as a call does** — owned. Awaiting a temporary task
  (`await f(x)`) moves the result out of it; awaiting a handle you keep gives a
  copy, so a task can be awaited more than once:

  ```sic
  Task<string> t = greet("ann");
  string a = await t;
  string b = await t;      // the same result again
  ```

- Dropping a handle does not cancel the task: one nobody awaits still runs the next
  time the thread waits. A task that never got to run before the program exits
  does not run.
- Any type can be a result: numbers, `string`, structs (with destructors too),
  `Option`/`Result`, containers, `bigint`, `fixed`, `any`, tuples (`tuple<…>`, or a
  plain `tuple` as a dynamic one), and closures as `Fn<…>`:

  ```sic
  async Fn<int(int)> adder(int n) { return [n](int x) => x + n; }
  Fn<int(int)> add40 = await adder(40);
  ```

## Arguments

A call copies its arguments into the task the way a call passes them, so a string,
container or tuple argument stays alive for the task even after the caller's
variable is gone. A pointer argument — and the `self` of an async method — must
outlive the task.

A plain `tuple` parameter has the shape its calls give it, as for any function
(static when they agree, dynamic otherwise). An async function cannot be variadic,
and every parameter needs a name.

## Stacks

A task's stack is 256 KiB, with a guard page under it: a task that recurses too
deep faults instead of overwriting memory. The stacks are registered with
valgrind, so it checks tasks like any other code.

## `art` — the scheduler's API

`import art;` gives the scheduler's functions:

| function | |
|---|---|
| `art::yield_now()` | let the other tasks run (from the thread's own code: each of them once) |
| `art::sleep(int ms)` | wait at least `ms` milliseconds while the others run |
| `art::spawn(fn, arg)` | run a plain `void fn(void *)` as a task nobody awaits |
| `art::run()` | run until every task has finished (in a task: every other one) |
| `art::pending()` | the number of this thread's tasks not yet finished |

```sic
import art;

void worker(void *arg) {
    for (int i = 0; i < 3; i++) { /* … */ art::yield_now(); }
}

int main() {
    art::spawn(worker, NULL);
    art::spawn(worker, NULL);
    art::run();                // the two interleave at each yield
    return 0;
}
```

`art::spawn` coroutines and `async` tasks share the one scheduler, which lives in the
program: a module's async functions run on its caller's scheduler.

Next: [standard library](standard-library.md).
