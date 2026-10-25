// An object-like macro naming a function-like one, invoked with arguments that
// span lines (Linux's `#define DECLARE_EVENT_CLASS_SCHEDSTAT DECLARE_EVENT_CLASS`
// in trace/events/sched.h): the lines are joined and the call expands.
#define ADD3(a, b, c) ((a) + (b) + (c))
#define SUM ADD3
#define SUM2 SUM
#define ID(x) x

int main(void) {
    int r = SUM(ID(10),
                ID(20),
                2);
    int s = SUM2(1,
                 2,
                 3);
    return r + s + SUM(1, 1, 0) + 2;
}
