/* A static struct ending in a FLEXIBLE ARRAY MEMBER (`T arr[];`) whose brace
 * initializer supplies elements must reserve and serialize storage for them.
 * sic sized the object as if the member were empty, so serialization wrote past
 * the buffer and the whole aggregate was zero-filled. QEMU's QemuOptsList ends
 * in `QemuOptDesc desc[]`; every static opts list (qemu_rtc_opts, ...) came out
 * all zeros, so its .name was NULL and find_list()'s strcmp crashed while
 * parsing options at machine boot. Also exercises the self-referential
 * QTAILQ_HEAD_INITIALIZER address (&global.head.tqh_circ). */
typedef enum { OPT_STRING = 0, OPT_BOOL, OPT_NUMBER } OptType;
typedef struct OptDesc { const char *name; OptType type; } OptDesc;
struct Circ { void *next; void *prev; };
struct Head { void *first; struct Circ circ; };
struct OptsList {
    const char *name;
    _Bool merge_lists;
    struct Head head;
    OptDesc desc[];          /* flexible array member */
};

static struct OptsList rtc_opts = {
    .name = "rtc",
    .head = { .circ = { 0, &(rtc_opts.head).circ } },
    .merge_lists = 1,
    .desc = {
        { .name = "base",  .type = OPT_STRING },
        { .name = "clock", .type = OPT_NUMBER },
        { .name = "drift", .type = OPT_BOOL },
        { }                  /* terminator */
    },
};

int main(void)
{
    if (rtc_opts.name == 0) return 1;                       /* whole struct zeroed */
    if (rtc_opts.name[0] != 'r') return 2;
    if (rtc_opts.merge_lists != 1) return 3;
    if (rtc_opts.desc[0].name == 0 || rtc_opts.desc[0].name[0] != 'b') return 4;
    if (rtc_opts.desc[1].type != OPT_NUMBER) return 5;
    if (rtc_opts.desc[2].name == 0 || rtc_opts.desc[2].type != OPT_BOOL) return 6;
    if (rtc_opts.desc[3].name != 0) return 7;               /* terminator */
    if (rtc_opts.head.circ.prev != (void *)&rtc_opts.head.circ) return 8;  /* self-ref */
    return 0;
}
