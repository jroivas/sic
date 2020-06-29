#include "str.h"
#include "sic.h"

struct string_info {
    char str[MAX_STR_LEN];
    struct string_info *next;
    int free;
};

static struct string_info *__strings = NULL;

struct string_info *str_find_free()
{
    if (!__strings)
        return NULL;
    struct string_info *tmp = __strings;
    if (tmp->free)
        return tmp;
    while (tmp->next != NULL) {
        tmp = tmp->next;
        if (tmp->free)
            return tmp;
    }
    return NULL;
}

char *str_alloc()
{
    struct string_info *res = str_find_free();
    if (res) {
        res->free = 0;
        return res->str;
    }
    res = calloc(1, sizeof(struct string_info));
    if (__strings) {
        struct string_info *tmp = __strings;
        while (tmp->next != NULL)
            tmp = tmp->next;
        tmp->next = res;
    } else
        __strings = res;

    return res->str;
}

void str_del(char *str)
{
    // Works only if str is first element in string_info
    struct string_info *tmp = (struct string_info*)str;
    tmp->free = 1;
}

void str_free_all()
{
    struct string_info *tmp = __strings;
    while (tmp != NULL) {
        struct string_info *next = tmp->next;
        free(tmp);
        tmp = next;
    }
}
