/* objsh - tiny object store driven by stdin commands:
 *   add <id> <name> | get <id> | del <id> | ren <id> <name>           */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CACHE_SLOTS 8

struct obj {
    int id;
    char name[24];
    struct obj *next;
};

static struct obj *head;
static struct obj *cache[CACHE_SLOTS];

static struct obj *lookup(int id)
{
    struct obj *c = cache[(unsigned)id % CACHE_SLOTS];
    if (c && c->id == id)
        return c;
    for (struct obj *o = head; o; o = o->next)
        if (o->id == id) {
            cache[(unsigned)id % CACHE_SLOTS] = o;
            return o;
        }
    return NULL;
}

static void add(int id, const char *name)
{
    if (lookup(id))
        return;
    struct obj *o = calloc(1, sizeof *o);
    o->id = id;
    snprintf(o->name, sizeof o->name, "%s", name);
    o->next = head;
    head = o;
}

static void del(int id)
{
    for (struct obj **pp = &head; *pp; pp = &(*pp)->next)
        if ((*pp)->id == id) {
            struct obj *dead = *pp;
            *pp = dead->next;
            free(dead);
            return;
        }
}

int main(void)
{
    char line[128], name[64];
    int id;
    while (fgets(line, sizeof line, stdin)) {
        if (sscanf(line, "add %d %63s", &id, name) == 2) {
            add(id, name);
        } else if (sscanf(line, "get %d", &id) == 1) {
            struct obj *o = lookup(id);
            printf("%d: %s\n", id, o ? o->name : "(none)");
        } else if (sscanf(line, "del %d", &id) == 1) {
            del(id);
        } else if (sscanf(line, "ren %d %63s", &id, name) == 2) {
            struct obj *o = lookup(id);
            if (o)
                snprintf(o->name, sizeof o->name, "%s", name);
        }
    }
    while (head) {
        struct obj *n = head->next;
        free(head);
        head = n;
    }
    return 0;
}
