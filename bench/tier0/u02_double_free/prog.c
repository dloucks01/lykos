/* kvload - load "SET key value" lines into a store and dump it */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ENTRIES 32
#define MAX_VAL 64

struct entry {
    char key[32];
    char *value;
};

struct store {
    struct entry e[MAX_ENTRIES];
    int n;
};

static struct entry *find(struct store *st, const char *key)
{
    for (int i = 0; i < st->n; i++)
        if (strcmp(st->e[i].key, key) == 0)
            return &st->e[i];
    return NULL;
}

static int store_put(struct store *st, const char *key, const char *val)
{
    struct entry *e = find(st, key);
    if (e) {
        free(e->value);
        if (strlen(val) > MAX_VAL) {
            fprintf(stderr, "value for %s too long\n", key);
            return -1;
        }
        e->value = strdup(val);
        return 0;
    }
    if (st->n == MAX_ENTRIES || strlen(key) >= sizeof e->key || strlen(val) > MAX_VAL)
        return -1;
    e = &st->e[st->n++];
    strcpy(e->key, key);
    e->value = strdup(val);
    return 0;
}

static void store_free(struct store *st)
{
    for (int i = 0; i < st->n; i++)
        free(st->e[i].value);
    st->n = 0;
}

int main(int argc, char **argv)
{
    static struct store st;
    char line[256], key[64], val[200];
    int lineno = 0, ok = 1;
    if (argc < 2) {
        fprintf(stderr, "usage: %s <config>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "r");
    if (!f) {
        perror("open");
        return 1;
    }
    while (fgets(line, sizeof line, f)) {
        lineno++;
        if (sscanf(line, "SET %63s %199s", key, val) != 2)
            continue;
        if (store_put(&st, key, val) != 0) {
            fprintf(stderr, "load failed at line %d\n", lineno);
            ok = 0;
            break;
        }
    }
    fclose(f);
    if (ok)
        for (int i = 0; i < st.n; i++)
            printf("%s = %s\n", st.e[i].key, st.e[i].value);
    store_free(&st);
    return ok ? 0 : 1;
}
