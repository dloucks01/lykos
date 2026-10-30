/* tagread - read "key: value" media tags and print a normalized summary */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

struct tags {
    char *title;
    char *artist;
    char *comment;
    int year;
};

static char *trim(char *s)
{
    while (isspace((unsigned char)*s))
        s++;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1]))
        s[--n] = '\0';
    return s;
}

static char *copy_comment(const char *val)
{
    char *c = malloc(strlen(val));
    if (!c)
        return NULL;
    strcpy(c, val);
    return c;
}

static void set_tag(struct tags *t, const char *key, const char *val)
{
    if (strcmp(key, "title") == 0 && !t->title)
        t->title = strdup(val);
    else if (strcmp(key, "artist") == 0 && !t->artist)
        t->artist = strdup(val);
    else if (strcmp(key, "comment") == 0 && !t->comment)
        t->comment = copy_comment(val);
    else if (strcmp(key, "year") == 0)
        t->year = atoi(val);
}

int main(int argc, char **argv)
{
    struct tags t = {0};
    char line[512];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <tagfile>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "r");
    if (!f) {
        perror("open");
        return 1;
    }
    while (fgets(line, sizeof line, f)) {
        char *colon = strchr(line, ':');
        if (!colon)
            continue;
        *colon = '\0';
        set_tag(&t, trim(line), trim(colon + 1));
    }
    fclose(f);
    printf("%s - %s (%d)\n", t.artist ? t.artist : "?", t.title ? t.title : "?", t.year);
    if (t.comment)
        printf("  # %s\n", t.comment);
    free(t.title);
    free(t.artist);
    free(t.comment);
    return 0;
}
