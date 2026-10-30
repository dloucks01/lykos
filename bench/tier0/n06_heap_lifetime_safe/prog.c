/* sessrun2 - replay a script: USER <name> | AUTH <pin> | NOTE <text> | SHOW */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct session {
    char *user;
    char *note;
    int authed;
};

static char *dup_str(const char *s)
{
    size_t n = strlen(s);
    char *d = malloc(n + 1);
    if (d)
        memcpy(d, s, n + 1);
    return d;
}

static void set_note(struct session *s, const char *text)
{
    char *fresh = dup_str(text);
    if (!fresh)
        return;
    free(s->note);
    s->note = fresh;
}

static void drop_user(struct session *s)
{
    free(s->user);
    s->user = NULL;
    s->authed = 0;
}

int main(int argc, char **argv)
{
    struct session s = { NULL, NULL, 0 };
    char line[256];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <script>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "r");
    if (!f) {
        perror("open");
        return 1;
    }
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "USER ", 5) == 0) {
            drop_user(&s);
            s.user = dup_str(line + 5);
        } else if (strncmp(line, "AUTH ", 5) == 0) {
            if (s.user && strcmp(line + 5, "4711") == 0)
                s.authed = 1;
            else
                drop_user(&s);
        } else if (strncmp(line, "NOTE ", 5) == 0) {
            set_note(&s, line + 5);
        } else if (strcmp(line, "SHOW") == 0) {
            printf("user=%s authed=%d note=%s\n", s.user ? s.user : "-", s.authed,
                   s.note ? s.note : "-");
        }
    }
    fclose(f);
    drop_user(&s);
    free(s.note);
    return 0;
}
