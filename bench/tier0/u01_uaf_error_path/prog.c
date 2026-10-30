/* sessrun - replay a session script: USER <name>, AUTH <pin>, SHOW, QUIT */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum state { ST_INIT, ST_USER, ST_AUTHED };

struct user {
    char name[32];
    int level;
};

struct session {
    enum state state;
    struct user *user;
};

static void cmd_user(struct session *s, const char *arg)
{
    s->user = calloc(1, sizeof *s->user);
    snprintf(s->user->name, sizeof s->user->name, "%s", arg);
    s->user->level = 1;
    s->state = ST_USER;
}

static void cmd_auth(struct session *s, const char *arg)
{
    if (s->state != ST_USER)
        return;
    if (strcmp(arg, "4711") != 0) {
        fprintf(stderr, "auth failed\n");
        free(s->user);
        s->state = ST_INIT;
        return;
    }
    s->user->level = 9;
    s->state = ST_AUTHED;
}

static void cmd_show(const struct session *s)
{
    if (!s->user) {
        puts("no user");
        return;
    }
    printf("level %d\n", s->user->level);
    printf("name  %s\n", s->user->name);
}

int main(int argc, char **argv)
{
    struct session s = { ST_INIT, NULL };
    char line[128];
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
        if (strncmp(line, "USER ", 5) == 0 && s.state == ST_INIT)
            cmd_user(&s, line + 5);
        else if (strncmp(line, "AUTH ", 5) == 0)
            cmd_auth(&s, line + 5);
        else if (strcmp(line, "SHOW") == 0)
            cmd_show(&s);
        else if (strcmp(line, "QUIT") == 0)
            break;
    }
    fclose(f);
    free(s.user);
    return 0;
}
