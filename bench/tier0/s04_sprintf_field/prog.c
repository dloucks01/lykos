/* profgreet - render the login greeting from a user profile file
 * profile lines:  key=value   (user, shell, lang)                     */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct profile {
    char user[256];
    char shell[256];
    char lang[16];
};

static void chomp(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

static int load_profile(FILE *f, struct profile *p)
{
    char line[512];
    memset(p, 0, sizeof *p);
    strcpy(p->shell, "/bin/sh");
    strcpy(p->lang, "en");
    while (fgets(line, sizeof line, f)) {
        chomp(line);
        char *eq = strchr(line, '=');
        if (!eq || line[0] == '#')
            continue;
        *eq = '\0';
        const char *val = eq + 1;
        if (strcmp(line, "user") == 0)
            snprintf(p->user, sizeof p->user, "%s", val);
        else if (strcmp(line, "shell") == 0)
            snprintf(p->shell, sizeof p->shell, "%s", val);
        else if (strcmp(line, "lang") == 0)
            snprintf(p->lang, sizeof p->lang, "%s", val);
    }
    return p->user[0] ? 0 : -1;
}

static void print_greeting(const struct profile *p)
{
    char motd[64];
    sprintf(motd, "Welcome back, %s!", p->user);
    printf("%s (shell %s, lang %s)\n", motd, p->shell, p->lang);
}

int main(int argc, char **argv)
{
    struct profile prof;
    if (argc < 2) {
        fprintf(stderr, "usage: %s <profile>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "r");
    if (!f) {
        perror("open");
        return 1;
    }
    int rc = load_profile(f, &prof);
    fclose(f);
    if (rc != 0) {
        fprintf(stderr, "profile has no user\n");
        return 1;
    }
    print_greeting(&prof);
    return 0;
}
