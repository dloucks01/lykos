/* jobrun - run a maintenance job description
 * job lines: title=<text>  list=yes|no  owner=<name>                  */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct job {
    char title[64];
    char owner[32];
    int list;
};

static void parse_job(FILE *f, struct job *j)
{
    char line[256];
    memset(j, 0, sizeof *j);
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "title=", 6) == 0)
            snprintf(j->title, sizeof j->title, "%s", line + 6);
        else if (strncmp(line, "owner=", 6) == 0)
            snprintf(j->owner, sizeof j->owner, "%s", line + 6);
        else if (strncmp(line, "list=", 5) == 0)
            j->list = strcmp(line + 5, "yes") == 0;
    }
}

int main(int argc, char **argv)
{
    struct job j;
    if (argc < 2) {
        fprintf(stderr, "usage: %s <job>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "r");
    if (!f) {
        perror("open");
        return 1;
    }
    parse_job(f, &j);
    fclose(f);
    printf("job '%s' (owner %s)\n", j.title, j.owner[0] ? j.owner : "root");
    fflush(stdout);
    if (j.list) {
        int rc = system("ls -l");
        if (rc != 0)
            fprintf(stderr, "listing failed: %d\n", rc);
    }
    return 0;
}
