/* svcport - look up the port(s) of a named service in /etc/services */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int lookup(const char *name)
{
    char cmd[256], line[512];
    int found = 0;
    snprintf(cmd, sizeof cmd, "grep -i -w '%s' /etc/services", name);
    FILE *p = popen(cmd, "r");
    if (!p) {
        perror("popen");
        return -1;
    }
    while (fgets(line, sizeof line, p)) {
        char svc[64], port[64];
        if (line[0] == '#')
            continue;
        if (sscanf(line, "%63s %63s", svc, port) == 2) {
            printf("%-16s %s\n", svc, port);
            found++;
        }
    }
    pclose(p);
    return found;
}

int main(int argc, char **argv)
{
    if (argc < 2 || argv[1][0] == '\0') {
        fprintf(stderr, "usage: %s <service>\n", argv[0]);
        return 2;
    }
    if (strlen(argv[1]) > 64) {
        fprintf(stderr, "name too long\n");
        return 1;
    }
    int n = lookup(argv[1]);
    if (n <= 0)
        printf("%s: not found\n", argv[1]);
    return 0;
}
