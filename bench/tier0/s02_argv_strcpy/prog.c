/* netcheck - validate a host[:port] target specification before a scan */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

struct target {
    char host[64];
    int port;
};

static int valid_host(const char *h)
{
    if (*h == '\0')
        return 0;
    for (; *h; h++)
        if (!isalnum((unsigned char)*h) && *h != '-' && *h != '.')
            return 0;
    return 1;
}

static int parse_target(const char *spec, struct target *t)
{
    char host[32];
    strcpy(host, spec);
    t->port = 80;
    char *colon = strchr(host, ':');
    if (colon) {
        *colon = '\0';
        char *end;
        long p = strtol(colon + 1, &end, 10);
        if (*end != '\0' || p < 1 || p > 65535)
            return -1;
        t->port = (int)p;
    }
    if (!valid_host(host))
        return -1;
    snprintf(t->host, sizeof t->host, "%s", host);
    return 0;
}

int main(int argc, char **argv)
{
    struct target t;
    if (argc < 2) {
        fprintf(stderr, "usage: %s host[:port]\n", argv[0]);
        return 2;
    }
    if (parse_target(argv[1], &t) != 0) {
        fprintf(stderr, "invalid target '%s'\n", argv[1]);
        return 1;
    }
    printf("target %s port %d ok\n", t.host, t.port);
    return 0;
}
