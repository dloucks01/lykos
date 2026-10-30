/* filebox (fixed) - print a file from the drop directory, named on the command line.
 * This version rejects any name containing "..", so the drop directory cannot be escaped.
 * Negative control for the path-traversal class. */
#include <stdio.h>
#include <string.h>

#define BASE "/var/lib/filebox/drop/"

static int serve(const char *name)
{
    char path[256];
    if (strstr(name, "..")) {                   /* reject traversal before building the path */
        fprintf(stderr, "invalid name\n");
        return 1;
    }
    strcpy(path, BASE);
    strncat(path, name, sizeof(path) - strlen(path) - 1);
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        return 1;
    }
    char buf[512];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        fwrite(buf, 1, n, stdout);
    fclose(f);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <name>\n", argv[0]);
        return 2;
    }
    return serve(argv[1]);
}
