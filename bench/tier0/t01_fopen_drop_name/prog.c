/* filebox - print a file from the drop directory, named on the command line.
 * The requested name is appended to a fixed base directory and opened with no check for
 * `..` components, so a name like ../../../../etc/passwd escapes the drop directory. */
#include <stdio.h>
#include <string.h>

#define BASE "/var/lib/filebox/drop/"

static int serve(const char *name)
{
    char path[256];
    strcpy(path, BASE);
    strncat(path, name, sizeof(path) - strlen(path) - 1);   /* name is not sanitised */
    FILE *f = fopen(path, "rb");                             /* CWE-22 site */
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
