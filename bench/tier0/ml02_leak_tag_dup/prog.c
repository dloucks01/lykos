/* tagcopy - read a tag line from a file and keep a duplicate of it. The duplicate made by
 * strdup() is printed but never freed: a memory leak (CWE-401). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    char buf[128];
    if (argc < 2)
        return 2;
    FILE *f = fopen(argv[1], "r");
    if (!f)
        return 1;
    if (!fgets(buf, sizeof buf, f)) {
        fclose(f);
        return 1;
    }
    fclose(f);
    buf[strcspn(buf, "\r\n")] = 0;
    if (strncmp(buf, "TAG:", 4) != 0)
        return 1;
    char *dup = strdup(buf + 4);    /* CWE-401: never freed */
    printf("tag=%s\n", dup);
    return 0;
}
