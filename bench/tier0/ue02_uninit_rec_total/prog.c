/* recordcat - open a record file; after validating the REC1 header it tests a `total` counter
 * that was never assigned, a use of an uninitialised stack value (CWE-457/908). Only a valid
 * REC1 header reaches the bug. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    unsigned char buf[64];
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f)
        return 1;
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n < 4 || memcmp(buf, "REC1", 4) != 0)
        return 1;
    int total;                      /* never assigned */
    if (total)                      /* CWE-457 use site */
        puts("nonempty");
    else
        puts("empty");
    return 0;
}
