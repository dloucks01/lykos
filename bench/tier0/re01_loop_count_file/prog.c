/* sumcount - read a repeat count from a RUN file header, then accumulate that many iterations
 * of work. The count is taken straight from the input with no upper bound, so a large value
 * makes the program run essentially forever: uncontrolled resource consumption (CWE-400/835). */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main(int argc, char **argv)
{
    unsigned char hdr[8];
    if (argc < 2)
        return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f)
        return 1;
    size_t got = fread(hdr, 1, sizeof hdr, f);
    fclose(f);
    if (got < 8 || memcmp(hdr, "RUN", 3) != 0)
        return 1;
    uint64_t count = 0;
    for (int i = 7; i >= 3; i--)             /* bytes 3..7, little end last: up to 2^40 */
        count = (count << 8) | hdr[i];
    volatile uint64_t acc = 0;
    for (uint64_t i = 0; i < count; i++)     /* CWE-400 site: input-controlled, unbounded */
        acc += i * 2654435761u;
    printf("acc=%llu\n", (unsigned long long)acc);
    return 0;
}
