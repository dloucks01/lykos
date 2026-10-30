/* sumcount (fixed) - the repeat count is clamped to a safe maximum, so the loop always
 * terminates quickly regardless of input. Negative control for the resource class. */
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
    for (int i = 7; i >= 3; i--)
        count = (count << 8) | hdr[i];
    if (count > 100000)                      /* clamp: bounded work */
        count = 100000;
    volatile uint64_t acc = 0;
    for (uint64_t i = 0; i < count; i++)
        acc += i * 2654435761u;
    printf("acc=%llu\n", (unsigned long long)acc);
    return 0;
}
