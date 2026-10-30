/* spincalc - read a 4-byte iteration count from stdin and run a nested compute loop that many
 * times. The count is unbounded, so a large value makes the program run essentially forever:
 * uncontrolled resource consumption (CWE-400/835). */
#include <stdio.h>
#include <stdint.h>

int main(void)
{
    unsigned char b[4];
    if (fread(b, 1, 4, stdin) != 4)
        return 1;
    uint32_t n = (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
    volatile double x = 1.0;
    for (uint32_t i = 0; i < n; i++)          /* CWE-400 site: input-controlled, unbounded */
        for (int j = 0; j < 50; j++)
            x = x * 1.0000001 + 1.0;
    printf("%f\n", x);
    return 0;
}
