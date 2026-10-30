/* sesslog (fixed) - the label buffer is freed before returning, so nothing leaks.
 * Negative control for the memory-leak class. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void)
{
    char line[128];
    if (!fgets(line, sizeof line, stdin))
        return 2;
    line[strcspn(line, "\r\n")] = 0;
    if (strncmp(line, "OPEN ", 5) != 0)
        return 1;
    char *label = malloc(64);
    strncpy(label, line + 5, 63);
    label[63] = 0;
    printf("opened %s\n", label);
    free(label);                    /* freed: no leak */
    return 0;
}
