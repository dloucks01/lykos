/* sesslog - open a session and remember its label. On the OPEN command the label buffer is
 * allocated but never freed before the program returns: a memory leak (CWE-401). */
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
    char *label = malloc(64);       /* CWE-401: never freed on this path */
    strncpy(label, line + 5, 63);
    label[63] = 0;
    printf("opened %s\n", label);
    return 0;
}
