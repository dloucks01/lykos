/* statusline (fixed) - the severity `level` is initialised to 0 and only overwritten from the
 * input, so it is always defined before use. Negative control for the uninitialised-read class. */
#include <stdio.h>
#include <string.h>

int main(void)
{
    char line[128];
    if (!fgets(line, sizeof line, stdin))
        return 2;
    line[strcspn(line, "\r\n")] = 0;
    if (strncmp(line, "STATUS", 6) != 0)
        return 1;
    int level = 0;                  /* initialised */
    if (strlen(line) > 6)
        level = line[6];
    if (level > 3)
        puts("high");
    else
        puts("low");
    return 0;
}
