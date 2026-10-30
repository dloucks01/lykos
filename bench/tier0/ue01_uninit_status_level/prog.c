/* statusline - read a one-line command and print a status word. On the STATUS command the
 * severity `level` is tested but, due to a missing assignment, is never set: a use of an
 * uninitialised stack value (CWE-457/908). Only a line beginning "STATUS" reaches the bug. */
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
    int level;                      /* never assigned */
    if (level > 3)                  /* CWE-457 use site */
        puts("high");
    else
        puts("low");
    return 0;
}
