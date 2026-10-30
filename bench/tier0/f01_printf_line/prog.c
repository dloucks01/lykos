/* notify - relay notification lines from stdin to the console,
 * prefixed with a sequence number; blank lines and #comments skipped */
#include <stdio.h>
#include <string.h>

#define MAX_LINE 512

static int relay(FILE *in)
{
    char line[MAX_LINE];
    unsigned seq = 0;
    while (fgets(line, sizeof line, in)) {
        if (line[0] == '\n' || line[0] == '#')
            continue;
        int has_nl = strchr(line, '\n') != NULL;
        printf("[%04u] ", ++seq);
        printf(line);
        if (!has_nl)
            putchar('\n');
    }
    return (int)seq;
}

int main(void)
{
    int n = relay(stdin);
    fflush(stdout);
    fprintf(stderr, "%d notifications relayed\n", n);
    return 0;
}
