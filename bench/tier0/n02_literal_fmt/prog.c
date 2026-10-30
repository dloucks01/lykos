/* notify2 - relay "LEVEL text" notification lines from stdin */
#include <stdio.h>
#include <string.h>

#define MAX_LINE 512

static void log_line(const char *level, const char *msg)
{
    fprintf(stderr, "[%s] %s\n", level, msg);
}

static void relay(FILE *in)
{
    char line[MAX_LINE], out[96];
    unsigned seq = 0;
    while (fgets(line, sizeof line, in)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#')
            continue;
        char *sp = strchr(line, ' ');
        const char *text = sp ? sp + 1 : "";
        if (sp)
            *sp = '\0';
        if (strcmp(line, "WARN") == 0 || strcmp(line, "ERR") == 0)
            log_line(line, text);
        snprintf(out, sizeof out, "%s: %s", line, text);
        printf("[%04u] ", ++seq);
        printf("%s", out);
        putchar('\n');
    }
    fprintf(stderr, "%u notifications relayed\n", seq);
}

int main(void)
{
    relay(stdin);
    return 0;
}
