/* banner - print a framed sign-in banner with the given title */
#include <stdio.h>
#include <string.h>

#define WIDTH 60

static void rule(void)
{
    char line[WIDTH + 1];
    memset(line, '=', WIDTH);
    line[WIDTH] = '\0';
    puts(line);
}

static void print_banner(const char *title)
{
    char out[128];
    snprintf(out, sizeof out, title);
    rule();
    printf("  ");
    puts(out);
    rule();
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <title>\n", argv[0]);
        return 2;
    }
    if (strlen(argv[1]) > 100) {
        fprintf(stderr, "title too long\n");
        return 1;
    }
    print_banner(argv[1]);
    return 0;
}
