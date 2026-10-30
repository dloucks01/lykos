/* integ - run the integrity checks listed in a job file
 * job lines:  name=<label>   path=<file to hash>   (one check per path=) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CHECKS 8

static void chomp(char *s)
{
    s[strcspn(s, "\r\n")] = '\0';
}

static int run_check(const char *label, const char *path)
{
    char cmd[512];
    printf("== %s\n", label);
    fflush(stdout);
    snprintf(cmd, sizeof cmd, "sha256sum -- %s", path);
    int rc = system(cmd);
    if (rc != 0)
        fprintf(stderr, "check '%s' failed (rc=%d)\n", label, rc);
    return rc;
}

int main(int argc, char **argv)
{
    char line[512], label[64] = "unnamed";
    int checks = 0, failed = 0;
    if (argc < 2) {
        fprintf(stderr, "usage: %s <jobfile>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "r");
    if (!f) {
        perror("open");
        return 1;
    }
    while (fgets(line, sizeof line, f) && checks < MAX_CHECKS) {
        chomp(line);
        if (strncmp(line, "name=", 5) == 0) {
            snprintf(label, sizeof label, "%s", line + 5);
        } else if (strncmp(line, "path=", 5) == 0) {
            if (line[5] == '\0' || line[5] == '-')
                continue;
            if (run_check(label, line + 5) != 0)
                failed++;
            checks++;
        }
    }
    fclose(f);
    printf("%d checks, %d failed\n", checks, failed);
    return 0;
}
