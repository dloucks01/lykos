/* svcprobe - run the configured health-check helper for a service
 * config lines: "service=<name>" and "helper=<path to checker>" */
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char line[256], service[64] = "default", helper[128] = "/bin/true";
    if (argc < 2) {
        fprintf(stderr, "usage: %s <config>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "r");
    if (!f) {
        perror("open");
        return 1;
    }
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "service=", 8) == 0)
            snprintf(service, sizeof service, "%s", line + 8);
        else if (strncmp(line, "helper=", 7) == 0)
            snprintf(helper, sizeof helper, "%s", line + 7);
    }
    fclose(f);
    printf("probing %s with %s\n", service, helper);
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        execl(helper, helper, service, (char *)NULL);
        _exit(127);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    printf("%s: %s\n", service, (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? "healthy" : "failed");
    return 0;
}
